//! Upstream pool: prober, health, ranking, quorum tip, degraded mode and
//! ejection (`docs/stage0-mvp-plan.md` §3).
//!
//! Every 15 s each upstream is probed with `get_info`. The probe records RTT
//! (EMA), block count, top hash and `synchronized`. The quorum tip is the
//! highest height at least `min_agree` upstreams agree on; without one the
//! pool is **degraded**: the highest-height owned node serves and cache
//! writes are suspended by the caller.
//!
//! An upstream that fails verification three times in an hour is ejected for
//! 24 h and the event is kept in a public fault log.
//!
//! No client identity ever reaches this module: it only knows method bodies.

use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use futures_util::stream::{BoxStream, StreamExt, TryStreamExt};
use mnr_core::hash::Hash;
use mnr_core::verify::{quorum_tip, QuorumTip, TipReport};
use mnr_core::wire::{GetInfoResult, JsonRpcRequest, JsonRpcResponse};
use parking_lot::{Mutex, RwLock};
use serde::Serialize;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::config::{Config, Kind, Transport, UpstreamConfig};
use crate::stream::{throttled, ByteBucket, Throttled};

/// EMA smoothing for RTT (gateway plan §3.5: alpha 0.3).
const RTT_ALPHA: f64 = 0.3;
/// Bonus for the owned node in ranking, in ms.
const OWNED_BONUS_MS: f64 = 20.0;
/// Faults within this window trigger ejection.
const FAULT_WINDOW: Duration = Duration::from_secs(3600);
/// Faults in the window that trigger ejection.
const FAULT_LIMIT: usize = 3;
/// Ejection length.
const EJECT_FOR: Duration = Duration::from_secs(24 * 3600);
/// Newest fault events kept for the public log.
const FAULT_LOG_MAX: usize = 1000;
/// Rule 5: how often each upstream host's `/.well-known/mnr-optout` is read.
pub const OPT_OUT_CHECK_EVERY: Duration = Duration::from_secs(24 * 3600);
/// Timeout for one opt-out check (a web host, possibly over Tor).
const OPT_OUT_TIMEOUT: Duration = Duration::from_secs(8);
/// Rule 3: how long a read queues for a light token on the best-ranked
/// public upstream before falling through to the next.
pub const PUBLIC_QUEUE_WAIT: Duration = Duration::from_millis(250);
/// The owned node is ours to load: reads queue longer on it.
pub const OWNED_QUEUE_WAIT: Duration = Duration::from_secs(1);
/// Poll interval while queuing.
const LIGHT_POLL: Duration = Duration::from_millis(10);
/// Largest *buffered* upstream response (light calls). Streams are not
/// buffered; they are paced by the bandwidth cap and bounded by
/// `stream::MAX_STREAM_BYTES`.
const MAX_RESPONSE_BYTES: u64 = 64 * 1024 * 1024;

/// What kind of work a caller wants an upstream for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Work {
    /// Light JSON call: any healthy on-tip upstream, onion included.
    Light,
    /// `get_blocks.bin` stream: owned first, clearnet public second, never onion.
    Stream,
}

#[derive(Debug, Clone, Default)]
pub struct Health {
    pub ok: bool,
    /// Block count reported by `get_info` (tip height + 1).
    pub block_count: u64,
    pub top_hash: Option<Hash>,
    pub synchronized: bool,
    pub rtt_ema_ms: Option<f64>,
    pub last_probe: Option<SystemTime>,
    pub last_error: Option<String>,
    /// Rule 5: the host published `/.well-known/mnr-optout`. Out of
    /// rotation for the life of this process; the operator moves it to the
    /// config's `opt_out` list.
    pub opted_out: bool,
    /// What the node's `get_info.restricted` said last (plan §3: the
    /// restricted-RPC check). Information for the upstreams page; the
    /// allow-list already guarantees we call nothing else (rule 7).
    pub restricted: Option<bool>,
    faults: Vec<Instant>,
    ejected_until: Option<Instant>,
    /// Ejected at the last probe round, so the lapse is logged once.
    was_ejected: bool,
}

impl Health {
    /// A synchronized, on-tip, healthy record for tests in other modules.
    #[cfg(test)]
    pub fn healthy_for_test(block_count: u64, top_hash: Hash) -> Self {
        Self {
            ok: true,
            block_count,
            top_hash: Some(top_hash),
            synchronized: true,
            rtt_ema_ms: Some(10.0),
            ..Self::default()
        }
    }

    fn ejected(&self, now: Instant) -> bool {
        self.ejected_until.is_some_and(|t| t > now)
    }
}

/// An upstream that asked to be removed, for the public log.
#[derive(Debug, Clone, Serialize)]
pub struct OptOutEvent {
    pub at_unix: u64,
    pub upstream: String,
    pub host: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FaultEvent {
    pub at_unix: u64,
    pub upstream: String,
    pub method: String,
    pub detail: String,
    pub ejected: bool,
    /// When the ejection this fault caused lapses (unix seconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ejected_until: Option<u64>,
}

pub struct Upstream {
    pub id: usize,
    pub cfg: UpstreamConfig,
    client: reqwest::Client,
    timeout: Duration,
    /// Requests we sent, for the public request-rate figure (rule 1).
    pub requests: AtomicU64,
    /// Answers from this upstream that passed verification (plan §4: the
    /// public numbers on the upstreams page).
    pub verified: AtomicU64,
    /// Answers that failed verification, ever (the fault log is bounded).
    pub faults: AtomicU64,
    /// Rule 3: light calls per second we allow ourselves against this node.
    light: Mutex<LightBucket>,
    /// Rule 3: concurrent `get_blocks.bin` streams against this node.
    streams: Arc<Semaphore>,
    /// Rule 3: bytes per second we allow ourselves to pull from this node,
    /// shared by all its streams.
    bandwidth: Arc<Mutex<ByteBucket>>,
}

/// Token bucket for the per-upstream light-call cap. Capacity equals one
/// second of the rate, so a burst can never exceed the published ceiling.
struct LightBucket {
    tokens: f64,
    rate: f64,
    last: Instant,
}

impl LightBucket {
    fn new(rps: u32) -> Self {
        Self {
            tokens: f64::from(rps),
            rate: f64::from(rps),
            last: Instant::now(),
        }
    }

    fn try_take(&mut self, now: Instant) -> bool {
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.rate);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// A forwarded upstream response, headers already reduced to what the
/// client may see.
#[derive(Debug, Clone)]
pub struct Forwarded {
    pub status: u16,
    pub content_type: Option<String>,
    pub body: Bytes,
}

/// A streamed upstream response: headers now, body as it arrives, paced by
/// the upstream's bandwidth cap and holding its stream slot.
pub struct Streamed {
    pub status: u16,
    pub content_type: Option<String>,
    /// The upstream's `Content-Length`, when it sent one.
    pub content_length: Option<u64>,
    pub body: Throttled,
}

/// Why a forward did not produce a response. `Cap` and the transport errors
/// are retryable on another upstream; the caller decides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardError {
    /// Our own per-upstream cap (rule 3) is exhausted right now.
    Cap,
    Timeout,
    Connect,
    Other(String),
}

impl fmt::Display for ForwardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cap => f.write_str("upstream cap reached"),
            Self::Timeout => f.write_str("timeout"),
            Self::Connect => f.write_str("connect failed"),
            Self::Other(s) => f.write_str(s),
        }
    }
}

pub struct Pool {
    pub upstreams: Vec<Upstream>,
    health: RwLock<Vec<Health>>,
    quorum: RwLock<Option<QuorumTip>>,
    faults: RwLock<VecDeque<FaultEvent>>,
    opt_outs: RwLock<Vec<OptOutEvent>>,
    min_agree: usize,
    interval: Duration,
}

/// Public view of one upstream, for `mnr.network/upstreams`.
#[derive(Debug, Clone, Serialize)]
pub struct UpstreamStatus {
    pub name: String,
    pub kind: &'static str,
    pub transport: &'static str,
    pub ok: bool,
    pub on_tip: bool,
    pub ejected: bool,
    /// Unix seconds at which the current ejection lapses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ejected_until: Option<u64>,
    /// `get_info.restricted` at the last probe; `null` before the first.
    pub restricted: Option<bool>,
    pub height: Option<u64>,
    pub rtt_ms: Option<u64>,
    pub synchronized: bool,
    pub opted_out: bool,
    pub requests: u64,
    pub verified: u64,
    pub faults: u64,
    pub caps: crate::config::Caps,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PoolStatus {
    pub degraded: bool,
    pub quorum_height: Option<u64>,
    pub quorum_hash: Option<String>,
    pub quorum_agreeing: usize,
    pub upstreams: Vec<UpstreamStatus>,
    pub faults: Vec<FaultEvent>,
    /// Hosts that published the opt-out signal since this process started.
    pub opt_outs: Vec<OptOutEvent>,
}

impl Pool {
    pub fn from_config(cfg: &Config) -> Result<Self, reqwest::Error> {
        let clearnet = client(cfg.user_agent(), None)?;
        let onion = match cfg.tor_socks {
            Some(addr) => Some(client(cfg.user_agent(), Some(addr))?),
            None => None,
        };
        let upstreams = cfg
            .upstreams
            .iter()
            .cloned()
            .enumerate()
            .map(|(id, u)| {
                let (client, timeout) = match u.transport {
                    Transport::Onion => (
                        onion.clone().expect("validated: onion needs tor_socks"),
                        Duration::from_millis(cfg.probe.onion_timeout_ms),
                    ),
                    _ => (
                        clearnet.clone(),
                        Duration::from_millis(cfg.probe.clearnet_timeout_ms),
                    ),
                };
                Upstream {
                    id,
                    light: Mutex::new(LightBucket::new(u.caps.rps_light)),
                    streams: Arc::new(Semaphore::new(u.caps.max_streams as usize)),
                    bandwidth: Arc::new(Mutex::new(ByteBucket::new(
                        u64::from(u.caps.mbps) * 1_000_000,
                    ))),
                    cfg: u,
                    client,
                    timeout,
                    requests: AtomicU64::new(0),
                    verified: AtomicU64::new(0),
                    faults: AtomicU64::new(0),
                }
            })
            .collect::<Vec<_>>();
        let n = upstreams.len();
        Ok(Self {
            upstreams,
            health: RwLock::new(vec![Health::default(); n]),
            quorum: RwLock::new(None),
            faults: RwLock::new(VecDeque::new()),
            opt_outs: RwLock::new(Vec::new()),
            min_agree: cfg.probe.min_agree,
            interval: Duration::from_secs(cfg.probe.interval_secs),
        })
    }

    /// Run probe rounds forever. The caller runs the first round itself
    /// before serving, so this sleeps first.
    pub async fn run_prober(self: Arc<Self>) {
        loop {
            tokio::time::sleep(self.interval).await;
            self.probe_all().await;
        }
    }

    /// One probe round across all upstreams in parallel, then recompute the
    /// quorum tip.
    pub async fn probe_all(&self) {
        let results =
            futures_util::future::join_all(self.upstreams.iter().map(|u| u.probe())).await;
        let now = Instant::now();
        let mut reports = Vec::new();
        {
            let mut health = self.health.write();
            for (u, r) in self.upstreams.iter().zip(results) {
                let h = &mut health[u.id];
                h.last_probe = Some(SystemTime::now());
                match r {
                    Ok(p) => {
                        h.ok = true;
                        h.block_count = p.block_count;
                        h.top_hash = Some(p.top_hash);
                        h.synchronized = p.synchronized;
                        h.restricted = Some(p.restricted);
                        h.rtt_ema_ms = Some(match h.rtt_ema_ms {
                            Some(prev) => prev + RTT_ALPHA * (p.rtt_ms - prev),
                            None => p.rtt_ms,
                        });
                        h.last_error = None;
                        if p.synchronized && !h.ejected(now) && p.block_count > 0 {
                            reports.push(TipReport {
                                upstream: u.id,
                                height: p.block_count - 1,
                                hash: p.top_hash,
                            });
                        }
                    }
                    Err(e) => {
                        h.ok = false;
                        h.last_error = Some(e);
                    }
                }
            }
        }
        self.note_ejection_lapses(now);
        let q = quorum_tip(&reports, self.min_agree);
        match &q {
            Some(q) => {
                tracing::debug!(height = q.height, agreeing = q.agreeing.len(), "quorum tip")
            }
            None => tracing::warn!(reports = reports.len(), "no quorum: degraded mode"),
        }
        *self.quorum.write() = q;
    }

    pub fn upstream(&self, id: usize) -> &Upstream {
        &self.upstreams[id]
    }

    /// Log, once, every ejection that has lapsed since the last round.
    fn note_ejection_lapses(&self, now: Instant) {
        let mut health = self.health.write();
        for (u, h) in self.upstreams.iter().zip(health.iter_mut()) {
            let ejected = h.ejected(now);
            if h.was_ejected && !ejected {
                tracing::info!(upstream = %u.cfg.name, "ejection lapsed: back in rotation");
            }
            h.was_ejected = ejected;
        }
    }

    /// Install synthetic health and quorum so dispatch tests can run
    /// against mock upstreams without probing.
    #[cfg(test)]
    pub fn set_for_test(&self, health: Vec<Health>, tip: Option<(u64, Hash)>) {
        *self.health.write() = health;
        *self.quorum.write() = tip.map(|(height, hash)| QuorumTip {
            height,
            hash,
            agreeing: (0..self.upstreams.len()).collect(),
        });
    }

    pub fn quorum(&self) -> Option<QuorumTip> {
        self.quorum.read().clone()
    }

    /// Upstreams that must agree on a tip hash (plan §3: 3).
    pub fn min_agree(&self) -> usize {
        self.min_agree
    }

    /// Seconds between probe rounds.
    pub fn interval(&self) -> Duration {
        self.interval
    }

    pub fn degraded(&self) -> bool {
        self.quorum.read().is_none()
    }

    /// Exactly on the quorum tip: same height *and* same hash. A node one
    /// block ahead is skipped until the quorum catches up (at most one probe
    /// round); a node at the same height with another hash is on a fork.
    fn on_tip(h: &Health, q: Option<&QuorumTip>) -> bool {
        match q {
            Some(q) => h.block_count == q.height + 1 && h.top_hash == Some(q.hash),
            None => false,
        }
    }

    /// Upstream ids to try, best first, for the given work.
    ///
    /// Healthy, not ejected, synchronized, on the quorum tip, sorted by RTT
    /// with a small bonus for owned nodes. Streams never go to onion
    /// upstreams and prefer owned nodes outright. In degraded mode only
    /// owned nodes are returned, highest block count first.
    pub fn ranked(&self, work: Work) -> Vec<usize> {
        let now = Instant::now();
        let health = self.health.read();
        let q = self.quorum.read();
        let mut candidates: Vec<(usize, f64)> = self
            .upstreams
            .iter()
            .filter(|u| work != Work::Stream || u.cfg.transport != Transport::Onion)
            .filter_map(|u| {
                let h = &health[u.id];
                if !h.ok || !h.synchronized || h.ejected(now) || h.opted_out {
                    return None;
                }
                let owned = u.cfg.kind == Kind::Owned;
                if q.is_none() {
                    // Degraded: owned nodes only, best height first.
                    return owned.then_some((u.id, -(h.block_count as f64)));
                }
                if !Self::on_tip(h, q.as_ref()) {
                    return None;
                }
                let mut score = h.rtt_ema_ms.unwrap_or(f64::MAX / 2.0);
                if owned {
                    score -= OWNED_BONUS_MS;
                    if work == Work::Stream {
                        score -= 1e6; // owned first for streams, always
                    }
                }
                Some((u.id, score))
            })
            .collect();
        candidates.sort_by(|a, b| a.1.total_cmp(&b.1));
        candidates.into_iter().map(|(id, _)| id).collect()
    }

    /// Record a verification failure against an upstream. Three in an hour
    /// eject it for 24 h; every fault is logged publicly.
    pub fn record_fault(&self, id: usize, method: &str, detail: String) {
        self.record_fault_at(id, method, detail, Instant::now());
    }

    /// Count an answer from `id` that passed verification.
    pub fn record_verified(&self, id: usize) {
        self.upstreams[id].verified.fetch_add(1, Ordering::Relaxed);
    }

    fn record_fault_at(&self, id: usize, method: &str, detail: String, now: Instant) {
        self.upstreams[id].faults.fetch_add(1, Ordering::Relaxed);
        let ejected = {
            let mut health = self.health.write();
            let h = &mut health[id];
            h.faults.retain(|t| now.duration_since(*t) < FAULT_WINDOW);
            h.faults.push(now);
            if h.faults.len() >= FAULT_LIMIT && !h.ejected(now) {
                h.ejected_until = Some(now + EJECT_FOR);
                h.was_ejected = true;
                true
            } else {
                false
            }
        };
        let ejected_until = ejected.then(|| unix_at(now + EJECT_FOR, now));
        let name = &self.upstreams[id].cfg.name;
        tracing::warn!(upstream = %name, method, %detail, ejected, "verification fault");
        let mut log = self.faults.write();
        if log.len() >= FAULT_LOG_MAX {
            log.pop_front();
        }
        log.push_back(FaultEvent {
            at_unix: unix_now(),
            upstream: name.clone(),
            method: method.to_owned(),
            detail,
            ejected,
            ejected_until,
        });
    }

    pub fn status(&self) -> PoolStatus {
        let now = Instant::now();
        let health = self.health.read();
        let q = self.quorum.read();
        let upstreams = self
            .upstreams
            .iter()
            .map(|u| {
                let h = &health[u.id];
                UpstreamStatus {
                    name: u.cfg.name.clone(),
                    kind: match u.cfg.kind {
                        Kind::Owned => "owned",
                        Kind::Public => "public",
                    },
                    transport: match u.cfg.transport {
                        Transport::Https => "https",
                        Transport::Http => "http",
                        Transport::Onion => "onion",
                    },
                    ok: h.ok,
                    on_tip: Self::on_tip(h, q.as_ref()),
                    ejected: h.ejected(now),
                    ejected_until: h
                        .ejected_until
                        .filter(|t| *t > now)
                        .map(|t| unix_at(t, now)),
                    restricted: h.restricted,
                    height: (h.block_count > 0).then(|| h.block_count - 1),
                    rtt_ms: h.rtt_ema_ms.map(|r| r.round() as u64),
                    synchronized: h.synchronized,
                    opted_out: h.opted_out,
                    requests: u.requests.load(Ordering::Relaxed),
                    verified: u.verified.load(Ordering::Relaxed),
                    faults: u.faults.load(Ordering::Relaxed),
                    caps: u.cfg.caps,
                    last_error: h.last_error.clone(),
                }
            })
            .collect();
        PoolStatus {
            degraded: q.is_none(),
            quorum_height: q.as_ref().map(|q| q.height),
            quorum_hash: q.as_ref().map(|q| hex(&q.hash)),
            quorum_agreeing: q.as_ref().map_or(0, |q| q.agreeing.len()),
            upstreams,
            faults: self.faults.read().iter().cloned().collect(),
            opt_outs: self.opt_outs.read().clone(),
        }
    }

    /// Rule 5, forever: read every host's opt-out signal now, then daily.
    pub async fn run_opt_out_checker(self: Arc<Self>) {
        loop {
            self.check_opt_outs().await;
            tokio::time::sleep(OPT_OUT_CHECK_EVERY).await;
        }
    }

    /// One round of opt-out checks across all upstreams.
    pub async fn check_opt_outs(&self) {
        let checks = self.upstreams.iter().filter_map(|u| {
            let url = u.cfg.opt_out_url()?;
            Some(async move { (u.id, u.opt_out_signal(&url).await) })
        });
        for (id, signal) in futures_util::future::join_all(checks).await {
            if signal == Some(true) {
                self.mark_opted_out(id);
            }
        }
    }

    /// Record that the host behind `id` asked to be removed: out of
    /// rotation now, in the public log, and an operator action logged.
    pub fn mark_opted_out(&self, id: usize) {
        let first_time = {
            let mut health = self.health.write();
            let h = &mut health[id];
            let first = !h.opted_out;
            h.opted_out = true;
            first
        };
        if !first_time {
            return;
        }
        let u = &self.upstreams[id];
        let host = u.cfg.host().unwrap_or("").to_owned();
        tracing::error!(
            upstream = %u.cfg.name,
            host = %host,
            "host published /.well-known/mnr-optout: removed from rotation; add it to opt_out in the config"
        );
        self.opt_outs.write().push(OptOutEvent {
            at_unix: unix_now(),
            upstream: u.cfg.name.clone(),
            host,
        });
    }
}

struct Probe {
    block_count: u64,
    top_hash: Hash,
    synchronized: bool,
    restricted: bool,
    rtt_ms: f64,
}

impl Upstream {
    /// Take one light-call token, or fail immediately with [`ForwardError::Cap`].
    pub fn try_take_light(&self) -> bool {
        self.light.lock().try_take(Instant::now())
    }

    /// Queue for a light-call token for up to `max_wait` (rule 3: above the
    /// cap, requests queue). Polls every 10 ms and never holds the bucket
    /// lock across a wait. The cap itself is never exceeded.
    pub async fn take_light_within(&self, max_wait: Duration) -> bool {
        let deadline = Instant::now() + max_wait;
        loop {
            if self.try_take_light() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(LIGHT_POLL).await;
        }
    }

    /// How long a read may queue on this upstream before trying the next:
    /// a moment on a public node, longer on our own.
    pub fn queue_wait(&self) -> Duration {
        match self.cfg.kind {
            Kind::Owned => OWNED_QUEUE_WAIT,
            Kind::Public => PUBLIC_QUEUE_WAIT,
        }
    }

    /// Reserve a stream slot, if one is free right now.
    pub fn try_take_stream(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.streams).try_acquire_owned().ok()
    }

    /// Forward a client body to `path` on this upstream.
    ///
    /// Rule 6: the request is rebuilt from scratch. Only the body, its
    /// `Content-Type` and `Accept` travel; no client header of any kind is
    /// copied. The identifying `User-Agent` comes from the shared client.
    /// The response is likewise reduced to status, content type and body.
    pub async fn forward(
        &self,
        path: &str,
        content_type: &str,
        body: Bytes,
        timeout: Duration,
    ) -> Result<Forwarded, ForwardError> {
        self.requests.fetch_add(1, Ordering::Relaxed);
        let url = format!("{}{}", self.cfg.url.trim_end_matches('/'), path);
        let resp = self
            .client
            .post(url)
            .timeout(timeout)
            .header(reqwest::header::CONTENT_TYPE, content_type)
            .header(reqwest::header::ACCEPT, content_type)
            .body(body)
            .send()
            .await
            .map_err(classify)?;
        let status = resp.status().as_u16();
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        if resp
            .content_length()
            .is_some_and(|n| n > MAX_RESPONSE_BYTES)
        {
            return Err(ForwardError::Other("response too large".into()));
        }
        let mut body = Vec::new();
        let mut resp = resp;
        while let Some(chunk) = resp.chunk().await.map_err(classify)? {
            if body.len() + chunk.len() > MAX_RESPONSE_BYTES as usize {
                return Err(ForwardError::Other("response too large".into()));
            }
            body.extend_from_slice(&chunk);
        }
        let body = Bytes::from(body);
        Ok(Forwarded {
            status,
            content_type,
            body,
        })
    }

    /// Forward a client body and return the answer as a stream (the
    /// `get_blocks.bin` family). `timeout` bounds the wait for the response
    /// headers; the body is bounded by the idle timeout and size ceiling of
    /// [`crate::stream`]. Rule 6 applies exactly as in [`Upstream::forward`].
    /// `slot` is this upstream's stream permit; the returned body owns it.
    pub async fn forward_stream(
        &self,
        path: &str,
        content_type: &str,
        body: Bytes,
        timeout: Duration,
        slot: OwnedSemaphorePermit,
    ) -> Result<Streamed, ForwardError> {
        self.requests.fetch_add(1, Ordering::Relaxed);
        let url = format!("{}{}", self.cfg.url.trim_end_matches('/'), path);
        let send = self
            .client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, content_type)
            .header(reqwest::header::ACCEPT, content_type)
            .body(body)
            .send();
        let resp = tokio::time::timeout(timeout, send)
            .await
            .map_err(|_| ForwardError::Timeout)?
            .map_err(classify)?;
        let status = resp.status().as_u16();
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let content_length = resp.content_length();
        let inner: BoxStream<'static, Result<Bytes, ForwardError>> =
            resp.bytes_stream().map_err(classify).boxed();
        Ok(Streamed {
            status,
            content_type,
            content_length,
            body: throttled(inner, Arc::clone(&self.bandwidth), slot),
        })
    }

    /// Read the host's opt-out signal: `Some(true)` on HTTP 200, `Some(false)`
    /// on any other status, `None` when the host did not answer (no answer
    /// today; checked again tomorrow). A dedicated call: it takes no light
    /// token and is not counted in the public request figure, which is
    /// about RPC load.
    pub async fn opt_out_signal(&self, url: &str) -> Option<bool> {
        let resp = self
            .client
            .get(url)
            .timeout(OPT_OUT_TIMEOUT)
            .send()
            .await
            .ok()?;
        Some(resp.status().as_u16() == 200)
    }

    /// `get_info` with the identifying User-Agent and nothing else.
    async fn probe(&self) -> Result<Probe, String> {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: serde_json::Value::from(0),
            method: "get_info".into(),
            params: None,
        };
        let started = Instant::now();
        self.requests.fetch_add(1, Ordering::Relaxed);
        let resp = self
            .client
            .post(format!("{}/json_rpc", self.cfg.url.trim_end_matches('/')))
            .timeout(self.timeout)
            .json(&req)
            .send()
            .await
            .map_err(|e| trim_error(&e))?;
        if !resp.status().is_success() {
            return Err(format!("http {}", resp.status().as_u16()));
        }
        let body: JsonRpcResponse<GetInfoResult> = resp.json().await.map_err(|e| trim_error(&e))?;
        let rtt_ms = started.elapsed().as_secs_f64() * 1000.0;
        let info = body
            .result
            .ok_or_else(|| body.error.map_or("empty result".to_owned(), |e| e.message))?;
        let tip = info.tip_report(self.id).map_err(|e| e.to_string())?;
        Ok(Probe {
            block_count: info.height,
            top_hash: tip.hash,
            synchronized: info.synchronized,
            restricted: info.restricted,
            rtt_ms,
        })
    }
}

fn client(
    user_agent: &str,
    socks: Option<std::net::SocketAddr>,
) -> Result<reqwest::Client, reqwest::Error> {
    let mut b = reqwest::Client::builder()
        .user_agent(user_agent)
        // Never forward anything about a client; these are our own requests.
        .no_proxy()
        .pool_max_idle_per_host(4)
        .connect_timeout(Duration::from_secs(5));
    if let Some(addr) = socks {
        b = b.proxy(reqwest::Proxy::all(format!("socks5h://{addr}"))?);
    }
    b.build()
}

fn classify(e: reqwest::Error) -> ForwardError {
    if e.is_timeout() {
        ForwardError::Timeout
    } else if e.is_connect() {
        ForwardError::Connect
    } else {
        ForwardError::Other(trim_error(&e))
    }
}

/// Error text without URLs, so a log line never carries an upstream host
/// next to anything else.
fn trim_error(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        "timeout".into()
    } else if e.is_connect() {
        "connect failed".into()
    } else if e.is_decode() {
        "bad response body".into()
    } else {
        "request failed".into()
    }
}

fn hex(h: &Hash) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

/// A monotonic instant expressed as unix seconds, relative to `now`.
fn unix_at(t: Instant, now: Instant) -> u64 {
    unix_now() + t.saturating_duration_since(now).as_secs()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool() -> Pool {
        let cfg = Config::parse(
            r#"
tor_socks = "127.0.0.1:9050"
[[upstreams]]
name = "own"
url = "http://10.0.0.2:18081"
kind = "owned"
transport = "http"
[[upstreams]]
name = "pub-fast"
url = "https://fast.example:18081"
kind = "public"
transport = "https"
[[upstreams]]
name = "pub-slow"
url = "https://slow.example:18081"
kind = "public"
transport = "https"
[[upstreams]]
name = "onion"
url = "http://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567.onion:18081"
kind = "public"
transport = "onion"
"#,
        )
        .unwrap();
        Pool::from_config(&cfg).unwrap()
    }

    fn healthy(block_count: u64, rtt: f64) -> Health {
        Health {
            ok: true,
            block_count,
            top_hash: Some([7; 32]),
            synchronized: true,
            rtt_ema_ms: Some(rtt),
            ..Health::default()
        }
    }

    fn set(pool: &Pool, hs: [Health; 4], tip: Option<u64>) {
        *pool.health.write() = hs.to_vec();
        *pool.quorum.write() = tip.map(|height| QuorumTip {
            height,
            hash: [7; 32],
            agreeing: vec![0, 1, 2],
        });
    }

    #[test]
    fn light_ranking_is_rtt_with_owned_bonus_and_drops_stale() {
        let p = pool();
        set(
            &p,
            [
                healthy(101, 30.0),
                healthy(101, 15.0),
                healthy(100, 5.0),
                healthy(101, 400.0),
            ],
            Some(100),
        );
        // own (30-20=10) beats pub-fast (15); pub-slow is one block behind
        // the quorum tip and is excluded; onion is last but allowed.
        assert_eq!(p.ranked(Work::Light), vec![0, 1, 3]);
    }

    #[test]
    fn streams_prefer_owned_and_never_onion() {
        let p = pool();
        set(
            &p,
            [
                healthy(101, 900.0),
                healthy(101, 15.0),
                healthy(101, 20.0),
                healthy(101, 1.0),
            ],
            Some(100),
        );
        assert_eq!(p.ranked(Work::Stream), vec![0, 1, 2]);
    }

    #[test]
    fn degraded_mode_serves_owned_only() {
        let p = pool();
        set(
            &p,
            [
                healthy(90, 30.0),
                healthy(101, 15.0),
                healthy(101, 20.0),
                healthy(101, 1.0),
            ],
            None,
        );
        assert!(p.degraded());
        assert_eq!(p.ranked(Work::Light), vec![0]);
        assert_eq!(p.ranked(Work::Stream), vec![0]);
    }

    #[test]
    fn third_fault_in_window_ejects_and_is_logged() {
        let p = pool();
        set(
            &p,
            [
                healthy(101, 30.0),
                healthy(101, 15.0),
                healthy(101, 20.0),
                healthy(101, 1.0),
            ],
            Some(100),
        );
        p.record_fault(1, "get_block", "hash mismatch".into());
        p.record_fault(1, "get_block", "hash mismatch".into());
        assert!(p.ranked(Work::Light).contains(&1));
        p.record_fault(1, "get_block", "hash mismatch".into());
        assert!(!p.ranked(Work::Light).contains(&1));
        let s = p.status();
        assert_eq!(s.faults.len(), 3);
        assert!(s.faults[2].ejected && !s.faults[1].ejected);
        assert!(s.upstreams[1].ejected);
        assert_eq!(s.quorum_height, Some(100));
        assert!(!s.degraded);
    }

    #[test]
    fn ahead_of_quorum_and_forked_are_not_on_tip() {
        let p = pool();
        let mut forked = healthy(101, 1.0);
        forked.top_hash = Some([8; 32]);
        set(
            &p,
            [
                healthy(102, 1.0),
                healthy(101, 15.0),
                forked,
                healthy(101, 20.0),
            ],
            Some(100),
        );
        // own is one block ahead, pub-slow is on a fork: neither is on tip.
        assert_eq!(p.ranked(Work::Light), vec![1, 3]);
        let s = p.status();
        assert!(!s.upstreams[0].on_tip && !s.upstreams[2].on_tip);
    }

    #[test]
    fn ejection_lapse_is_visible_and_logged_once() {
        let p = pool();
        set(
            &p,
            [
                healthy(101, 30.0),
                healthy(101, 15.0),
                healthy(101, 20.0),
                healthy(101, 1.0),
            ],
            Some(100),
        );
        let t0 = Instant::now();
        for _ in 0..3 {
            p.record_fault_at(2, "get_block", "x".into(), t0);
        }
        let s = p.status();
        assert!(s.upstreams[2].ejected);
        let until = s.upstreams[2].ejected_until.unwrap();
        assert!(until >= unix_now() + EJECT_FOR.as_secs() - 2);
        // Two wall-clock reads: allow a second of rounding between them.
        let logged = s.faults[2].ejected_until.unwrap();
        assert!(logged.abs_diff(until) <= 1, "{logged} vs {until}");
        assert!(s.faults[1].ejected_until.is_none());
        // A day later the ejection has lapsed: back in rotation, the
        // status feed no longer shows an end time, and the transition is
        // noted once (the flag flips).
        // (`status()` reads the real clock, so only the flag is checked.)
        let later = t0 + EJECT_FOR + Duration::from_secs(1);
        assert!(p.health.read()[2].was_ejected);
        p.note_ejection_lapses(later);
        assert!(!p.health.read()[2].was_ejected);
        p.note_ejection_lapses(later);
        assert!(
            !p.health.read()[2].was_ejected,
            "a second round does not re-log"
        );
    }

    #[test]
    fn restricted_flag_is_reported_from_the_probe() {
        let p = pool();
        let mut open = healthy(101, 1.0);
        open.restricted = Some(false);
        set(
            &p,
            [
                healthy(101, 30.0),
                open,
                healthy(101, 20.0),
                healthy(101, 1.0),
            ],
            Some(100),
        );
        let s = p.status();
        assert_eq!(s.upstreams[0].restricted, None, "not probed yet");
        assert_eq!(s.upstreams[1].restricted, Some(false));
        // Information only: an unrestricted node still serves.
        assert!(p.ranked(Work::Light).contains(&1));
    }

    #[test]
    fn faults_older_than_the_window_do_not_count() {
        let p = pool();
        set(
            &p,
            [
                healthy(101, 30.0),
                healthy(101, 15.0),
                healthy(101, 20.0),
                healthy(101, 1.0),
            ],
            Some(100),
        );
        let t0 = Instant::now();
        p.record_fault_at(2, "get_block", "x".into(), t0);
        p.record_fault_at(2, "get_block", "x".into(), t0);
        let later = t0 + FAULT_WINDOW + Duration::from_secs(1);
        p.record_fault_at(2, "get_block", "x".into(), later);
        assert!(!p.status().upstreams[2].ejected, "two faults aged out");
        p.record_fault_at(2, "get_block", "x".into(), later);
        p.record_fault_at(2, "get_block", "x".into(), later);
        assert!(p.status().upstreams[2].ejected);
    }

    #[test]
    fn light_cap_is_one_second_of_rate_then_refills() {
        let mut b = LightBucket::new(5);
        let t0 = Instant::now();
        for _ in 0..5 {
            assert!(b.try_take(t0));
        }
        assert!(!b.try_take(t0), "sixth call within a second is refused");
        assert!(b.try_take(t0 + Duration::from_millis(200)));
        assert!(!b.try_take(t0 + Duration::from_millis(200)));
        // Idle time never banks more than one second of calls.
        let t1 = t0 + Duration::from_secs(60);
        for _ in 0..5 {
            assert!(b.try_take(t1));
        }
        assert!(!b.try_take(t1));
    }

    #[tokio::test]
    async fn opted_out_host_leaves_rotation_and_is_logged_without_counting() {
        use axum::routing::get;
        use std::sync::atomic::AtomicUsize;
        let hits = Arc::new(AtomicUsize::new(0));
        let h2 = Arc::clone(&hits);
        let app = axum::Router::new().route(
            "/.well-known/mnr-optout",
            get(move || {
                let h = Arc::clone(&h2);
                async move {
                    h.fetch_add(1, Ordering::SeqCst);
                    "please remove us"
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let p = pool();
        set(
            &p,
            [
                healthy(101, 30.0),
                healthy(101, 15.0),
                healthy(101, 20.0),
                healthy(101, 1.0),
            ],
            Some(100),
        );
        let before = p.status().upstreams[1].requests;
        let u = p.upstream(1);
        // 200 → opted out; 404 → nothing; unreachable → no answer today.
        let yes = u
            .opt_out_signal(&format!("http://{addr}/.well-known/mnr-optout"))
            .await;
        assert_eq!(yes, Some(true));
        let no = u.opt_out_signal(&format!("http://{addr}/other")).await;
        assert_eq!(no, Some(false));
        let none = u
            .opt_out_signal("http://127.0.0.1:1/.well-known/mnr-optout")
            .await;
        assert_eq!(none, None);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(
            p.status().upstreams[1].requests,
            before,
            "not an RPC request"
        );
        assert!(p.ranked(Work::Light).contains(&1));
        p.mark_opted_out(1);
        p.mark_opted_out(1);
        assert!(!p.ranked(Work::Light).contains(&1));
        let s = p.status();
        assert!(s.upstreams[1].opted_out);
        assert_eq!(s.opt_outs.len(), 1, "logged once");
        assert_eq!(s.opt_outs[0].upstream, "pub-fast");
        assert_eq!(s.opt_outs[0].host, "fast.example");
        // The derived URL for a real upstream is the host's web root.
        assert_eq!(
            u.cfg.opt_out_url().as_deref(),
            Some("https://fast.example/.well-known/mnr-optout")
        );
    }

    #[tokio::test]
    async fn queuing_for_a_light_token_waits_for_the_refill_but_not_longer() {
        let p = pool();
        let u = p.upstream(1); // public, 5 rps
        while u.try_take_light() {}
        let t0 = Instant::now();
        assert!(u.take_light_within(Duration::from_millis(250)).await);
        let waited = t0.elapsed();
        assert!(waited >= Duration::from_millis(150), "{waited:?}");
        assert!(waited <= Duration::from_millis(250), "{waited:?}");
        while u.try_take_light() {}
        assert!(!u.take_light_within(Duration::from_millis(50)).await);
        assert_eq!(p.upstream(0).queue_wait(), OWNED_QUEUE_WAIT);
        assert_eq!(u.queue_wait(), PUBLIC_QUEUE_WAIT);
    }

    #[tokio::test]
    async fn contended_queue_never_exceeds_the_cap() {
        // 20 waiters on an exhausted 5 rps bucket, each willing to wait
        // 250 ms: at most one token refills in that window (200 ms), so at
        // most one or two succeed and every waiter is back by ~250 ms.
        let p = Arc::new(pool());
        let u = p.upstream(1);
        while u.try_take_light() {}
        let t0 = Instant::now();
        let waiters: Vec<_> = (0..20)
            .map(|_| {
                let p = Arc::clone(&p);
                tokio::spawn(async move {
                    p.upstream(1)
                        .take_light_within(Duration::from_millis(250))
                        .await
                })
            })
            .collect();
        let mut granted = 0;
        for w in waiters {
            if w.await.unwrap() {
                granted += 1;
            }
        }
        assert!(granted <= 2, "{granted} granted from one refill window");
        assert!(
            t0.elapsed() < Duration::from_millis(400),
            "{:?}",
            t0.elapsed()
        );
    }

    #[test]
    fn stream_slots_are_capped_per_upstream() {
        let p = pool();
        let u = p.upstream(1);
        let a = u.try_take_stream().expect("slot 1");
        let _b = u.try_take_stream().expect("slot 2");
        assert!(u.try_take_stream().is_none(), "default cap is 2");
        drop(a);
        assert!(u.try_take_stream().is_some());
    }

    #[test]
    fn fault_log_is_bounded() {
        let p = pool();
        for _ in 0..(FAULT_LOG_MAX + 5) {
            p.record_fault(1, "m", "d".into());
        }
        assert_eq!(p.status().faults.len(), FAULT_LOG_MAX);
    }

    #[test]
    fn unhealthy_and_unsynchronized_are_excluded() {
        let p = pool();
        let mut unsynced = healthy(101, 1.0);
        unsynced.synchronized = false;
        set(
            &p,
            [
                Health::default(),
                healthy(101, 15.0),
                unsynced,
                healthy(101, 1.0),
            ],
            Some(100),
        );
        assert_eq!(p.ranked(Work::Light), vec![3, 1]);
    }
}
