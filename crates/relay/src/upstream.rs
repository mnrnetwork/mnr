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

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use mnr_core::hash::Hash;
use mnr_core::verify::{quorum_tip, QuorumTip, TipReport};
use mnr_core::wire::{GetInfoResult, JsonRpcRequest, JsonRpcResponse};
use parking_lot::RwLock;
use serde::Serialize;

use crate::config::{Config, Kind, Transport, UpstreamConfig};

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
    pub consecutive_failures: u32,
    faults: Vec<Instant>,
    ejected_until: Option<Instant>,
}

impl Health {
    fn ejected(&self, now: Instant) -> bool {
        self.ejected_until.is_some_and(|t| t > now)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FaultEvent {
    pub at_unix: u64,
    pub upstream: String,
    pub method: String,
    pub detail: String,
    pub ejected: bool,
}

pub struct Upstream {
    pub id: usize,
    pub cfg: UpstreamConfig,
    client: reqwest::Client,
    timeout: Duration,
    /// Requests we sent, for the public request-rate figure (rule 1).
    pub requests: AtomicU64,
}

pub struct Pool {
    pub upstreams: Vec<Upstream>,
    health: RwLock<Vec<Health>>,
    quorum: RwLock<Option<QuorumTip>>,
    faults: RwLock<Vec<FaultEvent>>,
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
    pub height: Option<u64>,
    pub rtt_ms: Option<u64>,
    pub synchronized: bool,
    pub requests: u64,
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
                    cfg: u,
                    client,
                    timeout,
                    requests: AtomicU64::new(0),
                }
            })
            .collect::<Vec<_>>();
        let n = upstreams.len();
        Ok(Self {
            upstreams,
            health: RwLock::new(vec![Health::default(); n]),
            quorum: RwLock::new(None),
            faults: RwLock::new(Vec::new()),
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
                        h.rtt_ema_ms = Some(match h.rtt_ema_ms {
                            Some(prev) => prev + RTT_ALPHA * (p.rtt_ms - prev),
                            None => p.rtt_ms,
                        });
                        h.last_error = None;
                        h.consecutive_failures = 0;
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
                        h.consecutive_failures += 1;
                        h.last_error = Some(e);
                    }
                }
            }
        }
        let q = quorum_tip(&reports, self.min_agree);
        match &q {
            Some(q) => {
                tracing::debug!(height = q.height, agreeing = q.agreeing.len(), "quorum tip")
            }
            None => tracing::warn!(reports = reports.len(), "no quorum: degraded mode"),
        }
        *self.quorum.write() = q;
    }

    pub fn quorum(&self) -> Option<QuorumTip> {
        self.quorum.read().clone()
    }

    pub fn degraded(&self) -> bool {
        self.quorum.read().is_none()
    }

    fn on_tip(h: &Health, q: Option<&QuorumTip>) -> bool {
        match q {
            Some(q) => h.block_count > q.height,
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
                if !h.ok || !h.synchronized || h.ejected(now) {
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
        let now = Instant::now();
        let ejected = {
            let mut health = self.health.write();
            let h = &mut health[id];
            h.faults.retain(|t| now.duration_since(*t) < FAULT_WINDOW);
            h.faults.push(now);
            if h.faults.len() >= FAULT_LIMIT && !h.ejected(now) {
                h.ejected_until = Some(now + EJECT_FOR);
                true
            } else {
                false
            }
        };
        let name = &self.upstreams[id].cfg.name;
        tracing::warn!(upstream = %name, method, %detail, ejected, "verification fault");
        self.faults.write().push(FaultEvent {
            at_unix: unix_now(),
            upstream: name.clone(),
            method: method.to_owned(),
            detail,
            ejected,
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
                    height: (h.block_count > 0).then(|| h.block_count - 1),
                    rtt_ms: h.rtt_ema_ms.map(|r| r.round() as u64),
                    synchronized: h.synchronized,
                    requests: u.requests.load(Ordering::Relaxed),
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
            faults: self.faults.read().clone(),
        }
    }
}

struct Probe {
    block_count: u64,
    top_hash: Hash,
    synchronized: bool,
    rtt_ms: f64,
}

impl Upstream {
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
