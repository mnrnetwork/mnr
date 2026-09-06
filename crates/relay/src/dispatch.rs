//! Dispatch: policy class → which upstreams, how many, what is verified,
//! what is cached, and what the client is told about it
//! (`docs/stage0-mvp-plan.md` §3–§5; invariants 1, 2 and 4).
//!
//! - **Immutable** (`get_block`, headers, `on_get_block_hash`): served from
//!   the cache when present, else fetched from the best-ranked upstream and
//!   verified ([`crate::verify`]). A wrong answer is a fault against that
//!   upstream and the next one is asked (up to three). A verified answer at
//!   or below the tip safety line is cached under the current chain epoch.
//! - **`/get_transactions`**: each verified transaction below the safety
//!   line is cached on its own; a batch is served as cache hits plus one
//!   upstream call for the misses, reassembled in request order.
//! - **Reads** of everything else go to the best-ranked upstream with
//!   capacity and fall through on transport failure, cap exhaustion or a
//!   5xx; they are annotated `Mnr-Verify: none`.
//! - **Streams** take a stream slot and prefer the owned node.
//! - **Broadcasts** fan out to every healthy upstream in parallel and
//!   succeed if any accepts (`Mnr-Relayed: k/n`).
//!
//! Every answer carries `Mnr-Verify` and `Mnr-Cache`; a single-upstream
//! answer carries `Mnr-Upstream` (an opaque pool index, never a name).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::stream::{BoxStream, StreamExt};
use mnr_core::policy::{Class, Policy, TIP_SAFETY_DEPTH};
use mnr_core::wire::{GetTransactionsResult, JsonRpcResponse};
use serde_json::{json, Value};

use crate::agreement;
use crate::auth::Tier;
use crate::cache::{Cache, Cached, Status};
use crate::chain::ChainStore;
use crate::consensus;
use crate::upstream::{ForwardError, Forwarded, Pool, Work};
use crate::verify::{self, batch_label, Fault, TxCheck, Verify};

/// Overall budget for a broadcast (policy note: 6 s).
const BROADCAST_BUDGET: Duration = Duration::from_secs(6);
/// How long a broadcast queues for a per-upstream light token before it
/// gives up on that upstream (rule 3: above the cap, requests queue).
const BROADCAST_CAP_WAIT: Duration = Duration::from_secs(1);
/// How many ranked upstreams a read may try before giving up.
const MAX_ATTEMPTS: usize = 3;

/// What dispatch needs besides the request. Shared handles, so a
/// background cache refresh can outlive the request that triggered it.
#[derive(Clone)]
pub struct Ctx {
    pub pool: Arc<Pool>,
    pub chain: Arc<ChainStore>,
    pub cache: Arc<Cache>,
}

/// One client request, already authenticated and admitted.
pub struct Request {
    /// The upstream path: `/json_rpc` or the legacy path.
    pub path: &'static str,
    /// The method as the client named it (JSON-RPC method or legacy path).
    pub method: String,
    /// JSON-RPC params, if any.
    pub params: Option<Value>,
    /// JSON-RPC id (`Null` for legacy paths); re-attached to cached answers.
    pub id: Value,
    pub content_type: &'static str,
    pub body: Bytes,
    /// Decides the agreement rule for the outputs family.
    pub tier: Tier,
}

/// What the ingress turns into an HTTP response.
pub struct Outcome {
    pub status: u16,
    pub content_type: String,
    /// The whole body, unless `stream` is set.
    pub body: Bytes,
    /// A streamed body (the `get_blocks.bin` family): the ingress sends it
    /// through as it arrives, counting bytes for the work-unit charge.
    pub stream: Option<BoxStream<'static, Result<Bytes, std::io::Error>>>,
    /// The upstream's `Content-Length` for a streamed body, when known.
    pub content_length: Option<u64>,
    /// `Mnr-*` headers to add.
    pub headers: Vec<(&'static str, String)>,
    /// Work units this request cost beyond the one charged at admission
    /// (buffered bodies only; streams are charged as they flow).
    pub extra_wu: u64,
}

impl std::fmt::Debug for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Outcome")
            .field("status", &self.status)
            .field("content_type", &self.content_type)
            .field("body_len", &self.body.len())
            .field("stream", &self.stream.is_some())
            .field("headers", &self.headers)
            .field("extra_wu", &self.extra_wu)
            .finish()
    }
}

impl Outcome {
    pub(crate) fn json_error(status: u16, message: &str, verify: Verify) -> Self {
        let body = json!({
            "error": { "code": -32603, "message": message },
            "status": message,
            "untrusted": true,
        });
        Self {
            status,
            content_type: "application/json".into(),
            body: Bytes::from(body.to_string()),
            stream: None,
            content_length: None,
            headers: vec![
                ("Mnr-Verify", verify.label().into()),
                ("Mnr-Cache", Status::Bypass.label().into()),
            ],
            extra_wu: 0,
        }
    }

    pub(crate) fn json_ok(body: String, headers: Vec<(&'static str, String)>) -> Self {
        Self {
            status: 200,
            content_type: "application/json".into(),
            body: Bytes::from(body),
            stream: None,
            content_length: None,
            headers,
            extra_wu: 0,
        }
    }
}

/// Methods whose request body says something about the wallet: which
/// outputs it is building a ring from, which transactions it looks up,
/// which key images it checks. These go to our own node first
/// ([`Work::Sensitive`]); a public node sees them only as the fallback.
const SENSITIVE: &[&str] = &[
    "/get_transactions",
    "/get_outs",
    "/get_outs.bin",
    "/get_o_indexes.bin",
    "/get_output_distribution.bin",
    "get_output_distribution",
    "get_output_histogram",
    "/is_key_image_spent",
];

/// Which ranking a method's requests use.
pub(crate) fn work_for(method: &str) -> Work {
    if SENSITIVE.contains(&verify::canonical(method)) {
        Work::Sensitive
    } else {
        Work::Light
    }
}

/// Route one request by its policy class.
pub async fn dispatch(ctx: Ctx, policy: &'static Policy, req: Request) -> Outcome {
    let timeout = Duration::from_millis(u64::from(policy.timeout_ms.max(1000)));
    match policy.class {
        Class::Broadcast => broadcast(&ctx.pool, req.path, req.content_type, req.body).await,
        Class::PassthroughStream => {
            stream(&ctx.pool, req.path, req.content_type, req.body, timeout).await
        }
        Class::Deny | Class::NotDaemon => {
            Outcome::json_error(403, "method not allowed", Verify::None)
        }
        Class::Immutable => immutable(ctx, req, timeout).await,
        Class::ImmutableConditional if verify::canonical(&req.method) == "/get_transactions" => {
            transactions(ctx, req, timeout).await
        }
        Class::ImmutableConditional => agreement::agreement(ctx, policy, req, timeout).await,
        Class::Swr => consensus::swr(ctx, req, timeout).await,
        Class::Composed => crate::pool::compose(ctx, req, timeout).await,
        _ => {
            let work = work_for(&req.method);
            read(
                &ctx.pool,
                req.path,
                req.content_type,
                req.body,
                timeout,
                work,
            )
            .await
        }
    }
}

/// A light token for a read: the best-ranked upstream is worth a short
/// queue (rule 3: above the cap, requests queue or go to our own node);
/// the fall-through candidates are tried without waiting.
async fn take_light(u: &crate::upstream::Upstream, rank: usize) -> bool {
    if rank == 0 {
        u.take_light_within(u.queue_wait()).await
    } else {
        u.try_take_light()
    }
}

/// The tip safety line: the highest height that may be cached, or `None`
/// in degraded mode (no quorum → no cache writes).
pub(crate) fn safety_line(pool: &Pool) -> Option<u64> {
    pool.quorum()
        .map(|q| q.height.saturating_sub(TIP_SAFETY_DEPTH))
}

/// `serde_json::Value` objects serialise with sorted keys, so this is a
/// canonical form of the params for cache keys.
pub(crate) fn params_key(params: Option<&Value>) -> String {
    params.map_or_else(String::new, Value::to_string)
}

/// A cached `result`, re-wrapped with the client's id.
pub(crate) fn jsonrpc_body(id: &Value, result: &[u8]) -> String {
    format!(
        "{{\"id\":{},\"jsonrpc\":\"2.0\",\"result\":{}}}",
        id,
        String::from_utf8_lossy(result)
    )
}

/// The `result` of a JSON-RPC answer as bytes, if it has one.
fn result_bytes(body: &[u8]) -> Option<Vec<u8>> {
    let resp: JsonRpcResponse<Value> = serde_json::from_slice(body).ok()?;
    serde_json::to_vec(&resp.result?).ok()
}

fn verified_headers(
    v: &verify::Verified,
    upstream: Option<usize>,
    cache: Status,
) -> Vec<(&'static str, String)> {
    let mut h = vec![
        ("Mnr-Verify", v.verify.label().to_owned()),
        ("Mnr-Cache", cache.label().to_owned()),
    ];
    if let Some(id) = upstream {
        h.push(("Mnr-Upstream", id.to_string()));
    }
    if let Some((k, n)) = v.counted {
        h.push(("Mnr-Verified", format!("{k}/{n}")));
    }
    h
}

/// Try ranked upstreams in turn; `check` accepts or faults each answer.
/// Returns the accepted answer with its upstream, or the error outcome.
async fn fetch_verified<T>(
    pool: &Pool,
    path: &str,
    content_type: &str,
    body: Bytes,
    timeout: Duration,
    method: &str,
    mut check: impl FnMut(&Forwarded) -> Result<T, Fault>,
) -> Result<(Forwarded, usize, T), Box<Outcome>> {
    let ranked = pool.ranked(work_for(method));
    if ranked.is_empty() {
        return Err(Box::new(Outcome::json_error(
            503,
            "no healthy upstream",
            Verify::None,
        )));
    }
    let mut last = ForwardError::Cap;
    let mut faults = 0usize;
    let mut attempts = 0usize;
    for (rank, id) in ranked.into_iter().take(MAX_ATTEMPTS).enumerate() {
        let u = pool.upstream(id);
        if !take_light(u, rank).await {
            last = ForwardError::Cap;
            continue;
        }
        attempts += 1;
        match u.forward(path, content_type, body.clone(), timeout).await {
            Ok(f) if f.status >= 500 => last = ForwardError::Other(format!("http {}", f.status)),
            Ok(f) => match check(&f) {
                Ok(t) => return Ok((f, id, t)),
                Err(Fault(detail)) => {
                    pool.record_fault(id, method, detail);
                    faults += 1;
                }
            },
            Err(e) => last = e,
        }
    }
    if faults > 0 && faults == attempts {
        return Err(Box::new(Outcome::json_error(
            502,
            "upstream answers failed verification",
            Verify::Failed,
        )));
    }
    let status = if last == ForwardError::Cap { 503 } else { 502 };
    Err(Box::new(Outcome::json_error(
        status,
        &format!("upstream unavailable: {last}"),
        Verify::None,
    )))
}

/// Immutable JSON-RPC methods: cache, fetch, verify, fault-and-retry, cache.
async fn immutable(ctx: Ctx, req: Request, timeout: Duration) -> Outcome {
    let method = verify::canonical(&req.method).to_owned();
    let key = Cache::immutable_key(ctx.chain.epoch(), &method, &params_key(req.params.as_ref()));
    if let Some(c) = ctx.cache.immutable_get(&key).await {
        let v = verify::Verified {
            verify: label_of(c.verify),
            height: None,
            counted: None,
        };
        return Outcome::json_ok(
            jsonrpc_body(&req.id, &c.body),
            verified_headers(&v, None, Status::Hit),
        );
    }
    let line = safety_line(&ctx.pool);
    let fetched = fetch_verified(
        &ctx.pool,
        req.path,
        req.content_type,
        req.body,
        timeout,
        &method,
        |f| verify::verify_jsonrpc(&req.method, req.params.as_ref(), &f.body, &ctx.chain.read()),
    )
    .await;
    let (f, id, v) = match fetched {
        Ok(x) => x,
        Err(o) => return *o,
    };
    // A chain- or hash-verified answer is what the public verified count
    // records (plan §4); an unverifiable one (`none`) is served but not
    // credited, and a cache hit asked nobody.
    if v.verify != Verify::None {
        ctx.pool.record_verified(id);
    }
    let cacheable =
        v.verify != Verify::None && matches!((v.height, line), (Some(h), Some(l)) if h <= l);
    if cacheable {
        if let Some(result) = result_bytes(&f.body) {
            ctx.cache
                .immutable_put(
                    key,
                    Cached {
                        body: Bytes::from(result),
                        verify: v.verify.label(),
                    },
                )
                .await;
        }
    }
    let mut o = passthrough(f, id, 0);
    o.headers = verified_headers(&v, Some(id), Status::Miss);
    o
}

/// The label an entry was cached with, back as a [`Verify`].
fn label_of(label: &str) -> Verify {
    match label {
        "chain" => Verify::Chain,
        "hash" => Verify::Hash,
        "majority" => Verify::Majority,
        "agreement" => Verify::Agreement,
        "partial" => Verify::Partial,
        _ => Verify::None,
    }
}

/// One cached transaction: its `txs[i]` object and the parallel strings.
#[derive(serde::Serialize, serde::Deserialize)]
struct TxCached {
    entry: Value,
    as_hex: String,
    as_json: String,
}

/// `/get_transactions`: per-tx cache, batch split, verification. Also the
/// verified source of the composed pool listing (`pool.rs`).
pub(crate) async fn transactions(ctx: Ctx, req: Request, timeout: Duration) -> Outcome {
    let request: Value = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(_) => {
            return read(
                &ctx.pool,
                req.path,
                req.content_type,
                req.body,
                timeout,
                Work::Sensitive,
            )
            .await
        }
    };
    let Some(hashes) = request.get("txs_hashes").and_then(Value::as_array) else {
        return read(
            &ctx.pool,
            req.path,
            req.content_type,
            req.body,
            timeout,
            Work::Sensitive,
        )
        .await;
    };
    let hashes: Vec<String> = hashes
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_ascii_lowercase)
        .collect();
    let prune = request
        .get("prune")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let as_json = request
        .get("decode_as_json")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let epoch = ctx.chain.epoch();

    let mut hits: HashMap<String, TxCached> = HashMap::new();
    let mut misses: Vec<String> = Vec::new();
    for h in &hashes {
        if hits.contains_key(h) || misses.contains(h) {
            continue;
        }
        match ctx
            .cache
            .tx_get(&Cache::tx_key(epoch, h, prune, as_json))
            .await
        {
            Some(bytes) => match serde_json::from_slice::<TxCached>(&bytes) {
                Ok(c) => {
                    hits.insert(h.clone(), c);
                }
                Err(_) => misses.push(h.clone()),
            },
            None => misses.push(h.clone()),
        }
    }

    if misses.is_empty() {
        let v = verify::Verified {
            verify: if hashes.is_empty() {
                Verify::None
            } else {
                Verify::Hash
            },
            height: None,
            counted: None,
        };
        let body = assemble(&hashes, &hits, None, as_json);
        return Outcome::json_ok(body.to_string(), verified_headers(&v, None, Status::Hit));
    }

    let mut upstream_req = request.clone();
    upstream_req["txs_hashes"] = json!(misses);
    let tip = ctx.pool.quorum().map(|q| q.height);
    let line = safety_line(&ctx.pool);
    let fetched = fetch_verified(
        &ctx.pool,
        req.path,
        req.content_type,
        Bytes::from(upstream_req.to_string()),
        timeout,
        "/get_transactions",
        |f| {
            // A daemon-level answer (`{"status":"Failed",…}` with no `txs`)
            // is the node declining, not lying: pass it through unverified.
            let raw: Value =
                serde_json::from_slice(&f.body).map_err(|_| Fault("answer is not JSON".into()))?;
            if raw.get("txs").is_none() {
                let empty: GetTransactionsResult = serde_json::from_value(json!({
                    "txs": [], "txs_as_hex": [],
                    "status": raw.get("status").cloned().unwrap_or(json!("Failed")),
                    "untrusted": true
                }))
                .map_err(|_| Fault("answer is not a get_transactions result".into()))?;
                return Ok((empty, Vec::new()));
            }
            let result: GetTransactionsResult = serde_json::from_value(raw)
                .map_err(|_| Fault("answer is not a get_transactions result".into()))?;
            let checks = verify::verify_transactions(&misses, &result, tip)?;
            Ok((result, checks))
        },
    )
    .await;
    let (f, id, (result, checks)) = match fetched {
        Ok(x) => x,
        Err(o) => return *o,
    };
    if checks.iter().any(|c| matches!(c, TxCheck::Verified { .. })) {
        ctx.pool.record_verified(id);
    }
    let answer: Value = serde_json::from_slice(&f.body).unwrap_or(Value::Null);

    // Cache every verified, confirmed entry below the safety line.
    let mut fresh: HashMap<String, TxCached> = HashMap::new();
    for (i, (entry, check)) in result.txs.iter().zip(&checks).enumerate() {
        let hash = entry.tx_hash.to_ascii_lowercase();
        let cached = TxCached {
            entry: answer["txs"].get(i).cloned().unwrap_or(Value::Null),
            as_hex: answer["txs_as_hex"]
                .get(i)
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
            as_json: answer["txs_as_json"]
                .get(i)
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
        };
        if let TxCheck::Verified { height: Some(h) } = check {
            if line.is_some_and(|l| *h <= l) {
                if let Ok(bytes) = serde_json::to_vec(&cached) {
                    ctx.cache
                        .tx_put(
                            Cache::tx_key(epoch, &hash, prune, as_json),
                            Bytes::from(bytes),
                        )
                        .await;
                }
            }
        }
        fresh.insert(hash, cached);
    }

    let (mut label, mut counted) = batch_label(&checks);
    if hits.is_empty() {
        let v = verify::Verified {
            verify: label,
            height: None,
            counted,
        };
        let mut o = passthrough(f, id, 0);
        o.headers = verified_headers(&v, Some(id), Status::Miss);
        return o;
    }
    // Mixed: cached entries count as verified.
    let k = hits.len()
        + checks
            .iter()
            .filter(|c| matches!(c, TxCheck::Verified { .. }))
            .count();
    let n = hits.len() + checks.len();
    if k == n {
        label = Verify::Hash;
        counted = None;
    } else if k > 0 {
        label = Verify::Partial;
        counted = Some((k, n));
    }
    let v = verify::Verified {
        verify: label,
        height: None,
        counted,
    };
    hits.extend(fresh);
    let body = assemble(&hashes, &hits, Some(&answer), as_json);
    Outcome::json_ok(
        body.to_string(),
        verified_headers(&v, Some(id), Status::Miss),
    )
}

/// Rebuild a `/get_transactions` answer in request order from cached and
/// fresh entries; anything absent from both is `missed_tx`.
fn assemble(
    order: &[String],
    entries: &HashMap<String, TxCached>,
    upstream: Option<&Value>,
    as_json: bool,
) -> Value {
    let mut txs = Vec::new();
    let mut txs_as_hex = Vec::new();
    let mut txs_as_json = Vec::new();
    let mut missed = Vec::new();
    let mut seen = Vec::new();
    for h in order {
        if seen.contains(h) {
            continue;
        }
        seen.push(h.clone());
        match entries.get(h) {
            Some(c) => {
                txs.push(c.entry.clone());
                txs_as_hex.push(Value::String(c.as_hex.clone()));
                txs_as_json.push(Value::String(c.as_json.clone()));
            }
            None => missed.push(Value::String(h.clone())),
        }
    }
    let field = |name: &str, default: Value| -> Value {
        upstream
            .and_then(|u| u.get(name).cloned())
            .unwrap_or(default)
    };
    let mut out = json!({
        "credits": field("credits", json!(0)),
        "status": field("status", json!("OK")),
        "top_hash": field("top_hash", json!("")),
        "txs": txs,
        "txs_as_hex": txs_as_hex,
        "untrusted": field("untrusted", json!(true)),
    });
    if as_json {
        out["txs_as_json"] = Value::Array(txs_as_json);
    }
    if !missed.is_empty() {
        out["missed_tx"] = Value::Array(missed);
    }
    out
}

pub(crate) async fn read(
    pool: &Pool,
    path: &str,
    content_type: &str,
    body: Bytes,
    timeout: Duration,
    work: Work,
) -> Outcome {
    let ranked = pool.ranked(work);
    if ranked.is_empty() {
        return Outcome::json_error(503, "no healthy upstream", Verify::None);
    }
    let mut last = ForwardError::Cap;
    for (rank, id) in ranked.into_iter().take(MAX_ATTEMPTS).enumerate() {
        let u = pool.upstream(id);
        if !take_light(u, rank).await {
            last = ForwardError::Cap;
            continue;
        }
        match u.forward(path, content_type, body.clone(), timeout).await {
            Ok(f) if f.status >= 500 => {
                last = ForwardError::Other(format!("http {}", f.status));
            }
            Ok(f) => return passthrough(f, id, 0),
            Err(e) => last = e,
        }
    }
    let status = if last == ForwardError::Cap { 503 } else { 502 };
    Outcome::json_error(
        status,
        &format!("upstream unavailable: {last}"),
        Verify::None,
    )
}

/// Streams take a stream slot, prefer the owned node, and are sent through
/// as they arrive (see [`crate::stream`]): paced by the upstream's
/// bandwidth cap, cut on a 15 s upstream silence, never buffered.
async fn stream(
    pool: &Pool,
    path: &str,
    content_type: &str,
    body: Bytes,
    timeout: Duration,
) -> Outcome {
    let ranked = pool.ranked(Work::Stream);
    if ranked.is_empty() {
        return Outcome::json_error(503, "no healthy upstream", Verify::None);
    }
    let mut failed = 0usize;
    for id in ranked {
        let u = pool.upstream(id);
        let Some(slot) = u.try_take_stream() else {
            continue;
        };
        match u
            .forward_stream(path, content_type, body.clone(), timeout, slot)
            .await
        {
            Ok(s) if s.status < 500 => {
                return Outcome {
                    status: s.status,
                    content_type: s
                        .content_type
                        .unwrap_or_else(|| "application/octet-stream".to_owned()),
                    body: Bytes::new(),
                    stream: Some(s.body.boxed()),
                    content_length: s.content_length,
                    headers: vec![
                        ("Mnr-Verify", Verify::None.label().into()),
                        ("Mnr-Cache", Status::Bypass.label().into()),
                        ("Mnr-Upstream", id.to_string()),
                    ],
                    extra_wu: 0,
                };
            }
            Ok(_) | Err(_) => failed += 1,
        }
    }
    if failed > 0 {
        Outcome::json_error(502, "upstream unavailable for streams", Verify::None)
    } else {
        Outcome::json_error(503, "all stream slots busy", Verify::None)
    }
}

/// Fan out to every healthy upstream; success if any accepts. The response
/// carries `Mnr-Relayed: k/n`. If all reject, the first rejection is
/// returned verbatim so the wallet sees the daemon's own reason.
async fn broadcast(pool: &Pool, path: &str, content_type: &str, body: Bytes) -> Outcome {
    let ranked = pool.ranked(Work::Light);
    let n = ranked.len();
    if n == 0 {
        return Outcome::json_error(503, "no healthy upstream", Verify::None);
    }
    let sends = ranked.iter().map(|&id| {
        let u = pool.upstream(id);
        let body = body.clone();
        async move {
            // Rule 3 applies to broadcasts too: wait briefly for a light
            // token on this upstream, then skip it rather than exceed the
            // published cap. The owned node's cap is large.
            let started = Instant::now();
            while !u.try_take_light() {
                if started.elapsed() >= BROADCAST_CAP_WAIT {
                    return (id, Err(ForwardError::Cap));
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            (
                id,
                u.forward(path, content_type, body, BROADCAST_BUDGET).await,
            )
        }
    });
    let results = futures_util::future::join_all(sends).await;
    let mut accepted = 0usize;
    let mut first_ok: Option<(usize, Forwarded)> = None;
    let mut first_reject: Option<(usize, Forwarded)> = None;
    for (id, r) in results {
        if let Ok(f) = r {
            if f.status == 200 && accepted_by_daemon(&f.body) {
                accepted += 1;
                first_ok.get_or_insert((id, f));
            } else {
                first_reject.get_or_insert((id, f));
            }
        }
    }
    let relayed = format!("{accepted}/{n}");
    let (id, f) = match (first_ok, first_reject) {
        (Some(ok), _) => ok,
        (None, Some(rej)) => rej,
        (None, None) => {
            let mut o = Outcome::json_error(502, "no upstream answered", Verify::None);
            o.headers.push(("Mnr-Relayed", relayed));
            return o;
        }
    };
    let mut o = passthrough(f, id, 0);
    o.headers.push(("Mnr-Relayed", relayed));
    o
}

/// monerod answers a rejected `send_raw_transaction` with HTTP 200 and
/// `status != "OK"`; only `"OK"` counts as accepted.
fn accepted_by_daemon(body: &[u8]) -> bool {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v.get("status").and_then(Value::as_str).map(|s| s == "OK"))
        .unwrap_or(false)
}

/// `Mnr-Upstream` is the upstream's number in the pool (plan §4: an opaque
/// id, not the node name), so a client learns that different answers came
/// from different nodes without the relay advertising which one saw what.
fn passthrough(f: Forwarded, upstream: usize, extra_wu: u64) -> Outcome {
    Outcome {
        status: f.status,
        content_type: f
            .content_type
            .unwrap_or_else(|| "application/json".to_owned()),
        body: f.body,
        stream: None,
        content_length: None,
        headers: vec![
            ("Mnr-Verify", Verify::None.label().into()),
            ("Mnr-Cache", Status::Bypass.label().into()),
            ("Mnr-Upstream", upstream.to_string()),
        ],
        extra_wu,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::upstream::Health;
    use axum::body::Bytes as AxBytes;
    use axum::extract::Path;
    use axum::routing::post;
    use axum::Router;
    use mnr_core::headerchain::{Entry, HeaderChain};
    use mnr_core::wire::{decode_hex, JsonRpcRequest};
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    const BLOCK0: &str = include_str!("../../core/fixtures/mainnet/block-0.json");
    const BLOCK1: &str = include_str!("../../core/fixtures/mainnet/block-1.json");
    const TXS_FULL: &str = include_str!("../../core/fixtures/mainnet/txs-3754000-prune-false.json");

    type Handler = Arc<dyn Fn(&str, &[u8]) -> (u16, String) + Send + Sync>;

    /// A fake monerod: `handler(path, body)` decides every answer.
    async fn mock_with(handler: Handler, hits: Arc<AtomicUsize>) -> SocketAddr {
        let app = Router::new().route(
            "/{*rest}",
            post(move |Path(rest): Path<String>, body: AxBytes| {
                let handler = Arc::clone(&handler);
                let hits = Arc::clone(&hits);
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    let (status, body) = handler(&format!("/{rest}"), &body);
                    (axum::http::StatusCode::from_u16(status).unwrap(), body)
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        addr
    }

    /// A fake monerod that answers every POST with a fixed status + body.
    async fn mock(status: u16, body: &'static str, hits: Arc<AtomicUsize>) -> SocketAddr {
        mock_with(Arc::new(move |_, _| (status, body.to_owned())), hits).await
    }

    /// A pool over `addrs`, all healthy and on a synthetic quorum tip.
    fn pool_over(addrs: &[SocketAddr]) -> Pool {
        pool_at(addrs, 100)
    }

    fn pool_at(addrs: &[SocketAddr], tip: u64) -> Pool {
        let mut toml = String::from("[probe]\nmin_agree = 1\n");
        for (i, a) in addrs.iter().enumerate() {
            toml.push_str(&format!(
                "[[upstreams]]\nname = \"m{i}\"\nurl = \"http://{a}\"\nkind = \"public\"\ntransport = \"http\"\n"
            ));
        }
        let pool = Pool::from_config(&Config::parse(&toml).unwrap()).unwrap();
        let mut health = Vec::new();
        for i in 0..addrs.len() {
            let mut h = Health::healthy_for_test(tip + 1, [7; 32]);
            h.rtt_ema_ms = Some(10.0 + i as f64); // rank in address order
            health.push(h);
        }
        pool.set_for_test(health, Some((tip, [7; 32])));
        pool
    }

    struct Env {
        pool: Arc<Pool>,
        chain: Arc<ChainStore>,
        cache: Arc<Cache>,
    }

    impl Env {
        fn new(pool: Pool) -> Self {
            let chain = ChainStore::open(None).unwrap();
            let mut c = HeaderChain::new();
            for fx in [BLOCK0, BLOCK1] {
                let v: Value = serde_json::from_str(fx).unwrap();
                let blob = decode_hex(v["result"]["blob"].as_str().unwrap()).unwrap();
                c.append(Entry::from(&mnr_core::hash::parse_block(&blob).unwrap()))
                    .unwrap();
            }
            chain.set_for_test(c);
            Self {
                pool: Arc::new(pool),
                chain: Arc::new(chain),
                cache: Arc::new(Cache::new(1 << 20)),
            }
        }

        fn ctx(&self) -> Ctx {
            Ctx {
                pool: Arc::clone(&self.pool),
                chain: Arc::clone(&self.chain),
                cache: Arc::clone(&self.cache),
            }
        }

        async fn jsonrpc(&self, method: &str, params: Value) -> Outcome {
            let policy = mnr_core::policy::lookup(method).unwrap();
            let req = JsonRpcRequest {
                jsonrpc: "2.0".into(),
                id: json!(42),
                method: method.into(),
                params: Some(params.clone()),
            };
            dispatch(
                self.ctx(),
                policy,
                Request {
                    path: "/json_rpc",
                    method: method.into(),
                    params: Some(params),
                    id: json!(42),
                    content_type: "application/json",
                    body: Bytes::from(serde_json::to_vec(&req).unwrap()),
                    tier: Tier::Free,
                },
            )
            .await
        }

        async fn legacy(&self, path: &'static str, body: Value) -> Outcome {
            let policy = mnr_core::policy::lookup(path).unwrap();
            dispatch(
                self.ctx(),
                policy,
                Request {
                    path,
                    method: path.into(),
                    params: None,
                    id: Value::Null,
                    content_type: "application/json",
                    body: Bytes::from(body.to_string()),
                    tier: Tier::Free,
                },
            )
            .await
        }
    }

    fn header<'a>(o: &'a Outcome, name: &str) -> Option<&'a str> {
        o.headers
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.as_str())
    }

    /// Serve the block fixtures by height or hash; `tamper` flips a blob byte.
    fn block_server(tamper: bool) -> Handler {
        Arc::new(move |_, body| {
            let req: JsonRpcRequest = serde_json::from_slice(body).unwrap();
            let p = req.params.unwrap_or(Value::Null);
            let fx = match (p.get("height").and_then(Value::as_u64), p.get("hash")) {
                (Some(0), _) => BLOCK0,
                (Some(1), _) => BLOCK1,
                (_, Some(h)) => {
                    let h1: Value = serde_json::from_str(BLOCK1).unwrap();
                    if h1["result"]["block_header"]["hash"] == *h {
                        BLOCK1
                    } else {
                        BLOCK0
                    }
                }
                _ => {
                    return (
                        200,
                        json!({"jsonrpc":"2.0","id":req.id,"error":{"code":-2,"message":"Requested block height: 9 greater than current top block height: 1"}}).to_string(),
                    )
                }
            };
            let mut v: Value = serde_json::from_str(fx).unwrap();
            v["id"] = req.id;
            if tamper {
                let blob = v["result"]["blob"].as_str().unwrap().to_owned();
                let mut chars: Vec<char> = blob.chars().collect();
                let i = chars.len() - 10;
                chars[i] = if chars[i] == '0' { '1' } else { '0' };
                v["result"]["blob"] = Value::String(chars.into_iter().collect());
            }
            (200, v.to_string())
        })
    }

    #[tokio::test]
    async fn verified_block_is_cached_below_the_safety_line() {
        let hits = Arc::new(AtomicUsize::new(0));
        let good = mock_with(block_server(false), Arc::clone(&hits)).await;
        let env = Env::new(pool_over(&[good]));
        let o = env.jsonrpc("get_block", json!({"height": 1})).await;
        assert_eq!(o.status, 200);
        assert_eq!(header(&o, "Mnr-Verify"), Some("chain"));
        assert_eq!(header(&o, "Mnr-Cache"), Some("miss"));
        assert_eq!(header(&o, "Mnr-Upstream"), Some("0"));
        let v: Value = serde_json::from_slice(&o.body).unwrap();
        assert_eq!(v["id"], 42);
        // Second time: from cache, with this request's id, no upstream call.
        let o = env.jsonrpc("get_block", json!({"height": 1})).await;
        assert_eq!(header(&o, "Mnr-Cache"), Some("hit"));
        assert_eq!(header(&o, "Mnr-Verify"), Some("chain"));
        assert_eq!(header(&o, "Mnr-Upstream"), None);
        let v: Value = serde_json::from_slice(&o.body).unwrap();
        assert_eq!(v["id"], 42);
        assert_eq!(v["result"]["block_header"]["height"], 1);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        // The alias shares the cache entry.
        let o = env.jsonrpc("getblock", json!({"height": 1})).await;
        assert_eq!(header(&o, "Mnr-Cache"), Some("hit"));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        // One upstream answer was verified; the cache hits credit nobody.
        assert_eq!(env.pool.status().upstreams[0].verified, 1);
    }

    #[tokio::test]
    async fn chain_verified_answers_count_as_verified_and_unverifiable_ones_do_not() {
        let hits = Arc::new(AtomicUsize::new(0));
        let good = mock_with(block_server(false), Arc::clone(&hits)).await;
        let env = Env::new(pool_at(&[good], 5));
        let o = env.jsonrpc("get_block", json!({"height": 1})).await;
        assert_eq!(header(&o, "Mnr-Verify"), Some("chain"));
        assert_eq!(env.pool.status().upstreams[0].verified, 1);
        // Height 2 is beyond the test chain: served as `none`, not credited.
        let o = env.jsonrpc("get_block", json!({"height": 2})).await;
        assert_eq!(header(&o, "Mnr-Verify"), Some("none"));
        assert_eq!(env.pool.status().upstreams[0].verified, 1);
        assert_eq!(env.pool.status().upstreams[0].faults, 0);
    }

    #[tokio::test]
    async fn blocks_near_the_tip_are_verified_but_never_cached() {
        let hits = Arc::new(AtomicUsize::new(0));
        let good = mock_with(block_server(false), Arc::clone(&hits)).await;
        // Quorum tip at 5: block 1 is within TIP_SAFETY_DEPTH of it.
        let env = Env::new(pool_at(&[good], 5));
        for _ in 0..2 {
            let o = env.jsonrpc("get_block", json!({"height": 1})).await;
            assert_eq!(header(&o, "Mnr-Verify"), Some("chain"));
            assert_eq!(header(&o, "Mnr-Cache"), Some("miss"));
        }
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        // Degraded (no quorum): served, verified, not cached either.
        env.pool.set_for_test(vec![Health::default(); 1], None);
        let o = env.jsonrpc("get_block", json!({"height": 1})).await;
        assert_eq!(o.status, 503, "degraded with no owned node: nothing serves");
    }

    #[tokio::test]
    async fn tampered_upstream_is_faulted_and_the_next_one_answers() {
        let hits = Arc::new(AtomicUsize::new(0));
        let bad = mock_with(block_server(true), Arc::clone(&hits)).await;
        let good = mock_with(block_server(false), Arc::clone(&hits)).await;
        let env = Env::new(pool_over(&[bad, good]));
        let o = env.jsonrpc("get_block", json!({"height": 1})).await;
        assert_eq!(o.status, 200);
        assert_eq!(header(&o, "Mnr-Verify"), Some("chain"));
        assert_eq!(header(&o, "Mnr-Upstream"), Some("1"));
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        let s = env.pool.status();
        assert_eq!(s.faults.len(), 1);
        assert_eq!(s.faults[0].upstream, "m0");
        assert_eq!(s.faults[0].method, "get_block");
        assert!(
            s.faults[0].detail.contains("hash mismatch"),
            "{}",
            s.faults[0].detail
        );
        // By hash, beyond our chain's reach the label is `hash`; on the
        // chain it is `chain`.
        let h1: Value = serde_json::from_str(BLOCK1).unwrap();
        let o = env
            .jsonrpc(
                "get_block",
                json!({"hash": h1["result"]["block_header"]["hash"]}),
            )
            .await;
        assert_eq!(header(&o, "Mnr-Verify"), Some("chain"));
    }

    #[tokio::test]
    async fn all_upstreams_wrong_is_a_failed_verification_error() {
        let hits = Arc::new(AtomicUsize::new(0));
        let bad1 = mock_with(block_server(true), Arc::clone(&hits)).await;
        let bad2 = mock_with(block_server(true), Arc::clone(&hits)).await;
        let env = Env::new(pool_over(&[bad1, bad2]));
        let o = env.jsonrpc("get_block", json!({"height": 0})).await;
        assert_eq!(o.status, 502);
        assert_eq!(header(&o, "Mnr-Verify"), Some("failed"));
        assert_eq!(env.pool.status().faults.len(), 2);
        // A daemon error passes through unverified and is not a fault.
        let o = env.jsonrpc("get_block", json!({"height": 9})).await;
        assert_eq!(o.status, 200);
        assert_eq!(header(&o, "Mnr-Verify"), Some("none"));
        assert_eq!(env.pool.status().faults.len(), 2);
    }

    /// Serve `/get_transactions` from the fixture, filtered to the request.
    fn tx_server(tamper: bool, asked: Arc<parking_lot::Mutex<Vec<Vec<String>>>>) -> Handler {
        Arc::new(move |path, body| {
            assert_eq!(path, "/get_transactions");
            let req: Value = serde_json::from_slice(body).unwrap();
            let want: Vec<String> = req["txs_hashes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_owned())
                .collect();
            asked.lock().push(want.clone());
            let fx: Value = serde_json::from_str(TXS_FULL).unwrap();
            let mut txs = Vec::new();
            let mut as_hex = Vec::new();
            let mut missed = Vec::new();
            for h in &want {
                match fx["txs"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|t| t["tx_hash"] == *h)
                {
                    Some(t) => {
                        let mut t = t.clone();
                        if tamper {
                            let mut s = t["as_hex"].as_str().unwrap().to_owned();
                            let last = s.len() - 1;
                            s.replace_range(last.., if &s[last..] == "0" { "1" } else { "0" });
                            t["as_hex"] = Value::String(s);
                        }
                        as_hex.push(t["as_hex"].clone());
                        txs.push(t);
                    }
                    None => missed.push(Value::String(h.clone())),
                }
            }
            let mut out = json!({"credits":0,"status":"OK","top_hash":"","txs":txs,"txs_as_hex":as_hex,"untrusted":true});
            if !missed.is_empty() {
                out["missed_tx"] = Value::Array(missed);
            }
            (200, out.to_string())
        })
    }

    const TXS_MEMPOOL: &str = include_str!("../../core/fixtures/mainnet/txs-mempool.json");

    /// The symptom seen live on 0.1.8: a mempool entry has no `block_height`,
    /// the answer failed to parse, every upstream tried was faulted and the
    /// client got a 502. Now it verifies by hash, faults nobody and is never
    /// cached.
    #[tokio::test]
    async fn mempool_transaction_verifies_by_hash_faults_nobody_and_is_not_cached() {
        let hits = Arc::new(AtomicUsize::new(0));
        let srv = mock_with(
            Arc::new(|path, _body| {
                assert_eq!(path, "/get_transactions");
                (200, TXS_MEMPOOL.to_owned())
            }),
            Arc::clone(&hits),
        )
        .await;
        let env = Env::new(pool_at(&[srv], 3_760_000));
        let fx: Value = serde_json::from_str(TXS_MEMPOOL).unwrap();
        let h = fx["txs"][0]["tx_hash"].as_str().unwrap().to_owned();
        for round in 1..=2 {
            let o = env
                .legacy("/get_transactions", json!({"txs_hashes": [h]}))
                .await;
            assert_eq!(
                o.status,
                200,
                "round {round}: {}",
                String::from_utf8_lossy(&o.body)
            );
            assert_eq!(header(&o, "Mnr-Verify"), Some("hash"));
            assert_eq!(header(&o, "Mnr-Cache"), Some("miss"));
            let v: Value = serde_json::from_slice(&o.body).unwrap();
            assert_eq!(v["txs"][0]["in_pool"], true);
            assert!(v["txs"][0].get("block_height").is_none());
            assert_eq!(v["txs"][0]["relayed"], true);
            assert_eq!(env.pool.status().faults.len(), 0);
            assert_eq!(
                hits.load(Ordering::SeqCst),
                round,
                "pool entries are never cached"
            );
        }
    }

    fn fixture_hashes() -> Vec<String> {
        let fx: Value = serde_json::from_str(TXS_FULL).unwrap();
        fx["txs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["tx_hash"].as_str().unwrap().to_owned())
            .collect()
    }

    #[tokio::test]
    async fn transactions_are_verified_cached_per_tx_and_batches_split() {
        let hits = Arc::new(AtomicUsize::new(0));
        let asked = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let srv = mock_with(tx_server(false, Arc::clone(&asked)), Arc::clone(&hits)).await;
        // Tip far above the fixture's height so its txs are below the line.
        let env = Env::new(pool_at(&[srv], 3_760_000));
        let h = fixture_hashes();
        let o = env
            .legacy("/get_transactions", json!({"txs_hashes": [h[0], h[1]]}))
            .await;
        assert_eq!(o.status, 200);
        assert_eq!(header(&o, "Mnr-Verify"), Some("hash"));
        assert_eq!(header(&o, "Mnr-Cache"), Some("miss"));
        assert_eq!(header(&o, "Mnr-Upstream"), Some("0"));
        // Same two again: served from cache, no upstream call.
        let o = env
            .legacy("/get_transactions", json!({"txs_hashes": [h[1], h[0]]}))
            .await;
        assert_eq!(header(&o, "Mnr-Cache"), Some("hit"));
        assert_eq!(header(&o, "Mnr-Verify"), Some("hash"));
        let v: Value = serde_json::from_slice(&o.body).unwrap();
        assert_eq!(v["txs"][0]["tx_hash"], h[1], "request order is kept");
        assert_eq!(v["txs"][1]["tx_hash"], h[0]);
        assert_eq!(v["txs_as_hex"].as_array().unwrap().len(), 2);
        assert_eq!(v["status"], "OK");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        // Two cached plus one new plus one unknown: the upstream is asked
        // only for the two it has not seen, the answer is reassembled.
        let unknown = "ab".repeat(32);
        let o = env
            .legacy(
                "/get_transactions",
                json!({"txs_hashes": [h[0], h[2], h[1], unknown]}),
            )
            .await;
        assert_eq!(header(&o, "Mnr-Cache"), Some("miss"));
        assert_eq!(header(&o, "Mnr-Verify"), Some("hash"));
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        assert_eq!(asked.lock()[1], vec![h[2].clone(), unknown.clone()]);
        let v: Value = serde_json::from_slice(&o.body).unwrap();
        let got: Vec<&str> = v["txs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["tx_hash"].as_str().unwrap())
            .collect();
        assert_eq!(got, vec![h[0].as_str(), h[2].as_str(), h[1].as_str()]);
        assert_eq!(v["missed_tx"], json!([unknown]));
        assert_eq!(v["txs_as_hex"].as_array().unwrap().len(), 3);
        // The request shape is part of the key: prune=true misses.
        let o = env
            .legacy(
                "/get_transactions",
                json!({"txs_hashes": [h[0]], "prune": true}),
            )
            .await;
        assert_eq!(header(&o, "Mnr-Cache"), Some("miss"));
    }

    #[tokio::test]
    async fn daemon_refusal_on_get_transactions_is_passed_through_not_faulted() {
        let hits = Arc::new(AtomicUsize::new(0));
        let refusing = mock_with(
            Arc::new(|_, _| (200, r#"{"status":"Failed","untrusted":true}"#.to_owned())),
            Arc::clone(&hits),
        )
        .await;
        let env = Env::new(pool_at(&[refusing], 3_760_000));
        let o = env
            .legacy(
                "/get_transactions",
                json!({"txs_hashes": ["ab".repeat(32)]}),
            )
            .await;
        assert_eq!(o.status, 200);
        assert_eq!(header(&o, "Mnr-Verify"), Some("none"));
        assert!(
            env.pool.status().faults.is_empty(),
            "declining is not lying"
        );
        let v: Value = serde_json::from_slice(&o.body).unwrap();
        assert_eq!(v["status"], "Failed");
    }

    #[tokio::test]
    async fn tampered_transaction_is_a_fault_and_young_txs_are_not_cached() {
        let hits = Arc::new(AtomicUsize::new(0));
        let asked = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let bad = mock_with(tx_server(true, Arc::clone(&asked)), Arc::clone(&hits)).await;
        let good = mock_with(tx_server(false, Arc::clone(&asked)), Arc::clone(&hits)).await;
        // Quorum tip right at the fixture height: verified, but within the
        // safety line, so never cached.
        let env = Env::new(pool_at(&[bad, good], 3_754_000));
        let h = fixture_hashes();
        let o = env
            .legacy("/get_transactions", json!({"txs_hashes": [h[0]]}))
            .await;
        assert_eq!(o.status, 200);
        assert_eq!(header(&o, "Mnr-Verify"), Some("hash"));
        assert_eq!(header(&o, "Mnr-Upstream"), Some("1"));
        let s = env.pool.status();
        assert_eq!(s.faults.len(), 1);
        assert_eq!(s.faults[0].method, "/get_transactions");
        let o = env
            .legacy("/get_transactions", json!({"txs_hashes": [h[0]]}))
            .await;
        assert_eq!(header(&o, "Mnr-Cache"), Some("miss"));
        assert_eq!(hits.load(Ordering::SeqCst), 4, "bad, good, bad, good");
    }

    #[tokio::test]
    async fn streams_are_sent_through_and_release_the_slot_when_dropped() {
        let hits = Arc::new(AtomicUsize::new(0));
        let big = mock_with(
            Arc::new(|_, _| (200, "x".repeat(300_000))),
            Arc::clone(&hits),
        )
        .await;
        let env = Env::new(pool_over(&[big]));
        let mut o = env
            .legacy("/get_blocks.bin", json!({"start_height": 0}))
            .await;
        assert_eq!(o.status, 200);
        assert_eq!(header(&o, "Mnr-Verify"), Some("none"));
        assert_eq!(header(&o, "Mnr-Cache"), Some("bypass"));
        assert_eq!(o.content_length, Some(300_000));
        assert_eq!(o.extra_wu, 0, "streams are charged as they flow");
        let mut s = o.stream.take().expect("a streamed body");
        let u = env.pool.upstream(0);
        let held = u.try_take_stream().expect("one of two slots is free");
        assert!(u.try_take_stream().is_none(), "the stream holds the other");
        let mut total = 0;
        while let Some(c) = s.next().await {
            total += c.unwrap().len();
        }
        assert_eq!(total, 300_000);
        drop(s);
        drop(held);
        let a = u.try_take_stream();
        let b = u.try_take_stream();
        assert!(a.is_some() && b.is_some(), "both slots free again");
    }

    #[tokio::test]
    async fn broadcast_reports_k_of_n_and_returns_the_accepting_body() {
        let hits = Arc::new(AtomicUsize::new(0));
        let ok = mock(200, r#"{"status":"OK"}"#, Arc::clone(&hits)).await;
        let rej = mock(
            200,
            r#"{"status":"Failed","reason":"Sanity check failed"}"#,
            Arc::clone(&hits),
        )
        .await;
        let down = mock(500, "", Arc::clone(&hits)).await;
        let env = Env::new(pool_over(&[rej, ok, down]));
        let o = env.legacy("/send_raw_transaction", json!({})).await;
        assert_eq!(o.status, 200);
        assert!(o.headers.contains(&("Mnr-Relayed", "1/3".to_owned())));
        assert!(o.headers.contains(&("Mnr-Upstream", "1".to_owned())));
        assert_eq!(&o.body[..], br#"{"status":"OK"}"#);
        assert_eq!(
            hits.load(Ordering::SeqCst),
            3,
            "every healthy upstream was tried"
        );
    }

    #[tokio::test]
    async fn broadcast_all_rejected_returns_the_first_rejection_verbatim() {
        let hits = Arc::new(AtomicUsize::new(0));
        let rej = mock(
            200,
            r#"{"status":"Failed","reason":"double spend"}"#,
            Arc::clone(&hits),
        )
        .await;
        let env = Env::new(pool_over(&[rej]));
        let o = env.legacy("/send_raw_transaction", json!({})).await;
        assert_eq!(o.status, 200);
        assert!(o.headers.contains(&("Mnr-Relayed", "0/1".to_owned())));
        assert!(std::str::from_utf8(&o.body)
            .unwrap()
            .contains("double spend"));
    }

    #[tokio::test]
    async fn read_falls_through_on_5xx_to_the_next_upstream() {
        let hits = Arc::new(AtomicUsize::new(0));
        let bad = mock(502, "gateway", Arc::clone(&hits)).await;
        let good = mock(200, r#"{"height":101,"status":"OK"}"#, Arc::clone(&hits)).await;
        let env = Env::new(pool_over(&[bad, good]));
        let o = env.legacy("/get_transaction_pool_stats", json!({})).await;
        assert_eq!(o.status, 200);
        assert!(o.headers.contains(&("Mnr-Upstream", "1".to_owned())));
        assert!(o.headers.contains(&("Mnr-Verify", "none".to_owned())));
        assert!(o.headers.contains(&("Mnr-Cache", "bypass".to_owned())));
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn read_respects_the_per_upstream_light_cap() {
        let hits = Arc::new(AtomicUsize::new(0));
        let only = mock(200, r#"{"height":101,"status":"OK"}"#, Arc::clone(&hits)).await;
        let env = Env::new(pool_over(&[only]));
        let t0 = std::time::Instant::now();
        let mut statuses = Vec::new();
        for _ in 0..7 {
            statuses.push(
                env.legacy("/get_transaction_pool_stats", json!({}))
                    .await
                    .status,
            );
        }
        // Default cap is 5 rps: the sixth and seventh calls queue for the
        // refill (200 ms per token) instead of being refused, and the
        // public node never sees more than the cap.
        assert_eq!(statuses, vec![200; 7]);
        assert_eq!(hits.load(Ordering::SeqCst), 7);
        assert!(
            t0.elapsed() >= Duration::from_millis(350),
            "{:?}",
            t0.elapsed()
        );
        // A wait longer than the queue allowance falls through: with the
        // bucket drained and no other upstream, that is a 503.
        let u = env.pool.upstream(0);
        while u.try_take_light() {}
        for _ in 0..2 {
            let o = env.legacy("/get_transaction_pool_stats", json!({})).await;
            assert_eq!(o.status, 200, "one token refills within 250 ms");
        }
        assert_eq!(hits.load(Ordering::SeqCst), 9);
    }

    #[test]
    fn daemon_acceptance_is_status_ok_only() {
        assert!(accepted_by_daemon(br#"{"status":"OK","untrusted":false}"#));
        assert!(!accepted_by_daemon(
            br#"{"status":"Failed","reason":"double spend","double_spend":true}"#
        ));
        assert!(!accepted_by_daemon(b"not json"));
        assert!(!accepted_by_daemon(b"{}"));
    }

    #[test]
    fn error_outcomes_are_annotated_unverified() {
        let o = Outcome::json_error(503, "no healthy upstream", Verify::None);
        assert_eq!(o.status, 503);
        assert!(o.headers.contains(&("Mnr-Verify", "none".to_owned())));
        let v: Value = serde_json::from_slice(&o.body).unwrap();
        assert_eq!(v["error"]["code"], -32603);
    }

    #[test]
    fn sensitive_methods_are_routed_to_the_owned_node_first() {
        for m in [
            "/get_transactions",
            "/gettransactions",
            "/get_outs.bin",
            "/get_o_indexes.bin",
            "get_output_distribution",
            "get_output_histogram",
            "/is_key_image_spent",
        ] {
            assert_eq!(work_for(m), Work::Sensitive, "{m}");
        }
        for m in [
            "get_block",
            "get_info",
            "/get_transaction_pool_stats",
            "/get_height",
        ] {
            assert_eq!(work_for(m), Work::Light, "{m}");
        }
    }

    #[test]
    fn cached_results_are_rewrapped_with_the_client_id() {
        let body = jsonrpc_body(&json!("abc"), br#"{"count":5,"status":"OK"}"#);
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["id"], "abc");
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["result"]["count"], 5);
        assert_eq!(
            params_key(Some(&json!({"b": 1, "a": 2}))),
            r#"{"a":2,"b":1}"#
        );
        assert_eq!(params_key(None), "");
    }
}
