//! Majority for consensus state (`docs/stage0-mvp-plan.md` §4; invariant 1):
//! `get_info`, `get_height`, `get_block_count`, `get_last_block_header`,
//! `get_fee_estimate`, `hard_fork_info`, `get_version` and their aliases.
//!
//! None of this is self-authenticating, so agreement stands in for proof:
//! on a cache miss the top three ranked on-tip upstreams with a light token
//! are asked at once, each answer is reduced to an *agreement key* (tip
//! height and hash, fork version, node version; the fee estimate is the
//! median instead), and the largest group of at least two agreeing answers
//! is served as `Mnr-Verify: majority` with `Mnr-Agreeing: k/n`. Anything
//! less is served from the best-ranked answer as `none`. Disagreement is
//! never a fault here: a node one block ahead or behind is honest, and the
//! prober's on-tip check handles persistent divergence.
//!
//! Answers live in the SWR cache tier with the policy's windows (fresh 1 s,
//! served stale while a background refresh runs for 5 s, foreground refresh
//! with stale-if-error for 15 s), so the fan-out costs at most about three
//! upstream calls per second per method however many clients ask. Aggregate
//! worst case is 7 methods × 3 = 21 rps spread over the ranked pool; cap
//! exhaustion on an upstream simply leaves it out of that round.
//!
//! `get_info` is normalised (node-specific fields zeroed) so the answer
//! describes the network, not a node.
//!
//! `get_last_block_header` is the one method here with a self-authenticating
//! form: when the relay's header chain already holds the reported height,
//! the header is checked against it and served as `chain`; a header the
//! chain contradicts is served as `none` (a reorg in flight, which the next
//! chain-sync round settles; not a fault, for the reason above).

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use mnr_core::verify::{self as rules, median, ReportedHeader, VerifyError};
use mnr_core::wire::{
    BlockHeader, GetFeeEstimateResult, GetInfoResult, JsonRpcRequest, JsonRpcResponse,
};
use serde_json::{json, Value};

use crate::cache::{Cache, Freshness, Status, SwrEntry};
use crate::chain::ChainStore;
use crate::dispatch::{self, Ctx, Outcome, Request};
use crate::upstream::{Pool, Work};
use crate::verify::{self, Verify};

/// Upstreams asked per refresh.
const ASK: usize = 3;
/// Ranked candidates tried to find `ASK` with a light token right now.
const CANDIDATES: usize = 6;
/// Answers that must agree for a majority.
const MIN_AGREE: usize = 2;

/// Serve a `Class::Swr` request from the SWR tier, refreshing as its
/// freshness requires.
pub async fn swr(ctx: Ctx, req: Request, timeout: Duration) -> Outcome {
    let method = verify::canonical(&req.method).to_owned();
    let key = Cache::swr_key(&method, &dispatch::params_key(req.params.as_ref()));
    let plan = FetchPlan {
        method: method.clone(),
        path: req.path,
        content_type: req.content_type,
        params: req.params.clone(),
        body: req.body.clone(),
        timeout,
    };
    let now = Instant::now();
    // Without a quorum tip (plan §3, degraded mode) cache writes are
    // suspended: what is already cached is still served for its windows,
    // but an answer from the owned node alone is never written back.
    let degraded = ctx.pool.degraded();
    let existing = ctx.cache.swr_get(&key).await;
    let (entry, status) = match existing.as_ref().map(|e| e.freshness_at(now)) {
        Some(Freshness::Fresh) => (existing.expect("checked"), Status::Hit),
        Some(Freshness::Revalidate) if degraded => (existing.expect("checked"), Status::Stale),
        Some(Freshness::Revalidate) => {
            if ctx.cache.begin_refresh(&key) {
                let (cache, pool, chain, key, plan) = (
                    Arc::clone(&ctx.cache),
                    Arc::clone(&ctx.pool),
                    Arc::clone(&ctx.chain),
                    key.clone(),
                    plan.clone(),
                );
                tokio::spawn(async move {
                    if let Ok(e) = fetch(&pool, &chain, &plan).await {
                        cache.swr_put(key.clone(), e).await;
                    }
                    cache.end_refresh(&key);
                });
            }
            (existing.expect("checked"), Status::Stale)
        }
        Some(Freshness::IfError) => {
            let stale = existing.expect("checked");
            if ctx.cache.begin_refresh(&key) {
                let fresh = fetch(&ctx.pool, &ctx.chain, &plan).await;
                ctx.cache.end_refresh(&key);
                match fresh {
                    Ok(e) if degraded => (Arc::new(e), Status::Bypass),
                    Ok(e) => {
                        ctx.cache.swr_put(key, e.clone()).await;
                        (Arc::new(e), Status::Miss)
                    }
                    Err(_) => (stale, Status::Stale),
                }
            } else {
                (stale, Status::Stale)
            }
        }
        Some(Freshness::Expired) | None if degraded => {
            match fetch(&ctx.pool, &ctx.chain, &plan).await {
                Ok(e) => (Arc::new(e), Status::Bypass),
                Err(why) => return Outcome::json_error(502, &why, Verify::None),
            }
        }
        Some(Freshness::Expired) | None => {
            let (pool, chain) = (Arc::clone(&ctx.pool), Arc::clone(&ctx.chain));
            match ctx
                .cache
                .swr_get_or_fetch(key, async move { fetch(&pool, &chain, &plan).await })
                .await
            {
                Ok(e) => (e, Status::Miss),
                Err(why) => return Outcome::json_error(502, &why, Verify::None),
            }
        }
    };
    let body = if req.path == "/json_rpc" {
        dispatch::jsonrpc_body(&req.id, &entry.body)
    } else {
        String::from_utf8_lossy(&entry.body).into_owned()
    };
    let mut headers = vec![
        ("Mnr-Verify", entry.verify.to_owned()),
        ("Mnr-Cache", status.label().to_owned()),
    ];
    if let Some((k, n)) = entry.agreeing {
        headers.push(("Mnr-Agreeing", format!("{k}/{n}")));
    }
    Outcome::json_ok(body, headers)
}

/// Everything a refresh needs, independent of the client that caused it.
#[derive(Clone)]
struct FetchPlan {
    method: String,
    path: &'static str,
    content_type: &'static str,
    params: Option<Value>,
    body: Bytes,
    timeout: Duration,
}

impl FetchPlan {
    /// The body sent upstream: our own JSON-RPC envelope with the client's
    /// params (id 0), or the client's legacy body verbatim.
    fn upstream_body(&self) -> Bytes {
        if self.path == "/json_rpc" {
            let req = JsonRpcRequest {
                jsonrpc: "2.0".into(),
                id: json!(0),
                method: self.method.clone(),
                params: self.params.clone(),
            };
            Bytes::from(serde_json::to_vec(&req).expect("serialisable"))
        } else {
            self.body.clone()
        }
    }
}

/// One upstream's answer, reduced to its `result` (JSON-RPC) or body.
struct Answer {
    upstream: usize,
    value: Value,
}

/// Ask up to three upstreams and reduce their answers to one entry.
async fn fetch(pool: &Pool, chain: &ChainStore, plan: &FetchPlan) -> Result<SwrEntry, String> {
    let ranked = pool.ranked(Work::Light);
    let mut chosen = Vec::with_capacity(ASK);
    for id in ranked.into_iter().take(CANDIDATES) {
        if chosen.len() == ASK {
            break;
        }
        if pool.upstream(id).try_take_light() {
            chosen.push(id);
        }
    }
    if chosen.is_empty() {
        return Err("no healthy upstream with capacity".into());
    }
    let body = plan.upstream_body();
    let asks = chosen.iter().map(|&id| {
        let body = body.clone();
        async move {
            let f = pool
                .upstream(id)
                .forward(plan.path, plan.content_type, body, plan.timeout)
                .await
                .ok()
                .filter(|f| f.status == 200)?;
            let value = if plan.path == "/json_rpc" {
                serde_json::from_slice::<JsonRpcResponse<Value>>(&f.body)
                    .ok()?
                    .result?
            } else {
                serde_json::from_slice::<Value>(&f.body).ok()?
            };
            Some(Answer {
                upstream: id,
                value,
            })
        }
    });
    let answers: Vec<Answer> = futures_util::future::join_all(asks)
        .await
        .into_iter()
        .flatten()
        .collect();
    if answers.is_empty() {
        return Err("no upstream answered".into());
    }
    let asked = chosen.len();
    let quorum = pool.quorum().map(|q| q.height);
    let Reduced {
        value,
        agreeing,
        members,
        served,
    } = reduce(&plan.method, answers, quorum);
    let value = finish(&plan.method, value);
    let majority = agreeing.is_some_and(|k| k >= MIN_AGREE);
    let against_chain = if plan.method == "get_last_block_header" {
        check_last_header(&value, chain)
    } else {
        ChainCheck::Unknown
    };
    let verify = match against_chain {
        ChainCheck::Confirmed => Verify::Chain,
        ChainCheck::Contradicted => Verify::None,
        ChainCheck::Unknown if majority => Verify::Majority,
        ChainCheck::Unknown => Verify::None,
    };
    // The public verified count records answers confirmed by each other
    // (the agreeing members) or by our chain (the served answer alone,
    // when nothing agreed).
    match (verify, majority) {
        (Verify::None, _) => {}
        (_, true) => {
            for id in &members {
                pool.record_verified(*id);
            }
        }
        (_, false) => pool.record_verified(served),
    }
    Ok(SwrEntry {
        body: Bytes::from(serde_json::to_vec(&value).map_err(|e| e.to_string())?),
        verify: verify.label(),
        agreeing: agreeing.filter(|k| *k >= MIN_AGREE).map(|k| (k, asked)),
        fetched: Instant::now(),
    })
}

/// What the header chain says about a `get_last_block_header` answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChainCheck {
    /// The chain holds the height and the header matches it.
    Confirmed,
    /// The chain holds the height and the header differs.
    Contradicted,
    /// The chain does not reach the height (or the answer is not a header).
    Unknown,
}

fn check_last_header(value: &Value, chain: &ChainStore) -> ChainCheck {
    let Some(h) = value.get("block_header") else {
        return ChainCheck::Unknown;
    };
    let Ok(header) = serde_json::from_value::<BlockHeader>(h.clone()) else {
        return ChainCheck::Unknown;
    };
    let Ok(reported) = ReportedHeader::try_from(&header) else {
        return ChainCheck::Unknown;
    };
    match rules::verify_header_by_height(reported.height, &reported, &chain.read()) {
        Ok(()) => ChainCheck::Confirmed,
        Err(VerifyError::UnknownHeight(_)) => ChainCheck::Unknown,
        Err(e) => {
            tracing::warn!(
                height = reported.height,
                error = %e,
                "get_last_block_header disagrees with the header chain; served as none"
            );
            ChainCheck::Contradicted
        }
    }
}

/// The agreement key of one answer: what two honest nodes on the same
/// chain must report identically. `None` excludes the answer from the vote
/// (unparseable, or a tip more than one block from the quorum).
fn agreement_key(method: &str, v: &Value, quorum: Option<u64>) -> Option<Value> {
    let near_quorum = |tip: u64| quorum.is_none_or(|q| tip.abs_diff(q) <= 1);
    match method {
        "get_info" | "/get_info" => {
            let tip = v.get("height")?.as_u64()?.checked_sub(1)?;
            let top = v.get("top_block_hash")?;
            near_quorum(tip).then(|| json!([tip, top]))
        }
        "/get_height" => {
            let tip = v.get("height")?.as_u64()?.checked_sub(1)?;
            near_quorum(tip).then(|| json!([tip, v.get("hash").cloned().unwrap_or(Value::Null)]))
        }
        "get_block_count" => {
            let tip = v.get("count")?.as_u64()?.checked_sub(1)?;
            near_quorum(tip).then(|| json!([tip]))
        }
        "get_last_block_header" => {
            let h = v.get("block_header")?;
            let tip = h.get("height")?.as_u64()?;
            let hash = h.get("hash")?;
            near_quorum(tip).then(|| json!([tip, hash]))
        }
        "hard_fork_info" => Some(json!([
            v.get("version")?,
            v.get("enabled")?,
            v.get("state")?,
            v.get("earliest_height")?
        ])),
        "get_version" => Some(json!([v.get("version")?])),
        // The fee estimate is composed, not voted on.
        "get_fee_estimate" => Some(json!(["fee"])),
        _ => None,
    }
}

/// What [`reduce`] settled on.
struct Reduced {
    value: Value,
    /// How many answers agreed, when a vote took place.
    agreeing: Option<usize>,
    /// The upstreams whose answers agreed (empty without a majority).
    members: Vec<usize>,
    /// The upstream whose answer is served.
    served: usize,
}

/// The value to serve: the largest group of identical keys, or the
/// best-ranked answer (`answers` are in rank order) when nothing agrees.
fn reduce(method: &str, answers: Vec<Answer>, quorum: Option<u64>) -> Reduced {
    if method == "get_fee_estimate" {
        return fee_median(answers);
    }
    let keyed: Vec<(Option<Value>, Answer)> = answers
        .into_iter()
        .map(|a| (agreement_key(method, &a.value, quorum), a))
        .collect();
    let mut best: Option<(usize, usize)> = None; // (count, index of first member)
    for (i, (k, _)) in keyed.iter().enumerate() {
        let Some(k) = k else { continue };
        let count = keyed
            .iter()
            .filter(|(other, _)| other.as_ref() == Some(k))
            .count();
        if best.is_none_or(|(c, _)| count > c) {
            best = Some((count, i));
        }
    }
    match best {
        Some((count, i)) if count >= MIN_AGREE => {
            let key = keyed[i].0.clone();
            let members = keyed
                .iter()
                .filter(|(k, _)| *k == key)
                .map(|(_, a)| a.upstream)
                .collect();
            let answer = keyed.into_iter().nth(i).expect("index from iteration").1;
            Reduced {
                value: answer.value,
                agreeing: Some(count),
                members,
                served: answer.upstream,
            }
        }
        _ => {
            // Rank order is preserved from `chosen`: the first answer is
            // the best-ranked upstream that answered.
            let answer = keyed.into_iter().next().expect("non-empty").1;
            Reduced {
                value: answer.value,
                agreeing: None,
                members: Vec::new(),
                served: answer.upstream,
            }
        }
    }
}

/// `fee` = median of the estimates; `fees[i]` element-wise median when the
/// vectors align; everything else from the first answer. Every parseable
/// answer takes part, so the agreeing count is the parseable count.
fn fee_median(answers: Vec<Answer>) -> Reduced {
    let parsed: Vec<(GetFeeEstimateResult, &Answer)> = answers
        .iter()
        .filter_map(|a| serde_json::from_value(a.value.clone()).ok().map(|p| (p, a)))
        .collect();
    let n = parsed.len();
    let members: Vec<usize> = parsed.iter().map(|(_, a)| a.upstream).collect();
    let Some((first, first_answer)) = parsed.first() else {
        let first = answers.into_iter().next();
        return Reduced {
            served: first.as_ref().map_or(0, |a| a.upstream),
            value: first.map_or(Value::Null, |a| a.value),
            agreeing: None,
            members: Vec::new(),
        };
    };
    let mut out = first.clone();
    out.fee = median(&parsed.iter().map(|(p, _)| p.fee).collect::<Vec<_>>()).unwrap_or(first.fee);
    if let Some(fees) = &first.fees {
        let aligned = parsed
            .iter()
            .all(|(p, _)| p.fees.as_ref().is_some_and(|f| f.len() == fees.len()));
        if aligned {
            out.fees = Some(
                (0..fees.len())
                    .map(|i| {
                        median(
                            &parsed
                                .iter()
                                .map(|(p, _)| p.fees.as_ref().expect("aligned")[i])
                                .collect::<Vec<_>>(),
                        )
                        .expect("non-empty")
                    })
                    .collect(),
            );
        }
    }
    let value = serde_json::to_value(&out).unwrap_or_else(|_| first_answer.value.clone());
    Reduced {
        value,
        agreeing: Some(n),
        members,
        served: first_answer.upstream,
    }
}

/// Last touches before an answer is cached: `get_info` node-specific
/// fields are zeroed so the answer describes the network, not a node.
fn finish(method: &str, value: Value) -> Value {
    match method {
        "get_info" | "/get_info" => match serde_json::from_value::<GetInfoResult>(value.clone()) {
            Ok(mut info) => {
                info.normalise_get_info();
                serde_json::to_value(&info).unwrap_or(value)
            }
            Err(_) => value,
        },
        _ => value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Tier;
    use crate::chain::ChainStore;
    use crate::config::Config;
    use crate::upstream::Health;
    use axum::body::Bytes as AxBytes;
    use axum::extract::Path;
    use axum::routing::post;
    use axum::Router;
    use mnr_core::headerchain::{Entry, HeaderChain};
    use mnr_core::wire::decode_hex32;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const GET_INFO: &str = include_str!("../../core/fixtures/mainnet/get_info.json");
    const FEE: &str = include_str!("../../core/fixtures/mainnet/get_fee_estimate.json");
    const LAST_HEADER: &str =
        include_str!("../../core/fixtures/mainnet/get_last_block_header.json");

    type Handler = Arc<dyn Fn(&str, &[u8]) -> (u16, String) + Send + Sync>;

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

    /// A node answering `get_info`/`/get_info` at `height` blocks with
    /// `top` as the top hash, plus fixed fee/header/version answers.
    fn node(height: u64, top: &'static str, fee: u64) -> Handler {
        Arc::new(move |path, body| {
            let (method, id) = if path == "/json_rpc" {
                let r: JsonRpcRequest = serde_json::from_slice(body).unwrap();
                (r.method, r.id)
            } else {
                (path.to_owned(), Value::Null)
            };
            let result = match method.as_str() {
                "get_info" | "/get_info" => {
                    let mut v: Value = serde_json::from_str(GET_INFO).unwrap();
                    let mut r = v["result"].take();
                    r["height"] = json!(height);
                    r["top_block_hash"] = json!(top);
                    r["incoming_connections_count"] = json!(42);
                    r
                }
                "/get_height" => {
                    json!({"hash": top, "height": height, "status": "OK", "untrusted": true})
                }
                "get_block_count" => json!({"count": height, "status": "OK", "untrusted": true}),
                "get_fee_estimate" => {
                    let mut v: Value = serde_json::from_str(FEE).unwrap();
                    let mut r = v["result"].take();
                    r["fee"] = json!(fee);
                    r["fees"] = json!([fee, fee * 2, fee * 4, fee * 8]);
                    r
                }
                "get_last_block_header" => {
                    let mut v: Value = serde_json::from_str(LAST_HEADER).unwrap();
                    let mut r = v["result"].take();
                    r["block_header"]["height"] = json!(height - 1);
                    r["block_header"]["hash"] = json!(top);
                    r
                }
                "get_version" => {
                    json!({"release": true, "status": "OK", "untrusted": true, "version": 196614})
                }
                "hard_fork_info" => {
                    json!({"earliest_height": 2688888, "enabled": true, "state": 0, "status": "OK", "threshold": 0, "untrusted": true, "version": 16, "votes": 10080, "voting": 16, "window": 10080})
                }
                other => panic!("unexpected method {other}"),
            };
            if path == "/json_rpc" {
                (
                    200,
                    json!({"id": id, "jsonrpc": "2.0", "result": result}).to_string(),
                )
            } else {
                (200, result.to_string())
            }
        })
    }

    struct Env {
        ctx: Ctx,
        hits: Arc<AtomicUsize>,
    }

    impl Env {
        async fn new(nodes: Vec<Handler>) -> Self {
            Self::with_kinds(nodes, "public").await
        }

        async fn with_kinds(nodes: Vec<Handler>, kind: &str) -> Self {
            let hits = Arc::new(AtomicUsize::new(0));
            let mut toml = String::from("[probe]\nmin_agree = 1\n");
            let mut health = Vec::new();
            for (i, h) in nodes.into_iter().enumerate() {
                let addr = mock_with(h, Arc::clone(&hits)).await;
                toml.push_str(&format!(
                    "[[upstreams]]\nname = \"m{i}\"\nurl = \"http://{addr}\"\nkind = \"{kind}\"\ntransport = \"http\"\ncaps = {{ rps_light = 100, max_streams = 2, mbps = 10 }}\n"
                ));
                let mut hh = Health::healthy_for_test(1001, [7; 32]);
                hh.rtt_ema_ms = Some(10.0 + i as f64);
                health.push(hh);
            }
            let pool = Pool::from_config(&Config::parse(&toml).unwrap()).unwrap();
            pool.set_for_test(health, Some((1000, [7; 32])));
            Self {
                ctx: Ctx {
                    pool: Arc::new(pool),
                    chain: Arc::new(ChainStore::open(None).unwrap()),
                    cache: Arc::new(Cache::new(1 << 20)),
                },
                hits,
            }
        }

        async fn call(&self, method: &str) -> Outcome {
            let policy = mnr_core::policy::lookup(method).unwrap();
            let (path, body, id): (&'static str, Bytes, Value) = if method.starts_with('/') {
                (
                    mnr_core::policy::lookup(method).unwrap().method,
                    Bytes::from_static(b"{}"),
                    Value::Null,
                )
            } else {
                let req = json!({"jsonrpc":"2.0","id":"c1","method":method});
                ("/json_rpc", Bytes::from(req.to_string()), json!("c1"))
            };
            dispatch::dispatch(
                self.ctx.clone(),
                policy,
                Request {
                    path,
                    method: method.into(),
                    params: None,
                    id,
                    content_type: "application/json",
                    body,
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

    #[tokio::test]
    async fn two_of_three_agree_is_a_majority_and_is_cached() {
        let env = Env::new(vec![
            node(1001, "aa", 100),
            node(1001, "aa", 300),
            node(1000, "bb", 200), // one block behind: honest, outvoted
        ])
        .await;
        let o = env.call("get_info").await;
        assert_eq!(o.status, 200);
        assert_eq!(header(&o, "Mnr-Verify"), Some("majority"));
        assert_eq!(header(&o, "Mnr-Agreeing"), Some("2/3"));
        assert_eq!(header(&o, "Mnr-Cache"), Some("miss"));
        let v: Value = serde_json::from_slice(&o.body).unwrap();
        assert_eq!(v["id"], "c1", "client id re-attached");
        assert_eq!(v["result"]["height"], 1001);
        assert_eq!(v["result"]["top_block_hash"], "aa");
        assert_eq!(v["result"]["incoming_connections_count"], 0, "normalised");
        assert_eq!(env.hits.load(Ordering::SeqCst), 3);
        let s = env.ctx.pool.status();
        assert_eq!(
            (
                s.upstreams[0].verified,
                s.upstreams[1].verified,
                s.upstreams[2].verified
            ),
            (1, 1, 0),
            "agreeing upstreams count as verified"
        );
        // Fresh: served from cache, nobody asked again.
        let o = env.call("get_info").await;
        assert_eq!(header(&o, "Mnr-Cache"), Some("hit"));
        assert_eq!(header(&o, "Mnr-Verify"), Some("majority"));
        assert_eq!(env.hits.load(Ordering::SeqCst), 3);
        // The legacy twin has its own entry and no JSON-RPC envelope.
        let o = env.call("/get_info").await;
        let v: Value = serde_json::from_slice(&o.body).unwrap();
        assert_eq!(v["height"], 1001);
        assert!(v.get("result").is_none());
        assert_eq!(header(&o, "Mnr-Verify"), Some("majority"));
        assert!(
            env.ctx.pool.status().faults.is_empty(),
            "disagreement is never a fault"
        );
    }

    #[tokio::test]
    async fn no_agreement_is_served_unverified_from_the_best_upstream() {
        let env = Env::new(vec![
            node(1001, "aa", 1),
            node(1001, "bb", 1),
            node(1001, "cc", 1),
        ])
        .await;
        let o = env.call("/get_height").await;
        assert_eq!(header(&o, "Mnr-Verify"), Some("none"));
        assert_eq!(header(&o, "Mnr-Agreeing"), None);
        let v: Value = serde_json::from_slice(&o.body).unwrap();
        assert_eq!(v["hash"], "aa", "best-ranked answer");
        assert!(env
            .ctx
            .pool
            .status()
            .upstreams
            .iter()
            .all(|u| u.verified == 0));
        // Rank, not pool index, decides the fallback: make m2 the fastest.
        let env = Env::new(vec![
            node(1001, "aa", 1),
            node(1001, "bb", 1),
            node(1001, "cc", 1),
        ])
        .await;
        let mut health: Vec<Health> = (0..3)
            .map(|_| Health::healthy_for_test(1001, [7; 32]))
            .collect();
        health[0].rtt_ema_ms = Some(50.0);
        health[1].rtt_ema_ms = Some(40.0);
        health[2].rtt_ema_ms = Some(1.0);
        env.ctx.pool.set_for_test(health, Some((1000, [7; 32])));
        let o = env.call("/get_height").await;
        let v: Value = serde_json::from_slice(&o.body).unwrap();
        assert_eq!(v["hash"], "cc");
        // A lone upstream cannot form a majority either.
        let env = Env::new(vec![node(1001, "aa", 1)]).await;
        let o = env.call("get_block_count").await;
        assert_eq!(header(&o, "Mnr-Verify"), Some("none"));
        let v: Value = serde_json::from_slice(&o.body).unwrap();
        assert_eq!(v["result"]["count"], 1001);
    }

    #[tokio::test]
    async fn far_from_the_quorum_tip_does_not_vote() {
        // Two nodes agree at a height 50 blocks past the quorum tip (1000):
        // they are excluded from the vote, so nothing reaches a majority.
        let env = Env::new(vec![
            node(1051, "zz", 1),
            node(1051, "zz", 1),
            node(1001, "aa", 1),
        ])
        .await;
        let o = env.call("get_last_block_header").await;
        assert_eq!(header(&o, "Mnr-Verify"), Some("none"));
    }

    /// The fixture's last header, at test height 1000 with hash `TOP`,
    /// linked to a synthetic chain below it.
    const TOP: &str = "401f00ede03d0ad64f2dc2f8dd79807874cfcb40ea98e2d395e30961bd2b74f8";

    fn chain_through_1000(top_hash: [u8; 32]) -> HeaderChain {
        let fx: Value = serde_json::from_str(LAST_HEADER).unwrap();
        let h = &fx["result"]["block_header"];
        let prev = decode_hex32(h["prev_hash"].as_str().unwrap()).unwrap();
        let timestamp = h["timestamp"].as_u64().unwrap();
        let mut c = HeaderChain::new();
        let mut last = [0u8; 32];
        for i in 0..1000u64 {
            let hash = if i == 999 { prev } else { [i as u8; 32] };
            c.append(Entry {
                height: i,
                hash,
                prev_hash: last,
                timestamp: i,
            })
            .unwrap();
            last = hash;
        }
        c.append(Entry {
            height: 1000,
            hash: top_hash,
            prev_hash: prev,
            timestamp,
        })
        .unwrap();
        c
    }

    #[tokio::test]
    async fn last_header_is_checked_against_the_chain_when_it_reaches_the_height() {
        let nodes = || vec![node(1001, TOP, 1), node(1001, TOP, 1), node(1001, TOP, 1)];
        let verified = |env: &Env| {
            env.ctx
                .pool
                .status()
                .upstreams
                .iter()
                .map(|u| u.verified)
                .collect::<Vec<_>>()
        };
        // Chain stops at 999: majority only.
        let env = Env::new(nodes()).await;
        let mut short = chain_through_1000(decode_hex32(TOP).unwrap());
        short.truncate(999);
        env.ctx.chain.set_for_test(short);
        let o = env.call("get_last_block_header").await;
        assert_eq!(header(&o, "Mnr-Verify"), Some("majority"));
        assert_eq!(header(&o, "Mnr-Agreeing"), Some("3/3"));
        assert_eq!(verified(&env), vec![1, 1, 1]);
        // Chain holds 1000 with the same header: chain, and cached as such.
        let env = Env::new(nodes()).await;
        env.ctx
            .chain
            .set_for_test(chain_through_1000(decode_hex32(TOP).unwrap()));
        let o = env.call("get_last_block_header").await;
        assert_eq!(header(&o, "Mnr-Verify"), Some("chain"));
        assert_eq!(header(&o, "Mnr-Agreeing"), Some("3/3"));
        assert_eq!(verified(&env), vec![1, 1, 1]);
        let o = env.call("get_last_block_header").await;
        assert_eq!(header(&o, "Mnr-Verify"), Some("chain"));
        assert_eq!(header(&o, "Mnr-Cache"), Some("hit"));
        // Chain holds 1000 with another hash: contradicted, served as none,
        // nobody faulted, nobody credited.
        let env = Env::new(nodes()).await;
        env.ctx.chain.set_for_test(chain_through_1000([0xee; 32]));
        let o = env.call("get_last_block_header").await;
        assert_eq!(header(&o, "Mnr-Verify"), Some("none"));
        assert_eq!(header(&o, "Mnr-Agreeing"), Some("3/3"));
        assert_eq!(verified(&env), vec![0, 0, 0]);
        assert!(env.ctx.pool.status().faults.is_empty());
    }

    #[tokio::test]
    async fn a_single_chain_confirmed_last_header_is_chain_and_credited() {
        let env = Env::new(vec![node(1001, TOP, 1)]).await;
        env.ctx
            .chain
            .set_for_test(chain_through_1000(decode_hex32(TOP).unwrap()));
        let o = env.call("get_last_block_header").await;
        assert_eq!(header(&o, "Mnr-Verify"), Some("chain"));
        assert_eq!(header(&o, "Mnr-Agreeing"), None);
        assert_eq!(env.ctx.pool.status().upstreams[0].verified, 1);
    }

    #[tokio::test]
    async fn degraded_mode_serves_the_owned_node_and_suspends_cache_writes() {
        let env = Env::with_kinds(vec![node(1001, "aa", 1)], "owned").await;
        // No quorum: degraded. The owned node is healthy and serves alone.
        let mut h = Health::healthy_for_test(1001, [7; 32]);
        h.rtt_ema_ms = Some(10.0);
        env.ctx.pool.set_for_test(vec![h], None);
        for _ in 0..2 {
            let o = env.call("get_info").await;
            assert_eq!(o.status, 200);
            assert_eq!(header(&o, "Mnr-Verify"), Some("none"));
            assert_eq!(header(&o, "Mnr-Cache"), Some("bypass"));
        }
        assert_eq!(env.hits.load(Ordering::SeqCst), 2, "nothing was cached");
        let [_, _, (_, swr_entries, _), _] = env.ctx.cache.stats().await;
        assert_eq!(swr_entries, 0);
        // Quorum back: the next answer is written and the one after is a hit.
        let mut h = Health::healthy_for_test(1001, [7; 32]);
        h.rtt_ema_ms = Some(10.0);
        env.ctx.pool.set_for_test(vec![h], Some((1000, [7; 32])));
        let o = env.call("get_info").await;
        assert_eq!(header(&o, "Mnr-Cache"), Some("miss"));
        let o = env.call("get_info").await;
        assert_eq!(header(&o, "Mnr-Cache"), Some("hit"));
        assert_eq!(env.hits.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn fee_estimate_is_the_median() {
        let env = Env::new(vec![
            node(1001, "aa", 100),
            node(1001, "aa", 900),
            node(1001, "aa", 300),
        ])
        .await;
        let o = env.call("get_fee_estimate").await;
        assert_eq!(header(&o, "Mnr-Verify"), Some("majority"));
        assert_eq!(header(&o, "Mnr-Agreeing"), Some("3/3"));
        let v: Value = serde_json::from_slice(&o.body).unwrap();
        assert_eq!(v["result"]["fee"], 300);
        assert_eq!(v["result"]["fees"], json!([300, 600, 1200, 2400]));
        assert_eq!(v["result"]["quantization_mask"], 10000);
    }

    #[tokio::test]
    async fn version_and_fork_info_agree_by_value() {
        let env = Env::new(vec![node(1001, "aa", 1), node(1001, "aa", 1)]).await;
        for m in ["get_version", "hard_fork_info"] {
            let o = env.call(m).await;
            assert_eq!(header(&o, "Mnr-Verify"), Some("majority"), "{m}");
            assert_eq!(header(&o, "Mnr-Agreeing"), Some("2/2"), "{m}");
        }
    }

    #[tokio::test]
    async fn stale_entries_are_served_and_refreshed_in_the_background() {
        let env = Env::new(vec![
            node(1001, "aa", 1),
            node(1001, "aa", 1),
            node(1001, "aa", 1),
        ])
        .await;
        let key = Cache::swr_key("get_block_count", "");
        env.ctx
            .cache
            .swr_put(
                key.clone(),
                SwrEntry {
                    body: Bytes::from_static(br#"{"count":5,"status":"OK","untrusted":true}"#),
                    verify: "majority",
                    agreeing: Some((3, 3)),
                    fetched: Instant::now() - Duration::from_secs(3),
                },
            )
            .await;
        let o = env.call("get_block_count").await;
        assert_eq!(header(&o, "Mnr-Cache"), Some("stale"));
        let v: Value = serde_json::from_slice(&o.body).unwrap();
        assert_eq!(
            v["result"]["count"], 5,
            "the stale answer is what is served"
        );
        // The background refresh lands shortly after.
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            if env.hits.load(Ordering::SeqCst) >= 3 {
                break;
            }
        }
        let e = env.ctx.cache.swr_get(&key).await.unwrap();
        assert_eq!(e.freshness_at(Instant::now()), Freshness::Fresh);
        let o = env.call("get_block_count").await;
        assert_eq!(header(&o, "Mnr-Cache"), Some("hit"));
        let v: Value = serde_json::from_slice(&o.body).unwrap();
        assert_eq!(v["result"]["count"], 1001);
    }

    #[tokio::test]
    async fn stale_if_error_serves_the_old_answer_when_upstreams_fail() {
        let hits = Arc::new(AtomicUsize::new(0));
        let dead = mock_with(Arc::new(|_, _| (500, String::new())), Arc::clone(&hits)).await;
        let mut toml = String::from("[probe]\nmin_agree = 1\n");
        toml.push_str(&format!(
            "[[upstreams]]\nname = \"d\"\nurl = \"http://{dead}\"\nkind = \"public\"\ntransport = \"http\"\n"
        ));
        let pool = Pool::from_config(&Config::parse(&toml).unwrap()).unwrap();
        pool.set_for_test(
            vec![Health::healthy_for_test(1001, [7; 32])],
            Some((1000, [7; 32])),
        );
        let ctx = Ctx {
            pool: Arc::new(pool),
            chain: Arc::new(ChainStore::open(None).unwrap()),
            cache: Arc::new(Cache::new(1 << 20)),
        };
        let key = Cache::swr_key("get_version", "");
        ctx.cache
            .swr_put(
                key,
                SwrEntry {
                    body: Bytes::from_static(br#"{"version":1}"#),
                    verify: "majority",
                    agreeing: Some((2, 3)),
                    fetched: Instant::now() - Duration::from_secs(10),
                },
            )
            .await;
        let env = Env {
            ctx,
            hits: Arc::clone(&hits),
        };
        let o = env.call("get_version").await;
        assert_eq!(o.status, 200);
        assert_eq!(header(&o, "Mnr-Cache"), Some("stale"));
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "a foreground refresh was tried"
        );
        // With nothing cached, the failure is the client's answer.
        let o = env.call("get_info").await;
        assert_eq!(o.status, 502);
        assert_eq!(header(&o, "Mnr-Verify"), Some("none"));
    }

    #[test]
    fn agreement_keys_follow_the_review_resolutions() {
        let info = json!({"height": 1001, "top_block_hash": "aa"});
        assert_eq!(
            agreement_key("get_info", &info, Some(1000)),
            Some(json!([1000, "aa"]))
        );
        assert_eq!(
            agreement_key("get_info", &info, Some(1002)),
            None,
            "two blocks off"
        );
        assert_eq!(
            agreement_key("get_info", &info, None),
            Some(json!([1000, "aa"])),
            "degraded: no bound"
        );
        assert_eq!(
            agreement_key("get_block_count", &json!({"count": 1001}), Some(1000)),
            Some(json!([1000]))
        );
        assert_eq!(
            agreement_key("/get_height", &json!({"height": 1001}), Some(1000)),
            Some(json!([1000, null]))
        );
        assert_eq!(agreement_key("get_info", &json!({"height": 0}), None), None);
        assert_eq!(agreement_key("get_txpool_backlog", &json!({}), None), None);
    }
}
