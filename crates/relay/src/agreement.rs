//! Per-tier agreement for the outputs family (`docs/stage0-mvp-plan.md`
//! §4 and §10 item 3): `/get_outs(.bin)`, `/get_o_indexes.bin`,
//! `get_output_distribution(.bin)`, `get_output_histogram`.
//!
//! Ring-construction data is not self-authenticating from one answer, so
//! the policy asks for agreement between upstreams instead:
//! `Verification::Agreement { free: 1, pro: 2 }`. A Free token gets one
//! upstream (owned preferred by the ranking) and `Mnr-Verify: none`. A Pro
//! token gets two distinct on-tip upstreams asked in parallel; their answers
//! are parsed (epee for `.bin`, JSON otherwise), volatile keys are dropped,
//! and the trees are compared. Identical → `Mnr-Verify: agreement`,
//! `Mnr-Agreeing: 2/2`. Different → a third upstream breaks the tie: the
//! answers that match it are served, the outlier is a fault. No majority,
//! or no third upstream → HTTP 502 `Mnr-Verify: failed`, because a wrong
//! ring is worse than no ring. An answer this relay cannot parse is served
//! as `none`, never as agreement.
//!
//! Caching: only `get_output_distribution` (JSON-RPC) with
//! `to_height` at or below the safety line, and only when agreed. The rest
//! of the family needs the output distribution to map indices to heights
//! before it could be cached safely; that is deferred.

use std::time::Duration;

use bytes::Bytes;
use mnr_core::epee;
use mnr_core::policy::{Policy, Verification};
use mnr_core::wire::JsonRpcResponse;
use serde_json::Value;

use crate::auth::Tier;
use crate::cache::{Cache, Cached, Status};
use crate::dispatch::{self, Ctx, Outcome, Request};
use crate::upstream::{Forwarded, Pool, Work};
use crate::verify::Verify;

/// Ranked candidates tried to find upstreams with a light token.
const CANDIDATES: usize = 6;

/// Serve one outputs-family request under its tier's agreement rule.
pub async fn agreement(
    ctx: Ctx,
    policy: &'static Policy,
    req: Request,
    timeout: Duration,
) -> Outcome {
    let need = match policy.verification {
        Verification::Agreement { free, pro } => match req.tier {
            Tier::Pro => pro,
            Tier::Free => free,
        },
        _ => 1,
    } as usize;
    if need <= 1 {
        // Free: one upstream, our own node first (plan §10 item 3, and the
        // request says which outputs a wallet is looking at).
        return dispatch::read(
            &ctx.pool,
            req.path,
            req.content_type,
            req.body,
            timeout,
            Work::Sensitive,
        )
        .await;
    }

    let cache_key = distribution_key(&ctx, &req);
    if let Some(key) = &cache_key {
        if let Some(c) = ctx.cache.immutable_get(key).await {
            return Outcome::json_ok(
                dispatch::jsonrpc_body(&req.id, &c.body),
                vec![
                    ("Mnr-Verify", c.verify.to_owned()),
                    ("Mnr-Cache", Status::Hit.label().to_owned()),
                ],
            );
        }
    }

    // Pro: our node plus the best public node, compared.
    let ranked = ctx.pool.ranked(Work::Sensitive);
    let mut chosen = Vec::with_capacity(need);
    let mut spares = Vec::new();
    for id in ranked.into_iter().take(CANDIDATES) {
        if chosen.len() == need {
            spares.push(id);
        } else if ctx.pool.upstream(id).try_take_light() {
            chosen.push(id);
        }
    }
    if chosen.is_empty() {
        return Outcome::json_error(503, "no healthy upstream", Verify::None);
    }
    let answers = ask(&ctx.pool, &chosen, &req, timeout).await;
    let Some(first) = answers.first() else {
        return Outcome::json_error(502, "no upstream answered", Verify::None);
    };
    if answers.len() < need {
        // Not enough capacity for the tier's rule: served, but not agreed.
        return annotated(&answers[0], Verify::None, None);
    }
    let trees: Vec<Option<Comparable>> = answers
        .iter()
        .map(|(_, f)| comparable(req.path, &f.body))
        .collect();
    if trees.iter().any(Option::is_none) {
        return annotated(first, Verify::None, None);
    }
    let all_agree = trees.iter().all(|t| t == &trees[0]);
    if all_agree {
        for (id, _) in &answers {
            ctx.pool.record_verified(*id);
        }
        let o = annotated(first, Verify::Agreement, Some((need, need)));
        cache_if_distribution(&ctx, cache_key, &first.1).await;
        return o;
    }

    // Tie-break with the next ranked upstream that has a token right now.
    let spare = spares
        .into_iter()
        .find(|&id| ctx.pool.upstream(id).try_take_light());
    let Some(spare) = spare else {
        return Outcome::json_error(502, "upstreams disagree", Verify::Failed);
    };
    let Some(third) = ask(&ctx.pool, &[spare], &req, timeout)
        .await
        .into_iter()
        .next()
    else {
        // The tie-breaker did not answer: nobody is proven wrong, and the
        // client is told the relay could not decide, not that nodes lied.
        return Outcome::json_error(
            502,
            "upstreams disagree and the tie-breaker is unavailable",
            Verify::None,
        );
    };
    let Some(tie) = comparable(req.path, &third.1.body) else {
        return Outcome::json_error(502, "upstreams disagree", Verify::Failed);
    };
    let matching: Vec<usize> = trees
        .iter()
        .enumerate()
        .filter(|(_, t)| t.as_ref() == Some(&tie))
        .map(|(i, _)| i)
        .collect();
    if matching.is_empty() {
        return Outcome::json_error(502, "upstreams disagree", Verify::Failed);
    }
    let asked = need + 1;
    let agreeing = matching.len() + 1;
    ctx.pool.record_verified(third.0);
    for (i, (id, _)) in answers.iter().enumerate() {
        if matching.contains(&i) {
            ctx.pool.record_verified(*id);
            continue;
        }
        {
            ctx.pool.record_fault(
                *id,
                policy.method,
                format!("outputs answer disagrees with {agreeing} of {asked} upstreams"),
            );
        }
    }
    let winner = &answers[matching[0]];
    let o = annotated(winner, Verify::Agreement, Some((agreeing, asked)));
    cache_if_distribution(&ctx, cache_key, &winner.1).await;
    o
}

/// Forward the request to each of `ids` in parallel; failed answers are
/// dropped.
async fn ask(
    pool: &Pool,
    ids: &[usize],
    req: &Request,
    timeout: Duration,
) -> Vec<(usize, Forwarded)> {
    let sends = ids.iter().map(|&id| {
        let body = req.body.clone();
        async move {
            let f = pool
                .upstream(id)
                .forward(req.path, req.content_type, body, timeout)
                .await
                .ok()
                .filter(|f| f.status == 200)?;
            Some((id, f))
        }
    });
    futures_util::future::join_all(sends)
        .await
        .into_iter()
        .flatten()
        .collect()
}

fn annotated(
    answer: &(usize, Forwarded),
    verify: Verify,
    agreeing: Option<(usize, usize)>,
) -> Outcome {
    let (id, f) = answer;
    let mut headers = vec![
        ("Mnr-Verify", verify.label().to_owned()),
        ("Mnr-Cache", Status::Bypass.label().to_owned()),
        ("Mnr-Upstream", id.to_string()),
    ];
    if let Some((k, n)) = agreeing {
        headers.push(("Mnr-Agreeing", format!("{k}/{n}")));
    }
    Outcome {
        status: f.status,
        content_type: f
            .content_type
            .clone()
            .unwrap_or_else(|| "application/json".to_owned()),
        body: f.body.clone(),
        stream: None,
        content_length: None,
        headers,
        extra_wu: 0,
    }
}

/// An answer reduced to what two honest upstreams must agree on.
#[derive(Debug, PartialEq, Eq)]
enum Comparable {
    Epee(epee::Section),
    Json(Value),
}

fn comparable(path: &str, body: &[u8]) -> Option<Comparable> {
    if path.ends_with(".bin") {
        let root = epee::parse(body).ok()?;
        return Some(Comparable::Epee(epee::canonical(
            &root,
            epee::VOLATILE_KEYS,
        )));
    }
    let mut v = if path == "/json_rpc" {
        serde_json::from_slice::<JsonRpcResponse<Value>>(body)
            .ok()?
            .result?
    } else {
        serde_json::from_slice::<Value>(body).ok()?
    };
    if let Some(obj) = v.as_object_mut() {
        for k in epee::VOLATILE_KEYS {
            obj.remove(*k);
        }
    }
    Some(Comparable::Json(v))
}

/// The cache key for a `get_output_distribution` request whose range ends
/// at or below the safety line; `None` for everything else.
fn distribution_key(ctx: &Ctx, req: &Request) -> Option<String> {
    if req.path != "/json_rpc" || req.method != "get_output_distribution" {
        return None;
    }
    let to = req.params.as_ref()?.get("to_height")?.as_u64()?;
    let line = dispatch::safety_line(&ctx.pool)?;
    (to > 0 && to <= line).then(|| {
        Cache::immutable_key(
            ctx.chain.epoch(),
            &req.method,
            &dispatch::params_key(req.params.as_ref()),
        )
    })
}

async fn cache_if_distribution(ctx: &Ctx, key: Option<String>, f: &Forwarded) {
    let Some(key) = key else { return };
    let Ok(resp) = serde_json::from_slice::<JsonRpcResponse<Value>>(&f.body) else {
        return;
    };
    let Some(result) = resp.result else { return };
    let Ok(bytes) = serde_json::to_vec(&result) else {
        return;
    };
    ctx.cache
        .immutable_put(
            key,
            Cached {
                body: Bytes::from(bytes),
                verify: Verify::Agreement.label(),
            },
        )
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::ChainStore;
    use crate::config::Config;
    use crate::upstream::Health;
    use axum::body::Bytes as AxBytes;
    use axum::extract::Path;
    use axum::routing::post;
    use axum::Router;
    use serde_json::json;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    type Handler = Arc<dyn Fn(&str, &[u8]) -> (u16, Vec<u8>) + Send + Sync>;

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

    /// A node whose `/get_outs` answer lists `keys`, with its own volatile
    /// fields.
    fn outs_node(keys: &'static [u64], credits: u64) -> Handler {
        Arc::new(move |path, _| {
            let outs: Vec<Value> = keys
                .iter()
                .map(|k| json!({"height": 100, "key": format!("{k:064x}"), "mask": "m", "txid": "t", "unlocked": true}))
                .collect();
            let result = json!({"outs": outs, "credits": credits, "status": "OK", "top_hash": format!("{credits}"), "untrusted": credits % 2 == 0});
            if path == "/json_rpc" {
                (200, json!({"id": 0, "jsonrpc": "2.0", "result": {"distributions": keys, "credits": credits, "status": "OK", "top_hash": "", "untrusted": true}}).to_string().into_bytes())
            } else {
                (200, result.to_string().into_bytes())
            }
        })
    }

    struct Env {
        ctx: Ctx,
        hits: Arc<AtomicUsize>,
    }

    impl Env {
        async fn new(nodes: Vec<Handler>) -> Self {
            let hits = Arc::new(AtomicUsize::new(0));
            let mut toml = String::from("[probe]\nmin_agree = 1\n");
            let mut health = Vec::new();
            for (i, h) in nodes.into_iter().enumerate() {
                let addr = mock_with(h, Arc::clone(&hits)).await;
                toml.push_str(&format!(
                    "[[upstreams]]\nname = \"m{i}\"\nurl = \"http://{addr}\"\nkind = \"public\"\ntransport = \"http\"\n"
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

        async fn call(
            &self,
            tier: Tier,
            method: &str,
            params: Option<Value>,
            body: Bytes,
        ) -> Outcome {
            let policy = mnr_core::policy::lookup(method).unwrap();
            let (path, content_type): (&'static str, &'static str) = if method.starts_with('/') {
                (
                    policy.method,
                    if method.ends_with(".bin") {
                        "application/octet-stream"
                    } else {
                        "application/json"
                    },
                )
            } else {
                ("/json_rpc", "application/json")
            };
            dispatch::dispatch(
                self.ctx.clone(),
                policy,
                Request {
                    path,
                    method: method.into(),
                    params,
                    id: json!(1),
                    content_type,
                    body,
                    tier,
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
    async fn pro_gets_two_upstream_agreement_free_gets_one() {
        let env = Env::new(vec![
            outs_node(&[1, 2], 5),
            outs_node(&[1, 2], 0),
            outs_node(&[1, 2], 9),
        ])
        .await;
        let o = env
            .call(Tier::Pro, "/get_outs", None, Bytes::from_static(b"{}"))
            .await;
        assert_eq!(o.status, 200);
        assert_eq!(header(&o, "Mnr-Verify"), Some("agreement"));
        assert_eq!(header(&o, "Mnr-Agreeing"), Some("2/2"));
        assert_eq!(header(&o, "Mnr-Upstream"), Some("0"));
        assert_eq!(
            env.hits.load(Ordering::SeqCst),
            2,
            "volatile fields differ, payload agrees"
        );
        let o = env
            .call(Tier::Free, "/get_outs", None, Bytes::from_static(b"{}"))
            .await;
        assert_eq!(header(&o, "Mnr-Verify"), Some("none"));
        assert_eq!(header(&o, "Mnr-Agreeing"), None);
        assert_eq!(env.hits.load(Ordering::SeqCst), 3);
        assert!(env.ctx.pool.status().faults.is_empty());
    }

    #[tokio::test]
    async fn disagreement_is_broken_by_a_third_and_the_outlier_is_faulted() {
        let env = Env::new(vec![
            outs_node(&[1, 9], 0),
            outs_node(&[1, 2], 0),
            outs_node(&[1, 2], 0),
        ])
        .await;
        let o = env
            .call(Tier::Pro, "/get_outs", None, Bytes::from_static(b"{}"))
            .await;
        assert_eq!(o.status, 200);
        assert_eq!(header(&o, "Mnr-Verify"), Some("agreement"));
        assert_eq!(header(&o, "Mnr-Agreeing"), Some("2/3"));
        assert_eq!(header(&o, "Mnr-Upstream"), Some("1"));
        let v: Value = serde_json::from_slice(&o.body).unwrap();
        assert_eq!(v["outs"][1]["key"], format!("{:064x}", 2));
        let s = env.ctx.pool.status();
        assert_eq!(s.faults.len(), 1);
        assert_eq!(s.faults[0].upstream, "m0");
        assert_eq!(s.faults[0].method, "/get_outs");
        assert_eq!(env.hits.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn no_majority_is_a_failed_answer_not_a_guess() {
        // Two disagree, no third upstream at all.
        let env = Env::new(vec![outs_node(&[1, 9], 0), outs_node(&[1, 2], 0)]).await;
        let o = env
            .call(Tier::Pro, "/get_outs", None, Bytes::from_static(b"{}"))
            .await;
        assert_eq!(o.status, 502);
        assert_eq!(header(&o, "Mnr-Verify"), Some("failed"));
        assert!(
            env.ctx.pool.status().faults.is_empty(),
            "nobody can be blamed"
        );
        // Three-way split: the third agrees with neither.
        let env = Env::new(vec![
            outs_node(&[1, 9], 0),
            outs_node(&[1, 2], 0),
            outs_node(&[3], 0),
        ])
        .await;
        let o = env
            .call(Tier::Pro, "/get_outs", None, Bytes::from_static(b"{}"))
            .await;
        assert_eq!(o.status, 502);
        assert_eq!(header(&o, "Mnr-Verify"), Some("failed"));
    }

    #[tokio::test]
    async fn tie_break_skips_a_spare_without_capacity() {
        // m2 is the first spare but has no token left; m3 breaks the tie.
        let env = Env::new(vec![
            outs_node(&[1, 9], 0),
            outs_node(&[1, 2], 0),
            outs_node(&[1, 2], 0),
            outs_node(&[1, 2], 0),
        ])
        .await;
        let u = env.ctx.pool.upstream(2);
        while u.try_take_light() {}
        let o = env
            .call(Tier::Pro, "/get_outs", None, Bytes::from_static(b"{}"))
            .await;
        assert_eq!(o.status, 200);
        assert_eq!(header(&o, "Mnr-Verify"), Some("agreement"));
        assert_eq!(header(&o, "Mnr-Agreeing"), Some("2/3"));
        let s = env.ctx.pool.status();
        assert_eq!(s.upstreams[3].requests, 1, "m3 broke the tie");
        assert_eq!(s.faults[0].upstream, "m0");
    }

    #[tokio::test]
    async fn one_upstream_with_capacity_is_served_unagreed() {
        let env = Env::new(vec![outs_node(&[1], 0), outs_node(&[1], 0)]).await;
        let u = env.ctx.pool.upstream(1);
        while u.try_take_light() {}
        let o = env
            .call(Tier::Pro, "/get_outs", None, Bytes::from_static(b"{}"))
            .await;
        assert_eq!(o.status, 200);
        assert_eq!(header(&o, "Mnr-Verify"), Some("none"));
    }

    /// Hand-encoded epee: `{ outs: [u64...], status: <status> }`.
    fn epee_outs(outs: &[u64], status: &[u8]) -> Vec<u8> {
        let mut b = vec![
            0x01,
            0x11,
            0x01,
            0x01,
            0x01,
            0x01,
            0x02,
            0x01,
            0x01,
            2 << 2,
            4,
        ];
        b.extend_from_slice(b"outs");
        b.extend_from_slice(&[5 | 0x80, (outs.len() as u8) << 2]);
        for o in outs {
            b.extend_from_slice(&o.to_le_bytes());
        }
        b.push(6);
        b.extend_from_slice(b"status");
        b.extend_from_slice(&[10, (status.len() as u8) << 2]);
        b.extend_from_slice(status);
        b
    }

    fn bin_node(body: Vec<u8>) -> Handler {
        Arc::new(move |_, _| (200, body.clone()))
    }

    #[tokio::test]
    async fn bin_answers_are_compared_as_epee_trees() {
        // Same outputs, different status strings: agreement.
        let env = Env::new(vec![
            bin_node(epee_outs(&[1, 2], b"OK")),
            bin_node(epee_outs(&[1, 2], b"ok")),
        ])
        .await;
        let o = env
            .call(Tier::Pro, "/get_outs.bin", None, Bytes::from_static(b""))
            .await;
        assert_eq!(o.status, 200);
        assert_eq!(header(&o, "Mnr-Verify"), Some("agreement"));
        assert_eq!(
            &o.body[..],
            &epee_outs(&[1, 2], b"OK")[..],
            "passed through verbatim"
        );
        // A lying node is outvoted by the tie-breaker and faulted.
        let env = Env::new(vec![
            bin_node(epee_outs(&[1, 2], b"OK")),
            bin_node(epee_outs(&[1, 7], b"OK")),
            bin_node(epee_outs(&[1, 2], b"OK")),
        ])
        .await;
        let o = env
            .call(Tier::Pro, "/get_outs.bin", None, Bytes::from_static(b""))
            .await;
        assert_eq!(header(&o, "Mnr-Verify"), Some("agreement"));
        assert_eq!(header(&o, "Mnr-Agreeing"), Some("2/3"));
        assert_eq!(env.ctx.pool.status().faults[0].upstream, "m1");
        // An answer the relay cannot parse is never called agreement.
        let env = Env::new(vec![
            bin_node(b"not epee".to_vec()),
            bin_node(b"not epee".to_vec()),
        ])
        .await;
        let o = env
            .call(Tier::Pro, "/get_outs.bin", None, Bytes::from_static(b""))
            .await;
        assert_eq!(o.status, 200);
        assert_eq!(header(&o, "Mnr-Verify"), Some("none"));
    }

    #[test]
    fn comparable_strips_volatile_keys_for_json_and_epee() {
        let a = comparable(
            "/get_outs",
            br#"{"outs":[1],"status":"OK","credits":5,"top_hash":"a","untrusted":true}"#,
        );
        let b = comparable(
            "/get_outs",
            br#"{"outs":[1],"status":"Busy","credits":0,"top_hash":"b","untrusted":false}"#,
        );
        let c = comparable("/get_outs", br#"{"outs":[2],"status":"OK"}"#);
        assert!(a.is_some());
        assert_eq!(a, b);
        assert_ne!(a, c);
        let j = comparable(
            "/json_rpc",
            br#"{"id":0,"jsonrpc":"2.0","result":{"distributions":[1],"credits":1,"status":"OK"}}"#,
        );
        let k = comparable(
            "/json_rpc",
            br#"{"id":9,"jsonrpc":"2.0","result":{"distributions":[1],"credits":2,"status":"OK"}}"#,
        );
        assert_eq!(j, k);
        assert_eq!(
            comparable(
                "/json_rpc",
                br#"{"id":0,"jsonrpc":"2.0","error":{"code":-1,"message":"x"}}"#
            ),
            None
        );
        assert_eq!(comparable("/get_outs.bin", b"not epee"), None);
        let p = comparable("/get_outs.bin", &epee_outs(&[1, 2], b"OK")).unwrap();
        let q = comparable("/get_outs.bin", &epee_outs(&[1, 2], b"ok")).unwrap();
        assert_ne!(
            comparable("/get_outs.bin", &epee_outs(&[1, 3], b"OK")),
            Some(Comparable::Epee(match &p {
                Comparable::Epee(s) => s.clone(),
                _ => unreachable!(),
            }))
        );
        assert_eq!(p, q);
        match p {
            Comparable::Epee(s) => {
                assert!(s.contains_key("outs"));
                assert!(!s.contains_key("status"));
            }
            Comparable::Json(_) => panic!("bin answers are epee"),
        }
    }

    #[tokio::test]
    async fn agreed_distribution_below_the_line_is_cached() {
        let env = Env::new(vec![outs_node(&[4, 5], 1), outs_node(&[4, 5], 2)]).await;
        let params =
            json!({"amounts": [0], "from_height": 0, "to_height": 500, "cumulative": false});
        let body = Bytes::from(
            json!({"jsonrpc":"2.0","id":1,"method":"get_output_distribution","params":params})
                .to_string(),
        );
        let o = env
            .call(
                Tier::Pro,
                "get_output_distribution",
                Some(params.clone()),
                body.clone(),
            )
            .await;
        assert_eq!(header(&o, "Mnr-Verify"), Some("agreement"));
        assert_eq!(header(&o, "Mnr-Cache"), Some("bypass"));
        let o = env
            .call(
                Tier::Pro,
                "get_output_distribution",
                Some(params),
                body.clone(),
            )
            .await;
        assert_eq!(header(&o, "Mnr-Cache"), Some("hit"));
        assert_eq!(header(&o, "Mnr-Verify"), Some("agreement"));
        let v: Value = serde_json::from_slice(&o.body).unwrap();
        assert_eq!(v["id"], 1);
        assert_eq!(v["result"]["distributions"], json!([4, 5]));
        assert_eq!(env.hits.load(Ordering::SeqCst), 2);
        // Above the line: never cached.
        let params =
            json!({"amounts": [0], "from_height": 0, "to_height": 995, "cumulative": false});
        let body = Bytes::from(
            json!({"jsonrpc":"2.0","id":1,"method":"get_output_distribution","params":params})
                .to_string(),
        );
        for _ in 0..2 {
            let o = env
                .call(
                    Tier::Pro,
                    "get_output_distribution",
                    Some(params.clone()),
                    body.clone(),
                )
                .await;
            assert_eq!(header(&o, "Mnr-Cache"), Some("bypass"));
        }
        assert_eq!(env.hits.load(Ordering::SeqCst), 6);
    }
}
