//! Dispatch: policy class → which upstreams, how many, and what to tell the
//! client about it (`docs/stage0-mvp-plan.md` §3, §4 invariant 1 and 4).
//!
//! Reads go to the best-ranked upstream with capacity and fall through to
//! the next on transport failure, cap exhaustion or a 5xx (daemon reads are
//! idempotent). Streams take a stream slot and prefer the owned node.
//! Broadcasts fan out to every healthy upstream in parallel and succeed if
//! any accepts. Verification is not wired yet (week 3): every answer is
//! annotated `Mnr-Verify: none` rather than silently trusted.

use std::time::{Duration, Instant};

use bytes::Bytes;
use mnr_core::policy::{Class, Policy};
use serde_json::Value;

use crate::limits::{stream_wu, LIGHT_WU};
use crate::upstream::{ForwardError, Forwarded, Pool, Work};

/// Overall budget for a broadcast (policy note: 6 s).
const BROADCAST_BUDGET: Duration = Duration::from_secs(6);
/// How long a broadcast queues for a per-upstream light token before it
/// gives up on that upstream (rule 3: above the cap, requests queue).
const BROADCAST_CAP_WAIT: Duration = Duration::from_secs(1);
/// How many ranked upstreams a read may try before giving up.
const MAX_ATTEMPTS: usize = 3;

/// What the ingress turns into an HTTP response.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub status: u16,
    pub content_type: String,
    pub body: Bytes,
    /// `Mnr-*` headers to add.
    pub headers: Vec<(&'static str, String)>,
    /// Work units this request cost beyond the one charged at admission.
    pub extra_wu: u64,
}

impl Outcome {
    fn json_error(status: u16, message: &str) -> Self {
        let body = serde_json::json!({
            "error": { "code": -32603, "message": message },
            "status": message,
            "untrusted": true,
        });
        Self {
            status,
            content_type: "application/json".into(),
            body: Bytes::from(body.to_string()),
            headers: vec![("Mnr-Verify", "none".into())],
            extra_wu: 0,
        }
    }
}

/// Forward `body` for `policy` at `path`. `content_type` is what the client
/// sent (`application/json` or `application/octet-stream` for `.bin`).
pub async fn dispatch(
    pool: &Pool,
    policy: &'static Policy,
    path: &str,
    content_type: &str,
    body: Bytes,
) -> Outcome {
    let timeout = Duration::from_millis(u64::from(policy.timeout_ms.max(1000)));
    match policy.class {
        Class::Broadcast => broadcast(pool, path, content_type, body).await,
        Class::PassthroughStream => stream(pool, path, content_type, body, timeout).await,
        Class::Deny | Class::NotDaemon => Outcome::json_error(403, "method not allowed"),
        _ => read(pool, path, content_type, body, timeout).await,
    }
}

async fn read(
    pool: &Pool,
    path: &str,
    content_type: &str,
    body: Bytes,
    timeout: Duration,
) -> Outcome {
    let ranked = pool.ranked(Work::Light);
    if ranked.is_empty() {
        return Outcome::json_error(503, "no healthy upstream");
    }
    let mut last = ForwardError::Cap;
    for id in ranked.into_iter().take(MAX_ATTEMPTS) {
        let u = pool.upstream(id);
        if !u.try_take_light() {
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
    Outcome::json_error(status, &format!("upstream unavailable: {last}"))
}

async fn stream(
    pool: &Pool,
    path: &str,
    content_type: &str,
    body: Bytes,
    timeout: Duration,
) -> Outcome {
    let ranked = pool.ranked(Work::Stream);
    if ranked.is_empty() {
        return Outcome::json_error(503, "no healthy upstream");
    }
    for id in ranked {
        let u = pool.upstream(id);
        let Some(_slot) = u.try_take_stream() else {
            continue;
        };
        match u.forward(path, content_type, body.clone(), timeout).await {
            Ok(f) if f.status < 500 => {
                let wu = stream_wu(f.body.len() as u64).saturating_sub(LIGHT_WU);
                return passthrough(f, id, wu);
            }
            Ok(_) | Err(_) => continue,
        }
    }
    Outcome::json_error(503, "all stream slots busy")
}

/// Fan out to every healthy upstream; success if any accepts. The response
/// carries `Mnr-Relayed: k/n`. If all reject, the first rejection is
/// returned verbatim so the wallet sees the daemon's own reason.
async fn broadcast(pool: &Pool, path: &str, content_type: &str, body: Bytes) -> Outcome {
    let ranked = pool.ranked(Work::Light);
    let n = ranked.len();
    if n == 0 {
        return Outcome::json_error(503, "no healthy upstream");
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
            let mut o = Outcome::json_error(502, "no upstream answered");
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
        headers: vec![
            ("Mnr-Verify", "none".into()),
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
    use axum::routing::post;
    use axum::Router;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// A fake monerod that answers every POST with a fixed status + body.
    async fn mock(status: u16, body: &'static str, hits: Arc<AtomicUsize>) -> SocketAddr {
        let app = Router::new().route(
            "/{*rest}",
            post(move || {
                let hits = Arc::clone(&hits);
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    (axum::http::StatusCode::from_u16(status).unwrap(), body)
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        addr
    }

    /// A pool over `addrs`, all healthy and on a synthetic quorum tip.
    fn pool_over(addrs: &[SocketAddr]) -> Pool {
        let mut toml = String::from("[probe]\nmin_agree = 1\n");
        for (i, a) in addrs.iter().enumerate() {
            toml.push_str(&format!(
                "[[upstreams]]\nname = \"m{i}\"\nurl = \"http://{a}\"\nkind = \"public\"\ntransport = \"http\"\n"
            ));
        }
        let pool = Pool::from_config(&Config::parse(&toml).unwrap()).unwrap();
        let healthy = Health::healthy_for_test(101, [7; 32]);
        pool.set_for_test(vec![healthy; addrs.len()], Some((100, [7; 32])));
        pool
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
        let pool = pool_over(&[rej, ok, down]);
        let policy = mnr_core::policy::lookup("/send_raw_transaction").unwrap();
        let o = dispatch(
            &pool,
            policy,
            "/send_raw_transaction",
            "application/json",
            Bytes::from("{}"),
        )
        .await;
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
        let pool = pool_over(&[rej]);
        let policy = mnr_core::policy::lookup("/send_raw_transaction").unwrap();
        let o = dispatch(
            &pool,
            policy,
            "/send_raw_transaction",
            "application/json",
            Bytes::from("{}"),
        )
        .await;
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
        let pool = pool_over(&[bad, good]);
        let policy = mnr_core::policy::lookup("/get_height").unwrap();
        let o = dispatch(
            &pool,
            policy,
            "/get_height",
            "application/json",
            Bytes::new(),
        )
        .await;
        assert_eq!(o.status, 200);
        assert!(o.headers.contains(&("Mnr-Upstream", "1".to_owned())));
        assert!(o.headers.contains(&("Mnr-Verify", "none".to_owned())));
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn read_respects_the_per_upstream_light_cap() {
        let hits = Arc::new(AtomicUsize::new(0));
        let only = mock(200, r#"{"height":101,"status":"OK"}"#, Arc::clone(&hits)).await;
        let pool = pool_over(&[only]);
        let policy = mnr_core::policy::lookup("/get_height").unwrap();
        let mut statuses = Vec::new();
        for _ in 0..7 {
            statuses.push(
                dispatch(
                    &pool,
                    policy,
                    "/get_height",
                    "application/json",
                    Bytes::new(),
                )
                .await
                .status,
            );
        }
        // Default cap is 5 rps: the sixth and seventh calls within the same
        // second are refused by us, never sent to the public node.
        assert_eq!(statuses, vec![200, 200, 200, 200, 200, 503, 503]);
        assert_eq!(hits.load(Ordering::SeqCst), 5);
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
        let o = Outcome::json_error(503, "no healthy upstream");
        assert_eq!(o.status, 503);
        assert!(o.headers.contains(&("Mnr-Verify", "none".to_owned())));
        let v: Value = serde_json::from_slice(&o.body).unwrap();
        assert_eq!(v["error"]["code"], -32603);
    }
}
