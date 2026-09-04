//! Dispatch: policy class → which upstreams, how many, and what to tell the
//! client about it (`docs/stage0-mvp-plan.md` §3, §4 invariant 1 and 4).
//!
//! Reads go to the best-ranked upstream with capacity and fall through to
//! the next on transport failure, cap exhaustion or a 5xx (daemon reads are
//! idempotent). Streams take a stream slot and prefer the owned node.
//! Broadcasts fan out to every healthy upstream in parallel and succeed if
//! any accepts. Verification is not wired yet (week 3): every answer is
//! annotated `Mnr-Verify: none` rather than silently trusted.

use std::time::Duration;

use bytes::Bytes;
use mnr_core::policy::{Class, Policy};
use serde_json::Value;

use crate::limits::{stream_wu, LIGHT_WU};
use crate::upstream::{ForwardError, Forwarded, Pool, Work};

/// Overall budget for a broadcast (policy note: 6 s).
const BROADCAST_BUDGET: Duration = Duration::from_secs(6);
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
            Ok(f) => return passthrough(f, &u.cfg.name, 0),
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
                return passthrough(f, &u.cfg.name, wu);
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
            // A broadcast is never refused by our own light cap: it is one
            // call per upstream and the tx is the user's money.
            u.try_take_light();
            (
                u.cfg.name.clone(),
                u.forward(path, content_type, body, BROADCAST_BUDGET).await,
            )
        }
    });
    let results = futures_util::future::join_all(sends).await;
    let mut accepted = 0usize;
    let mut first_ok: Option<(String, Forwarded)> = None;
    let mut first_reject: Option<(String, Forwarded)> = None;
    for (name, r) in results {
        if let Ok(f) = r {
            if f.status == 200 && accepted_by_daemon(&f.body) {
                accepted += 1;
                first_ok.get_or_insert((name, f));
            } else {
                first_reject.get_or_insert((name, f));
            }
        }
    }
    let relayed = format!("{accepted}/{n}");
    let (name, f) = match (first_ok, first_reject) {
        (Some(ok), _) => ok,
        (None, Some(rej)) => rej,
        (None, None) => {
            let mut o = Outcome::json_error(502, "no upstream answered");
            o.headers.push(("Mnr-Relayed", relayed));
            return o;
        }
    };
    let mut o = passthrough(f, &name, 0);
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

fn passthrough(f: Forwarded, upstream: &str, extra_wu: u64) -> Outcome {
    Outcome {
        status: f.status,
        content_type: f
            .content_type
            .unwrap_or_else(|| "application/json".to_owned()),
        body: f.body,
        headers: vec![
            ("Mnr-Verify", "none".into()),
            ("Mnr-Upstream", upstream.to_owned()),
        ],
        extra_wu,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
