//! HTTP ingress: the paths a stock wallet hits, auth, limits, policy, then
//! dispatch (`docs/stage0-mvp-plan.md` §5, §6; invariant 3 and 7).
//!
//! Two shapes are served, both with the same token:
//!
//! - `/v1/<token>/json_rpc` and `/v1/<token>/<legacy path>` for
//!   `--daemon-address rpc.mnr.network:443/v1/<token>`;
//! - `/json_rpc`, `/<legacy path>` (also under `/v1/`) with HTTP Basic auth
//!   for `--daemon-login`.
//!
//! No request log exists: handlers never log the path, the token or the
//! peer address; error samples carry only the 8-character token handle.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use axum::{Json, Router};
use mnr_core::policy::{self, Class, Transport};
use mnr_core::wire::{JsonRpcRequest, JsonRpcResponse, MNR_RATE_LIMITED, MNR_SUBSCRIPTION_EXPIRED};
use serde_json::Value;

use crate::auth::{self, AuthError, Principal, TokenStore};
use crate::billing::{self, Billing};
use crate::cache::Cache;
use crate::chain::ChainStore;
use crate::dispatch::{self, Outcome};
use crate::limits::{Limiter, StreamPermit, Verdict, LIGHT_WU};
use crate::metrics::Metrics;
use crate::stream::Accounted;
use crate::upstream::Pool;

/// Shared state for every handler.
pub struct App {
    pub pool: Arc<Pool>,
    pub chain: Arc<ChainStore>,
    pub cache: Arc<Cache>,
    pub metrics: Arc<Metrics>,
    /// The storefront; `None` without `[auth] database`.
    pub billing: Option<Arc<Billing>>,
    pub store: Arc<dyn TokenStore>,
    pub limiter: Arc<dyn Limiter>,
}

pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/upstreams.json", get(upstreams))
        // Storefront (spec/storefront.md), before the RPC catch-alls.
        .route("/v1/tokens/free", any(billing::free_token_handler))
        .route("/v1/invoices", any(billing::create_invoice_handler))
        .route("/v1/invoices/{id}", get(billing::invoice_status_handler))
        // `/v1/{token}/rotate` is handled inside `rpc` (it would conflict
        // with the catch-all in the router).
        .route("/v1/{*rest}", any(rpc))
        .route("/{*rest}", any(rpc))
        .with_state(app)
}

async fn healthz(State(app): State<Arc<App>>) -> (StatusCode, &'static str) {
    if app.pool.degraded() {
        (StatusCode::SERVICE_UNAVAILABLE, "degraded")
    } else {
        (StatusCode::OK, "ok")
    }
}

/// The public status feed behind `mnr.network/upstreams` (rule 1). Public
/// data, so any origin may read it; cached briefly since it changes once a
/// probe round.
async fn upstreams(State(app): State<Arc<App>>) -> Response {
    let mut r = Json(app.pool.status()).into_response();
    let h = r.headers_mut();
    h.insert("access-control-allow-origin", HeaderValue::from_static("*"));
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=10"),
    );
    r
}

/// Every RPC path lands here. `rest` is everything after `/` or `/v1/`.
async fn rpc(
    State(app): State<Arc<App>>,
    Path(rest): Path<String>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let (path_token, rpc_path) = split_token(&rest);
    // Token rotation lives beside the RPC paths: `/v1/<token>/rotate`.
    if let Some(token) = path_token {
        if rest.rsplit('/').next() == Some("rotate") {
            return billing::rotate_response(&app, token, &method);
        }
    }
    let authz = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let Some(token) = auth::extract_token(path_token, authz) else {
        app.metrics.refused("unauthorized");
        return unauthorized();
    };
    let principal = match app.store.authenticate(&auth::token_hash(&token)) {
        Ok(p) => p,
        Err(AuthError::Unknown) => {
            app.metrics.refused("unauthorized");
            return unauthorized();
        }
        Err(AuthError::Expired) => {
            app.metrics.refused("expired");
            return json_rpc_error(
                StatusCode::FORBIDDEN,
                Value::Null,
                MNR_SUBSCRIPTION_EXPIRED,
                "subscription expired",
                &[],
            );
        }
    };
    // Token is out of scope from here on; only the principal travels.
    drop(token);

    if method != Method::POST && method != Method::GET {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }

    let is_jsonrpc = rpc_path == "/json_rpc";
    let (policy, id, requested, params) = match rpc_path {
        "/json_rpc" => {
            let req: JsonRpcRequest = match serde_json::from_slice(&body) {
                Ok(r) => r,
                Err(_) => {
                    app.metrics.refused("bad_request");
                    return json_rpc_error(
                        StatusCode::BAD_REQUEST,
                        Value::Null,
                        mnr_core::wire::PARSE_ERROR,
                        "parse error",
                        &[],
                    );
                }
            };
            (
                policy::lookup_or_deny(&req.method),
                req.id,
                req.method,
                req.params,
            )
        }
        p => (policy::lookup_or_deny(p), Value::Null, p.to_owned(), None),
    };

    match policy.class {
        Class::Deny => {
            app.metrics.refused("denied");
            return denied(is_jsonrpc, id, &requested);
        }
        Class::NotDaemon => {
            app.metrics.refused("not_daemon");
            let hint = policy.note.split(';').next().map(str::trim);
            return json_response(
                StatusCode::OK,
                &JsonRpcResponse::<()>::method_not_found(id, &requested, hint),
                &[],
            );
        }
        _ => {}
    }

    match app.limiter.admit(&principal, LIGHT_WU) {
        Verdict::Allow => {}
        Verdict::RateLimited { retry_after_secs } => {
            app.metrics.refused("rate_limited");
            return json_rpc_error(
                StatusCode::TOO_MANY_REQUESTS,
                id,
                MNR_RATE_LIMITED,
                "rate limited",
                &[("Retry-After", retry_after_secs.to_string())],
            );
        }
        Verdict::QuotaExceeded => {
            app.metrics.refused("quota");
            return json_rpc_error(
                StatusCode::TOO_MANY_REQUESTS,
                id,
                MNR_RATE_LIMITED,
                "work-unit allowance exhausted",
                &[("Retry-After", "3600".into())],
            );
        }
    }

    // Concurrent streams are capped per principal (plan §5): take a permit
    // that the RAII guard releases when the response body is done. It is
    // handed to the accounting stream in `respond`.
    let stream_permit = if policy.class == Class::PassthroughStream {
        match app.limiter.take_stream(&principal) {
            Some(p) => Some(p),
            None => {
                app.metrics.refused("streams");
                return json_rpc_error(
                    StatusCode::TOO_MANY_REQUESTS,
                    id,
                    MNR_RATE_LIMITED,
                    "too many concurrent streams",
                    &[("Retry-After", "1".into())],
                );
            }
        }
    } else {
        None
    };

    let content_type = if rpc_path.ends_with(".bin") {
        "application/octet-stream"
    } else {
        "application/json"
    };
    let ctx = dispatch::Ctx {
        pool: Arc::clone(&app.pool),
        chain: Arc::clone(&app.chain),
        cache: Arc::clone(&app.cache),
    };
    let request = dispatch::Request {
        path: rpc_path,
        method: requested,
        params,
        id,
        content_type,
        body,
        tier: principal.tier,
    };
    let outcome = dispatch::dispatch(ctx, policy, request).await;
    if outcome.extra_wu > 0 {
        app.limiter.charge(&principal, outcome.extra_wu);
    }
    app.metrics
        .charged(principal.tier, LIGHT_WU + outcome.extra_wu);
    let label = |name: &str| -> String {
        outcome
            .headers
            .iter()
            .find(|(k, _)| *k == name)
            .map_or_else(|| "-".to_owned(), |(_, v)| v.clone())
    };
    app.metrics.request(
        policy.class.label(),
        &label("Mnr-Verify"),
        &label("Mnr-Cache"),
        outcome.status,
    );
    respond(outcome, &principal, &app, stream_permit)
}

/// `sub_…/json_rpc` → (token, "/json_rpc"); `json_rpc` → (None, "/json_rpc").
/// The RPC path is normalised to one of the paths the policy knows, so an
/// unknown path becomes `/` and is denied without ever being echoed.
fn split_token(rest: &str) -> (Option<&str>, &'static str) {
    match rest.split_once('/') {
        Some((first, tail)) if auth::looks_like_token(first) => {
            (Some(first), slash(tail.trim_end_matches('/')))
        }
        None if auth::looks_like_token(rest) => (Some(rest), "/"),
        _ => (None, slash(rest.trim_end_matches('/'))),
    }
}

/// Map `get_height` to the static `/get_height` from the policy table.
fn slash(rest: &str) -> &'static str {
    policy_paths().find(|p| &p[1..] == rest).unwrap_or("/")
}

fn policy_paths() -> impl Iterator<Item = &'static str> {
    policy::table()
        .iter()
        .filter(|p| p.transport == Transport::LegacyPath || p.method == "/json_rpc")
        .map(|p| p.method)
        .chain(std::iter::once("/json_rpc"))
}

/// JSON-RPC callers get `-32601` in a 200 like monerod would; legacy paths
/// get a 403 so a wallet does not mistake the body for a daemon answer.
fn denied(is_jsonrpc: bool, id: Value, requested: &str) -> Response {
    if is_jsonrpc {
        json_response(
            StatusCode::OK,
            &JsonRpcResponse::<()>::method_not_found(id, requested, None),
            &[],
        )
    } else {
        json_rpc_error(
            StatusCode::FORBIDDEN,
            Value::Null,
            mnr_core::wire::METHOD_NOT_FOUND,
            "method not allowed",
            &[],
        )
    }
}

/// 401 with two challenges. Digest first: stock Monero wallets speak only
/// Digest for `--daemon-login`, and they expect the token as the username
/// (see [`auth::extract_token`]). The nonce is random per challenge. Basic
/// second, for everything else.
fn unauthorized() -> Response {
    let mut r = json_rpc_error(
        StatusCode::UNAUTHORIZED,
        Value::Null,
        mnr_core::wire::INVALID_REQUEST,
        "unknown token",
        &[],
    );
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).expect("operating system random source");
    let nonce: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
    let digest = format!(
        "Digest realm=\"mnr\", qop=\"auth\", algorithm=MD5, nonce=\"{nonce}\", opaque=\"mnr\""
    );
    if let Ok(v) = HeaderValue::from_str(&digest) {
        r.headers_mut().append(header::WWW_AUTHENTICATE, v);
    }
    r.headers_mut().append(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"mnr\""),
    );
    r
}

fn json_rpc_error(
    status: StatusCode,
    id: Value,
    code: i64,
    message: &str,
    extra: &[(&'static str, String)],
) -> Response {
    json_response(
        status,
        &JsonRpcResponse::<()>::error(id, code, message),
        extra,
    )
}

fn json_response<T: serde::Serialize>(
    status: StatusCode,
    body: &T,
    extra: &[(&'static str, String)],
) -> Response {
    let bytes = serde_json::to_vec(body).unwrap_or_default();
    let mut r = (status, Bytes::from(bytes)).into_response();
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    set_headers(&mut r, extra);
    r
}

fn respond(
    o: Outcome,
    principal: &Principal,
    app: &App,
    stream_permit: Option<StreamPermit>,
) -> Response {
    let status = StatusCode::from_u16(o.status).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut r = match o.stream {
        Some(inner) => {
            // The client's stream permit and the work-unit charge live with
            // the body: released and settled when it ends or the client goes.
            let counted = Accounted::new(
                inner,
                Arc::clone(&app.limiter),
                Arc::clone(&app.metrics),
                principal.clone(),
                stream_permit,
            );
            let mut r = (status, axum::body::Body::from_stream(counted)).into_response();
            if let Some(n) = o.content_length {
                if let Ok(v) = HeaderValue::from_str(&n.to_string()) {
                    r.headers_mut().insert(header::CONTENT_LENGTH, v);
                }
            }
            r
        }
        None => (status, o.body).into_response(),
    };
    if let Ok(ct) = HeaderValue::from_str(&o.content_type) {
        r.headers_mut().insert(header::CONTENT_TYPE, ct);
    }
    set_headers(&mut r, &o.headers);
    set_headers(&mut r, &[("Mnr-Tier", principal.tier.label().to_owned())]);
    r
}

fn set_headers(r: &mut Response, extra: &[(&'static str, String)]) {
    for (k, v) in extra {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(v),
        ) {
            r.headers_mut().insert(name, value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "sub_4k9ZQ2pQ7wq1sDhBfT8zPxT5Y3v7g9jN2mR6cLbVwXyU";

    #[test]
    fn unauthorized_offers_digest_then_basic() {
        let r = unauthorized();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        let challenges: Vec<&str> = r
            .headers()
            .get_all(header::WWW_AUTHENTICATE)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(challenges.len(), 2);
        assert!(
            challenges[0].starts_with("Digest realm=\"mnr\""),
            "{}",
            challenges[0]
        );
        assert!(challenges[0].contains("qop=\"auth\"") && challenges[0].contains("algorithm=MD5"));
        assert_eq!(challenges[1], "Basic realm=\"mnr\"");
        let r2 = unauthorized();
        assert_ne!(
            r.headers().get_all(header::WWW_AUTHENTICATE).iter().next(),
            r2.headers().get_all(header::WWW_AUTHENTICATE).iter().next(),
            "nonce is fresh per challenge"
        );
    }

    #[test]
    fn path_token_is_split_from_the_rpc_path() {
        assert_eq!(
            split_token(&format!("{TOKEN}/json_rpc")),
            (Some(TOKEN), "/json_rpc")
        );
        assert_eq!(
            split_token(&format!("{TOKEN}/get_blocks.bin")),
            (Some(TOKEN), "/get_blocks.bin")
        );
        assert_eq!(split_token("json_rpc"), (None, "/json_rpc"));
        assert_eq!(split_token("get_height"), (None, "/get_height"));
        // Restricted endpoints are explicit Deny rows, so they keep their
        // name; anything the table has never heard of collapses to `/`.
        assert_eq!(split_token("set_log_level"), (None, "/set_log_level"));
        assert_eq!(split_token("wp-login.php"), (None, "/"));
        assert_eq!(split_token(TOKEN), (Some(TOKEN), "/"));
    }
}
