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
use crate::cache::Cache;
use crate::chain::ChainStore;
use crate::dispatch::{self, Outcome};
use crate::limits::{Limiter, Verdict, LIGHT_WU};
use crate::upstream::{Pool, PoolStatus};

/// Shared state for every handler.
pub struct App {
    pub pool: Arc<Pool>,
    // Read by verification (next commit).
    #[allow(dead_code)]
    pub chain: Arc<ChainStore>,
    #[allow(dead_code)]
    pub cache: Arc<Cache>,
    pub store: Arc<dyn TokenStore>,
    pub limiter: Arc<dyn Limiter>,
}

pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/upstreams.json", get(upstreams))
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

async fn upstreams(State(app): State<Arc<App>>) -> Json<PoolStatus> {
    Json(app.pool.status())
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
    let authz = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let Some(token) = auth::extract_token(path_token, authz) else {
        return unauthorized();
    };
    let principal = match app.store.authenticate(&auth::token_hash(&token)) {
        Ok(p) => p,
        Err(AuthError::Unknown) => return unauthorized(),
        Err(AuthError::Expired) => {
            return json_rpc_error(
                StatusCode::FORBIDDEN,
                Value::Null,
                MNR_SUBSCRIPTION_EXPIRED,
                "subscription expired",
                &[],
            )
        }
    };
    // Token is out of scope from here on; only the principal travels.
    drop(token);

    if method != Method::POST && method != Method::GET {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }

    let is_jsonrpc = rpc_path == "/json_rpc";
    let (policy, id, requested) = match rpc_path {
        "/json_rpc" => {
            let req: JsonRpcRequest = match serde_json::from_slice(&body) {
                Ok(r) => r,
                Err(_) => {
                    return json_rpc_error(
                        StatusCode::BAD_REQUEST,
                        Value::Null,
                        mnr_core::wire::PARSE_ERROR,
                        "parse error",
                        &[],
                    )
                }
            };
            (policy::lookup_or_deny(&req.method), req.id, req.method)
        }
        p => (policy::lookup_or_deny(p), Value::Null, p.to_owned()),
    };

    match policy.class {
        Class::Deny => return denied(is_jsonrpc, id, &requested),
        Class::NotDaemon => {
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
            return json_rpc_error(
                StatusCode::TOO_MANY_REQUESTS,
                id,
                MNR_RATE_LIMITED,
                "rate limited",
                &[("Retry-After", retry_after_secs.to_string())],
            )
        }
        Verdict::QuotaExceeded => {
            return json_rpc_error(
                StatusCode::TOO_MANY_REQUESTS,
                id,
                MNR_RATE_LIMITED,
                "work-unit allowance exhausted",
                &[("Retry-After", "3600".into())],
            )
        }
    }

    // Concurrent streams are capped per principal (plan §5): take a permit
    // that the RAII guard releases when this request finishes. The permit
    // must live for the whole dispatch, so it is bound for the handler.
    let _stream_permit = if policy.class == Class::PassthroughStream {
        match app.limiter.take_stream(&principal) {
            Some(p) => Some(p),
            None => {
                return json_rpc_error(
                    StatusCode::TOO_MANY_REQUESTS,
                    id,
                    MNR_RATE_LIMITED,
                    "too many concurrent streams",
                    &[("Retry-After", "1".into())],
                )
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
    let outcome = dispatch::dispatch(&app.pool, policy, rpc_path, content_type, body).await;
    if outcome.extra_wu > 0 {
        app.limiter.charge(&principal, outcome.extra_wu);
    }
    respond(outcome, &principal)
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

fn unauthorized() -> Response {
    let mut r = json_rpc_error(
        StatusCode::UNAUTHORIZED,
        Value::Null,
        mnr_core::wire::INVALID_REQUEST,
        "unknown token",
        &[],
    );
    r.headers_mut().insert(
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

fn respond(o: Outcome, principal: &Principal) -> Response {
    let status = StatusCode::from_u16(o.status).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut r = (status, o.body).into_response();
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
