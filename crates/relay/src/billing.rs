//! The storefront (`docs/stage0-mvp-plan.md` §5 payments; `spec/storefront.md`):
//! free tokens issued instantly, Pro tokens paid with an XMR invoice, token
//! rotation. Everything a client is, we never learn; everything a client
//! pays, a view-only wallet sees.
//!
//! - `POST /v1/tokens/free` — a Free token, returned once.
//! - `POST /v1/invoices` — a Pro invoice: a fresh subaddress on the
//!   view-only `monero-wallet-rpc`, an amount, a 24 h deadline.
//! - `GET /v1/invoices/{id}` — its status; once paid, the token.
//! - `POST /v1/{token}/rotate` — a new token, the old one valid 24 h more.
//!
//! **No raw token at rest.** A Pro token is *derived*: `SHA-256(secret ‖
//! "mnr-invoice-token-v1" ‖ invoice id)`, base58, `sub_` prefix. The store
//! keeps only its hash, like every token; the invoice status endpoint
//! recomputes it from the id, which is the client's secret. The secret
//! lives in `[billing] secret_file` (32 random bytes, created on first
//! start, mode 0600).
//!
//! **No client identity stored.** Issuance is throttled per client key,
//! where the key is `SHA-256(boot key ‖ client address)` with a random
//! per-process boot key: it cannot be reversed after a restart and is
//! never written anywhere. The address comes from the socket, or from
//! `[billing] client_ip_header` when a trusted proxy in front sets it
//! (Cloudflare's `CF-Connecting-IP` forwarded by Caddy); the relay's own
//! listener stays on loopback in that setup.
//!
//! **Watcher.** Every 30 s pending invoices are checked against the wallet's
//! incoming transfers to their subaddress; the sum with at least
//! `[billing] confirmations` confirmations, received after the invoice was
//! created, pays it when it reaches the amount. Payment activates the
//! derived token for `30 d × months`, or extends the token a renewal names.
//! A renewal reuses the token's previous subaddress. Overpayment is a tip
//! and is logged as an amount only. A wallet that does not answer leaves
//! invoices pending; nothing is ever marked paid on an error.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::extract::{ConnectInfo, Path as AxPath, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use parking_lot::Mutex;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::auth::{self, handle, token_hash, Tier};
use crate::config::BillingConfig;
use crate::store::{Invoice, InvoiceStatus, SqliteStore};

/// How often the watcher checks pending invoices.
const WATCH_EVERY: Duration = Duration::from_secs(30);
/// How long an unpaid invoice stays open.
const INVOICE_TTL: Duration = Duration::from_secs(24 * 3600);
/// Seconds in the month a Pro payment buys.
const MONTH_SECS: u64 = 30 * 24 * 3600;
/// Window of the per-client issuance bucket.
const BUCKET_WINDOW: Duration = Duration::from_secs(3600);
/// Transfers older than this before the invoice was created are not
/// counted for it (clock skew between us and the wallet).
const CREATED_SLACK: u64 = 60;
const TOKEN_DOMAIN: &[u8] = b"mnr-invoice-token-v1";

pub struct Billing {
    cfg: BillingConfig,
    store: Arc<SqliteStore>,
    wallet: reqwest::Client,
    secret: [u8; 32],
    boot_key: [u8; 32],
    /// Issuance timestamps per client key, pruned to the last hour.
    buckets: Mutex<HashMap<[u8; 32], Vec<Instant>>>,
    /// `(day, count)` of free tokens issued today.
    free_today: Mutex<(u64, u64)>,
}

/// Why a storefront request was refused.
#[derive(Debug)]
enum Refusal {
    Throttled,
    Unavailable(&'static str),
    BadRequest(&'static str),
    NotFound,
}

impl Refusal {
    fn response(self) -> Response {
        let (status, msg) = match self {
            Self::Throttled => (
                StatusCode::TOO_MANY_REQUESTS,
                "too many requests; try again later",
            ),
            Self::Unavailable(m) => (StatusCode::SERVICE_UNAVAILABLE, m),
            Self::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            Self::NotFound => (StatusCode::NOT_FOUND, "unknown invoice"),
        };
        (status, Json(json!({ "error": msg }))).into_response()
    }
}

impl Billing {
    /// Build the storefront over an opened token store. Fails only if the
    /// secret file cannot be created or read.
    pub fn new(cfg: BillingConfig, store: Arc<SqliteStore>) -> Result<Self, String> {
        let secret = match &cfg.secret_file {
            Some(p) => load_or_create_secret(p)?,
            None => {
                let mut s = [0u8; 32];
                getrandom::fill(&mut s).expect("operating system random source");
                tracing::warn!(
                    "no [billing] secret_file: invoice tokens will not survive a restart"
                );
                s
            }
        };
        let mut boot_key = [0u8; 32];
        getrandom::fill(&mut boot_key).expect("operating system random source");
        let wallet = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self {
            cfg,
            store,
            wallet,
            secret,
            boot_key,
            buckets: Mutex::new(HashMap::new()),
            free_today: Mutex::new((0, 0)),
        })
    }

    /// The Pro token an invoice pays for. Deterministic in the id and the
    /// secret; never stored raw.
    pub fn derived_token(&self, invoice_id: &str) -> String {
        let mut h = Sha256::new();
        h.update(self.secret);
        h.update(TOKEN_DOMAIN);
        h.update(invoice_id.as_bytes());
        let bytes: [u8; 32] = h.finalize().into();
        format!("sub_{}", crate::store::base58_encode(&bytes))
    }

    /// The client key for throttling: unrecoverable after this process ends.
    fn client_key(&self, headers: &HeaderMap, peer: IpAddr) -> [u8; 32] {
        let from_header = self
            .cfg
            .client_ip_header
            .as_deref()
            .and_then(|name| headers.get(name))
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(str::trim)
            .filter(|v| !v.is_empty());
        let addr = from_header.map_or_else(|| peer.to_string(), str::to_owned);
        let mut h = Sha256::new();
        h.update(self.boot_key);
        h.update(addr.as_bytes());
        h.finalize().into()
    }

    /// Take one issuance from the client's bucket, or refuse.
    fn admit(&self, key: [u8; 32], now: Instant) -> Result<(), Refusal> {
        let mut buckets = self.buckets.lock();
        // Keep the map bounded: drop clients whose window is empty.
        buckets.retain(|_, v| {
            v.retain(|t| now.duration_since(*t) < BUCKET_WINDOW);
            !v.is_empty()
        });
        let v = buckets.entry(key).or_default();
        if v.len() >= self.cfg.per_client_per_hour as usize {
            return Err(Refusal::Throttled);
        }
        v.push(now);
        Ok(())
    }

    fn admit_free_today(&self) -> Result<(), Refusal> {
        let day = unix_now() / 86_400;
        let mut t = self.free_today.lock();
        if t.0 != day {
            *t = (day, 0);
        }
        if t.1 >= self.cfg.free_per_day {
            return Err(Refusal::Throttled);
        }
        t.1 += 1;
        Ok(())
    }

    fn cors(&self, r: &mut Response) {
        if let Some(origin) = &self.cfg.cors_origin {
            if let Ok(v) = HeaderValue::from_str(origin) {
                let h = r.headers_mut();
                h.insert("access-control-allow-origin", v);
                h.insert(
                    "access-control-allow-methods",
                    HeaderValue::from_static("GET, POST, OPTIONS"),
                );
                h.insert(
                    "access-control-allow-headers",
                    HeaderValue::from_static("content-type"),
                );
                h.insert("access-control-max-age", HeaderValue::from_static("600"));
                h.insert("vary", HeaderValue::from_static("Origin"));
            }
        }
        // Tokens are shown once; nothing here may be cached by anyone.
        r.headers_mut()
            .insert("cache-control", HeaderValue::from_static("no-store"));
    }

    // ── wallet-rpc ──────────────────────────────────────────────────────

    async fn wallet_call(&self, method: &str, params: Value) -> Result<Value, String> {
        let url = self
            .cfg
            .wallet_rpc
            .as_deref()
            .ok_or("no [billing] wallet_rpc configured")?;
        let body = json!({"jsonrpc": "2.0", "id": "0", "method": method, "params": params});
        let resp = self
            .wallet
            .post(url)
            .json(&body)
            .send()
            .await
            .map_err(|_| "wallet-rpc unreachable".to_owned())?;
        if !resp.status().is_success() {
            return Err(format!("wallet-rpc http {}", resp.status().as_u16()));
        }
        let v: Value = resp
            .json()
            .await
            .map_err(|_| "wallet-rpc answer is not JSON".to_owned())?;
        if let Some(e) = v.get("error") {
            return Err(format!(
                "wallet-rpc error: {}",
                e.get("message").and_then(Value::as_str).unwrap_or("?")
            ));
        }
        v.get("result")
            .cloned()
            .ok_or_else(|| "wallet-rpc answer has no result".to_owned())
    }

    /// A fresh subaddress on account 0, labelled with the invoice id.
    async fn new_subaddress(&self, label: &str) -> Result<(String, u32), String> {
        let r = self
            .wallet_call(
                "create_address",
                json!({"account_index": 0, "label": label}),
            )
            .await?;
        let address = r
            .get("address")
            .and_then(Value::as_str)
            .ok_or("create_address: no address")?
            .to_owned();
        let index = r
            .get("address_index")
            .and_then(Value::as_u64)
            .ok_or("create_address: no address_index")? as u32;
        Ok((address, index))
    }

    /// Atomic units received on `subaddr_index` with enough confirmations,
    /// counting only transfers from around the invoice's creation on, and
    /// the highest confirmation count seen (for the status page).
    async fn received(&self, subaddr_index: u32, since: u64) -> Result<(u64, u64), String> {
        let r = self
            .wallet_call(
                "get_transfers",
                json!({"in": true, "pool": true, "account_index": 0, "subaddr_indices": [subaddr_index]}),
            )
            .await?;
        let mut sum = 0u64;
        let mut best_conf = 0u64;
        for list in ["in", "pool"] {
            let Some(items) = r.get(list).and_then(Value::as_array) else {
                continue;
            };
            for t in items {
                let minor = t
                    .get("subaddr_index")
                    .and_then(|s| s.get("minor"))
                    .and_then(Value::as_u64);
                if minor != Some(u64::from(subaddr_index)) {
                    continue;
                }
                let ts = t.get("timestamp").and_then(Value::as_u64).unwrap_or(0);
                if ts + CREATED_SLACK < since {
                    continue;
                }
                let conf = t.get("confirmations").and_then(Value::as_u64).unwrap_or(0);
                best_conf = best_conf.max(conf);
                if conf >= u64::from(self.cfg.confirmations) {
                    sum = sum.saturating_add(t.get("amount").and_then(Value::as_u64).unwrap_or(0));
                }
            }
        }
        Ok((sum, best_conf))
    }

    // ── watcher ─────────────────────────────────────────────────────────

    pub async fn run_watcher(self: Arc<Self>) {
        loop {
            self.check_invoices().await;
            tokio::time::sleep(WATCH_EVERY).await;
        }
    }

    /// One pass over pending invoices.
    pub async fn check_invoices(&self) {
        let now = unix_now();
        let expired = self.store.expire_invoices(now);
        if expired > 0 {
            tracing::info!(expired, "invoices expired unpaid");
        }
        for inv in self.store.pending_invoices() {
            match self.received(inv.subaddr_index, inv.created_at).await {
                Ok((received, _)) => {
                    if received >= inv.amount {
                        self.activate(&inv, received);
                    } else if received != inv.received {
                        let _ = self.store.update_invoice(&inv.id, received, false);
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "invoice check failed; will retry");
                    return;
                }
            }
        }
    }

    /// Payment arrived: activate the derived token or extend the renewed one.
    fn activate(&self, inv: &Invoice, received: u64) {
        let now = unix_now();
        let bought = MONTH_SECS * u64::from(inv.months);
        match inv.renew_hash {
            Some(hash) => {
                let from = self
                    .store
                    .valid_until(&hash)
                    .flatten()
                    .filter(|v| *v > now)
                    .unwrap_or(now);
                if let Err(e) = self.store.extend(&hash, from + bought) {
                    tracing::error!(error = %e, invoice = %inv.id, "cannot extend renewed token");
                    return;
                }
                tracing::info!(handle = %handle(&hash), months = inv.months, "pro token renewed");
            }
            None => {
                let token = self.derived_token(&inv.id);
                self.store
                    .issue_token(&token, Tier::Pro, Some(now + bought));
                tracing::info!(
                    handle = %handle(&token_hash(&token)),
                    months = inv.months,
                    "pro token activated"
                );
            }
        }
        if received > inv.amount {
            tracing::info!(
                tip_atomic = received - inv.amount,
                "invoice overpaid; the difference is a tip"
            );
        }
        if let Err(e) = self.store.update_invoice(&inv.id, received, true) {
            tracing::error!(error = %e, "cannot mark invoice paid");
        }
    }

    // ── handlers ────────────────────────────────────────────────────────

    async fn free_token(&self, headers: &HeaderMap, peer: IpAddr) -> Result<Value, Refusal> {
        self.admit(self.client_key(headers, peer), Instant::now())?;
        self.admit_free_today()?;
        let token = self.store.issue(Tier::Free, None);
        Ok(json!({
            "token": token,
            "tier": "free",
            "allowance_wu": Tier::Free.monthly_wu(),
            "burst_rps": Tier::Free.burst_rps(),
            "daemon_address": "https://rpc.mnr.network/v1/<token>",
            "docs": "https://mnr.network/docs/connect-wallets/",
        }))
    }

    async fn create_invoice(
        &self,
        headers: &HeaderMap,
        peer: IpAddr,
        req: InvoiceRequest,
    ) -> Result<Value, Refusal> {
        if self.cfg.wallet_rpc.is_none() {
            return Err(Refusal::Unavailable(
                "pro invoices are not enabled on this relay",
            ));
        }
        let months = req.months.unwrap_or(1);
        if months == 0 || months > self.cfg.months_max {
            return Err(Refusal::BadRequest("months out of range"));
        }
        self.admit(self.client_key(headers, peer), Instant::now())?;
        let renew_hash = match req.renew.as_deref() {
            Some(t) if auth::looks_like_token(t) => {
                let h = token_hash(t);
                if self.store.valid_until(&h).is_none() {
                    return Err(Refusal::BadRequest("unknown token to renew"));
                }
                Some(h)
            }
            Some(_) => return Err(Refusal::BadRequest("renew is not a token")),
            None => None,
        };
        let id = new_invoice_id();
        // A renewal reuses the token's previous subaddress so the wallet
        // does not grow by one address per month per customer: the last
        // renewal's, or the purchase invoice's (whose derived token this is).
        let previous = renew_hash.and_then(|h| {
            self.store.latest_invoice_for(&h).or_else(|| {
                self.store
                    .purchase_invoice_for(&h, |id| token_hash(&self.derived_token(id)))
            })
        });
        let (address, subaddr_index) = match previous {
            Some(p) => (p.address, p.subaddr_index),
            None => self.new_subaddress(&id).await.map_err(|e| {
                tracing::warn!(error = %e, "cannot create invoice subaddress");
                Refusal::Unavailable("wallet unavailable; try again later")
            })?,
        };
        let now = unix_now();
        let inv = Invoice {
            id: id.clone(),
            subaddr_index,
            address: address.clone(),
            amount: self.cfg.pro_price_atomic.saturating_mul(u64::from(months)),
            months,
            renew_hash,
            created_at: now,
            expires_at: now + INVOICE_TTL.as_secs(),
            status: InvoiceStatus::Pending,
            received: 0,
            paid_at: None,
        };
        self.store
            .create_invoice(&inv)
            .map_err(|_| Refusal::Unavailable("cannot store invoice"))?;
        Ok(invoice_view(&inv, None, 0))
    }

    async fn invoice_status(&self, id: &str) -> Result<Value, Refusal> {
        let Some(inv) = self.store.invoice(id) else {
            return Err(Refusal::NotFound);
        };
        let confirmations = match inv.status {
            InvoiceStatus::Pending => self
                .received(inv.subaddr_index, inv.created_at)
                .await
                .map(|(_, c)| c)
                .unwrap_or(0),
            _ => u64::from(self.cfg.confirmations),
        };
        let token = match (inv.status, inv.renew_hash) {
            (InvoiceStatus::Paid, None) => Some(self.derived_token(&inv.id)),
            _ => None,
        };
        Ok(invoice_view(&inv, token, confirmations))
    }

    fn rotate(&self, token: &str) -> Result<Value, Refusal> {
        let hash = token_hash(token);
        match self.store.rotate(&hash) {
            Ok(new) => Ok(json!({ "token": new, "previous_valid_secs": 24 * 3600 })),
            Err(_) => Err(Refusal::NotFound),
        }
    }
}

fn invoice_view(inv: &Invoice, token: Option<String>, confirmations: u64) -> Value {
    let mut v = json!({
        "invoice_id": inv.id,
        "status": inv.status.label(),
        "address": inv.address,
        "amount_atomic": inv.amount,
        "amount_xmr": format!("{:.12}", inv.amount as f64 / 1e12).trim_end_matches('0').trim_end_matches('.').to_owned(),
        "months": inv.months,
        "renewal": inv.renew_hash.is_some(),
        "received_atomic": inv.received,
        "confirmations": confirmations,
        "created_at": inv.created_at,
        "expires_at": inv.expires_at,
        "uri": format!("monero:{}?tx_amount={}", inv.address, inv.amount as f64 / 1e12),
    });
    if let Some(t) = token {
        v["token"] = Value::String(t);
    }
    v
}

#[derive(Debug, Default, Deserialize)]
pub struct InvoiceRequest {
    pub months: Option<u32>,
    pub renew: Option<String>,
}

fn new_invoice_id() -> String {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).expect("operating system random source");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn load_or_create_secret(path: &Path) -> Result<[u8; 32], String> {
    match std::fs::read(path) {
        Ok(bytes) => bytes
            .try_into()
            .map_err(|_| format!("{} is not a 32-byte secret", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut s = [0u8; 32];
            getrandom::fill(&mut s).expect("operating system random source");
            #[cfg(unix)]
            {
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)
                    .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
                f.write_all(&s)
                    .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
            }
            #[cfg(not(unix))]
            std::fs::write(path, s).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
            tracing::info!(path = %path.display(), "created the invoice token secret");
            Ok(s)
        }
        Err(e) => Err(format!("cannot read {}: {e}", path.display())),
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

// ── axum glue ────────────────────────────────────────────────────────────

/// Shared state the storefront handlers need.
pub type Shared = Arc<Option<Arc<Billing>>>;

fn finish(billing: &Option<Arc<Billing>>, r: Result<Value, Refusal>) -> Response {
    let mut resp = match r {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => e.response(),
    };
    if let Some(b) = billing {
        b.cors(&mut resp);
    }
    resp
}

fn disabled() -> Result<Value, Refusal> {
    Err(Refusal::Unavailable(
        "the storefront needs [auth] database on this relay",
    ))
}

pub async fn free_token_handler(
    State(app): State<Arc<crate::ingress::App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    let b = &app.billing;
    if method == Method::OPTIONS {
        return finish(b, Ok(Value::Null));
    }
    let r = match b.as_ref() {
        Some(b) => b.free_token(&headers, peer.ip()).await,
        None => disabled(),
    };
    finish(b, r)
}

pub async fn create_invoice_handler(
    State(app): State<Arc<crate::ingress::App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let b = &app.billing;
    if method == Method::OPTIONS {
        return finish(b, Ok(Value::Null));
    }
    let req: InvoiceRequest = if body.is_empty() {
        InvoiceRequest::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(r) => r,
            Err(_) => return finish(b, Err(Refusal::BadRequest("invalid JSON body"))),
        }
    };
    let r = match b.as_ref() {
        Some(b) => b.create_invoice(&headers, peer.ip(), req).await,
        None => disabled(),
    };
    finish(b, r)
}

pub async fn invoice_status_handler(
    State(app): State<Arc<crate::ingress::App>>,
    AxPath(id): AxPath<String>,
) -> Response {
    let b = &app.billing;
    if id.len() != 32 || !id.bytes().all(|c| c.is_ascii_hexdigit()) {
        return finish(b, Err(Refusal::NotFound));
    }
    let r = match b.as_ref() {
        Some(b) => b.invoice_status(&id).await,
        None => disabled(),
    };
    finish(b, r)
}

/// `POST /v1/{token}/rotate`, called from the RPC handler once the path
/// token is known.
pub fn rotate_response(app: &crate::ingress::App, token: &str, method: &Method) -> Response {
    let b = &app.billing;
    if *method == Method::OPTIONS {
        return finish(b, Ok(Value::Null));
    }
    if *method != Method::POST {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let r = match b.as_ref() {
        Some(b) if auth::looks_like_token(token) => b.rotate(token),
        Some(_) => Err(Refusal::NotFound),
        None => disabled(),
    };
    finish(b, r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::TokenStore;
    use axum::routing::post;
    use axum::Router;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A fake view-only wallet-rpc: hands out subaddresses and reports what
    /// the test says was received.
    struct Wallet {
        next_index: AtomicU64,
        /// `(minor index, amount, confirmations, timestamp)` transfers.
        transfers: Mutex<Vec<(u64, u64, u64, u64)>>,
        calls: AtomicU64,
    }

    async fn wallet(w: Arc<Wallet>) -> String {
        let app = Router::new().route(
            "/json_rpc",
            post(move |Json(req): Json<Value>| {
                let w = Arc::clone(&w);
                async move {
                    w.calls.fetch_add(1, Ordering::SeqCst);
                    let result = match req["method"].as_str().unwrap() {
                        "create_address" => {
                            let i = w.next_index.fetch_add(1, Ordering::SeqCst);
                            json!({"address": format!("8sub{i}"), "address_index": i})
                        }
                        "get_transfers" => {
                            let want: Vec<u64> = req["params"]["subaddr_indices"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .map(|v| v.as_u64().unwrap())
                                .collect();
                            let items: Vec<Value> = w
                                .transfers
                                .lock()
                                .iter()
                                .filter(|(m, ..)| want.contains(m))
                                .map(|(m, a, c, ts)| json!({"amount": a, "confirmations": c, "timestamp": ts, "subaddr_index": {"major": 0, "minor": m}, "txid": "t"}))
                                .collect();
                            json!({"in": items})
                        }
                        other => panic!("unexpected wallet method {other}"),
                    };
                    Json(json!({"id": "0", "jsonrpc": "2.0", "result": result}))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}/json_rpc")
    }

    fn cfg(wallet_rpc: Option<String>, dir: &Path) -> BillingConfig {
        BillingConfig {
            wallet_rpc,
            pro_price_atomic: 60_000_000_000,
            confirmations: 10,
            free_per_day: 100,
            per_client_per_hour: 3,
            months_max: 12,
            client_ip_header: Some("CF-Connecting-IP".into()),
            secret_file: Some(dir.join("secret")),
            cors_origin: Some("https://mnr.network".into()),
        }
    }

    fn peer() -> IpAddr {
        "127.0.0.1".parse().unwrap()
    }

    #[tokio::test]
    async fn free_tokens_are_issued_and_throttled_per_client_key() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(SqliteStore::open(Some(&dir.path().join("b.db"))).unwrap());
        let b = Billing::new(cfg(None, dir.path()), Arc::clone(&store)).unwrap();
        let h = HeaderMap::new();
        let mut tokens = Vec::new();
        for _ in 0..3 {
            let v = b.free_token(&h, peer()).await.unwrap();
            let t = v["token"].as_str().unwrap().to_owned();
            assert!(auth::looks_like_token(&t));
            assert_eq!(
                store.authenticate(&token_hash(&t)).unwrap().tier,
                Tier::Free
            );
            tokens.push(t);
        }
        assert!(matches!(
            b.free_token(&h, peer()).await,
            Err(Refusal::Throttled)
        ));
        // Another client (by the proxy header) has its own bucket.
        let mut other = HeaderMap::new();
        other.insert("cf-connecting-ip", HeaderValue::from_static("203.0.113.9"));
        assert!(b.free_token(&other, peer()).await.is_ok());
        // Keys are hashes with a per-process key: never the address.
        let k = b.client_key(&other, peer());
        assert_ne!(&k[..], b"203.0.113.9");
        let b2 = Billing::new(cfg(None, dir.path()), Arc::clone(&store)).unwrap();
        assert_ne!(
            k,
            b2.client_key(&other, peer()),
            "a new process has a new key"
        );
        // The secret file was created 0600 and reloads identically.
        assert_eq!(b.secret, b2.secret);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join("secret"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[tokio::test]
    async fn invoice_pays_after_enough_confirmations_and_derives_the_token() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(SqliteStore::open(Some(&dir.path().join("b.db"))).unwrap());
        let w = Arc::new(Wallet {
            next_index: AtomicU64::new(1),
            transfers: Mutex::new(Vec::new()),
            calls: AtomicU64::new(0),
        });
        let url = wallet(Arc::clone(&w)).await;
        let b = Billing::new(cfg(Some(url), dir.path()), Arc::clone(&store)).unwrap();
        let h = HeaderMap::new();
        let v = b
            .create_invoice(
                &h,
                peer(),
                InvoiceRequest {
                    months: Some(2),
                    renew: None,
                },
            )
            .await
            .unwrap();
        let id = v["invoice_id"].as_str().unwrap().to_owned();
        assert_eq!(v["amount_atomic"], 120_000_000_000u64);
        assert_eq!(v["amount_xmr"], "0.12");
        assert_eq!(v["address"], "8sub1");
        assert_eq!(v["status"], "pending");
        assert!(v.get("token").is_none());
        // Nine confirmations: still pending, received not yet counted.
        let now = unix_now();
        w.transfers.lock().push((1, 120_000_000_000, 9, now));
        b.check_invoices().await;
        let s = b.invoice_status(&id).await.unwrap();
        assert_eq!(s["status"], "pending");
        assert_eq!(s["confirmations"], 9);
        assert!(s.get("token").is_none());
        // A transfer from before the invoice existed does not count.
        w.transfers
            .lock()
            .push((1, 500_000_000_000, 50, now - 3600));
        b.check_invoices().await;
        assert_eq!(b.invoice_status(&id).await.unwrap()["status"], "pending");
        // Ten confirmations: paid, token derived, authenticates as Pro.
        w.transfers.lock().clear();
        w.transfers.lock().push((1, 120_000_000_000, 10, now));
        b.check_invoices().await;
        let s = b.invoice_status(&id).await.unwrap();
        assert_eq!(s["status"], "paid");
        let token = s["token"].as_str().unwrap().to_owned();
        assert_eq!(token, b.derived_token(&id));
        let p = store.authenticate(&token_hash(&token)).unwrap();
        assert_eq!(p.tier, Tier::Pro);
        let until = store.valid_until(&token_hash(&token)).unwrap().unwrap();
        assert!(until >= now + 2 * MONTH_SECS - 5 && until <= now + 2 * MONTH_SECS + 60);
        // The status can be read again later and still carries the token;
        // nothing raw is in the database.
        assert_eq!(b.invoice_status(&id).await.unwrap()["token"], token);
        let rows: Vec<String> = {
            let conn = store.conn();
            let mut stmt = conn.prepare("SELECT address FROM invoices").unwrap();
            let rows = stmt
                .query_map([], |r| r.get(0))
                .unwrap()
                .map(Result::unwrap)
                .collect();
            rows
        };
        assert_eq!(rows, vec!["8sub1"]);
        let dump = std::fs::read(dir.path().join("b.db")).unwrap();
        assert!(
            !dump.windows(token.len()).any(|w| w == token.as_bytes()),
            "raw token at rest"
        );

        // Renewal: reuses the subaddress, extends the same token.
        let v = b
            .create_invoice(
                &h,
                peer(),
                InvoiceRequest {
                    months: Some(1),
                    renew: Some(token.clone()),
                },
            )
            .await
            .unwrap();
        assert_eq!(v["address"], "8sub1", "same subaddress");
        assert_eq!(v["renewal"], true);
        let rid = v["invoice_id"].as_str().unwrap().to_owned();
        w.transfers.lock().push((1, 60_000_000_000, 12, unix_now()));
        b.check_invoices().await;
        let s = b.invoice_status(&rid).await.unwrap();
        assert_eq!(s["status"], "paid");
        assert!(s.get("token").is_none(), "a renewal reveals nothing");
        let extended = store.valid_until(&token_hash(&token)).unwrap().unwrap();
        assert!(extended >= until + MONTH_SECS - 5, "{extended} vs {until}");
    }

    #[tokio::test]
    async fn wallet_failures_leave_invoices_pending_and_expiry_closes_them() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(SqliteStore::open(Some(&dir.path().join("b.db"))).unwrap());
        let inv = Invoice {
            id: "0".repeat(32),
            subaddr_index: 3,
            address: "8x".into(),
            amount: 1,
            months: 1,
            renew_hash: None,
            created_at: unix_now() - 10,
            expires_at: unix_now() + 100,
            status: InvoiceStatus::Pending,
            received: 0,
            paid_at: None,
        };
        store.create_invoice(&inv).unwrap();
        // The wallet is unreachable: nothing changes, nothing is paid.
        let b = Billing::new(
            cfg(Some("http://127.0.0.1:1/json_rpc".into()), dir.path()),
            Arc::clone(&store),
        )
        .unwrap();
        b.check_invoices().await;
        assert_eq!(
            store.invoice(&inv.id).unwrap().status,
            InvoiceStatus::Pending
        );
        // Past its deadline it expires on the next pass.
        let old = Invoice {
            id: "1".repeat(32),
            expires_at: unix_now() - 1,
            ..inv.clone()
        };
        store.create_invoice(&old).unwrap();
        b.check_invoices().await;
        assert_eq!(
            store.invoice(&old.id).unwrap().status,
            InvoiceStatus::Expired
        );
        assert_eq!(
            b.invoice_status(&old.id).await.unwrap()["status"],
            "expired"
        );
        assert!(matches!(
            b.invoice_status("nope").await,
            Err(Refusal::NotFound)
        ));
        // Without a wallet, invoices are refused but free tokens still work.
        let b = Billing::new(cfg(None, dir.path()), Arc::clone(&store)).unwrap();
        assert!(matches!(
            b.create_invoice(&HeaderMap::new(), peer(), InvoiceRequest::default())
                .await,
            Err(Refusal::Unavailable(_))
        ));
        assert!(b.free_token(&HeaderMap::new(), peer()).await.is_ok());
        // Rotation keeps the old token valid and returns a new one.
        let t = b.free_token(&HeaderMap::new(), peer()).await.unwrap()["token"]
            .as_str()
            .unwrap()
            .to_owned();
        let r = b.rotate(&t).unwrap();
        let t2 = r["token"].as_str().unwrap().to_owned();
        assert_ne!(t, t2);
        assert!(store.authenticate(&token_hash(&t)).is_ok(), "grace");
        assert!(store.authenticate(&token_hash(&t2)).is_ok());
        assert!(matches!(b.rotate("sub_notatoken"), Err(Refusal::NotFound)));
    }

    /// The four routes through the real router: routing beside the RPC
    /// catch-alls, CORS on storefront answers only, preflight, rotation.
    #[tokio::test]
    async fn storefront_routes_answer_through_the_router() {
        use crate::cache::Cache;
        use crate::chain::ChainStore;
        use crate::config::Config;
        use crate::ingress::{router, App};
        use crate::limits::Limiter;
        use crate::metrics::Metrics;
        use crate::upstream::Pool;

        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(SqliteStore::open(Some(&dir.path().join("b.db"))).unwrap());
        let b = Arc::new(Billing::new(cfg(None, dir.path()), Arc::clone(&store)).unwrap());
        let cfg = Config::parse(
            "[probe]\nmin_agree = 1\n[[upstreams]]\nname = \"o\"\nurl = \"http://10.0.0.2:18081\"\nkind = \"owned\"\ntransport = \"http\"\n",
        )
        .unwrap();
        let limiter: Arc<dyn Limiter> = Arc::clone(&store) as Arc<dyn Limiter>;
        let app = Arc::new(App {
            pool: Arc::new(Pool::from_config(&cfg).unwrap()),
            chain: Arc::new(ChainStore::open(None).unwrap()),
            cache: Arc::new(Cache::new(1 << 20)),
            metrics: Arc::new(Metrics::new()),
            billing: Some(b),
            store: Arc::clone(&store) as Arc<dyn TokenStore>,
            limiter,
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                listener,
                router(app).into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap()
        });
        let c = reqwest::Client::new();
        let base = format!("http://{addr}");

        let r = c
            .post(format!("{base}/v1/tokens/free"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        assert_eq!(
            r.headers().get("access-control-allow-origin").unwrap(),
            "https://mnr.network"
        );
        assert_eq!(r.headers().get("cache-control").unwrap(), "no-store");
        let v: Value = r.json().await.unwrap();
        let token = v["token"].as_str().unwrap().to_owned();
        assert!(auth::looks_like_token(&token));

        // Preflight.
        let r = c
            .request(Method::OPTIONS, format!("{base}/v1/invoices"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        assert!(r.headers().contains_key("access-control-allow-methods"));
        // No wallet: invoices are unavailable, with CORS so the page can say so.
        let r = c
            .post(format!("{base}/v1/invoices"))
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 503);
        assert!(r.headers().contains_key("access-control-allow-origin"));
        let r = c
            .get(format!("{base}/v1/invoices/{}", "a".repeat(32)))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 404);
        let r = c
            .get(format!("{base}/v1/invoices/short"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 404);

        // Rotation beside the RPC catch-all; the RPC path still gets 401/503.
        let r = c
            .post(format!("{base}/v1/{token}/rotate"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        let v: Value = r.json().await.unwrap();
        let t2 = v["token"].as_str().unwrap().to_owned();
        assert_ne!(t2, token);
        let r = c
            .get(format!("{base}/v1/{token}/rotate"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 405);
        let r = c
            .post(format!("{base}/v1/{t2}/get_height"))
            .body("{}")
            .send()
            .await
            .unwrap();
        assert!(
            matches!(r.status().as_u16(), 502 | 503),
            "authenticated, but no healthy upstream: {}",
            r.status()
        );
        assert!(
            r.headers().get("access-control-allow-origin").is_none(),
            "RPC answers carry no CORS"
        );
        // Something that is not even token-shaped never reaches rotation.
        let r = c
            .post(format!("{base}/v1/sub_unknown/rotate"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 401);
        // Token-shaped but unknown: nothing to rotate.
        let r = c
            .post(format!("{base}/v1/sub_{}/rotate", "1".repeat(44)))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 404);
    }
}
