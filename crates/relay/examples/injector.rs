//! A synthetic monerod with fault injection, for the reorg and ejection
//! drill (`docs/stage0-mvp-plan.md` §7 weeks 5–6; `sim/drill.sh`).
//!
//! It serves a deterministic header chain from genesis to `tip` (hashes
//! derived from the height, linkage intact) over the daemon's JSON-RPC and
//! legacy paths, and a synthetic `get_blocks.bin` body. Faults are switched
//! at runtime on `POST /_inject`:
//!
//! - `{"mode":"honest"}` — the canonical chain.
//! - `{"mode":"branch","from":280,"id":1}` — an alternate chain from `from`
//!   up, with its own hashes (the reorg drill: every node switches).
//! - `{"mode":"lie_header","height":200}` — one header answered with a wrong
//!   hash (the ejection drill: one node lies, three times).
//! - `{"mode":"drop_streams"}` — `get_blocks.bin` bodies cut after 64 KB.
//! - any of the above with `"tip": N` to move the tip.
//!
//! Nothing here touches a real node; the drill proves the relay end to end
//! (binary, HTTP, config, verification, cache epoch, ejection, metrics)
//! against behaviour that mainnet would take hours or luck to show.
//!
//! Run: `cargo run -p mnr-relay --release --example injector -- 127.0.0.1:18191`

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{any, post};
use axum::{Json, Router};
use futures_util::stream;
use parking_lot::Mutex;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const GET_INFO: &str = include_str!("../../core/fixtures/mainnet/get_info.json");

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
enum Mode {
    Honest,
    Branch { from: u64, id: u8 },
    LieHeader { height: u64 },
    DropStreams,
}

#[derive(Debug, Clone, Deserialize)]
struct Inject {
    #[serde(flatten)]
    mode: Mode,
    tip: Option<u64>,
}

struct Node {
    mode: Mutex<Mode>,
    tip: Mutex<u64>,
}

fn hash_at(h: u64, mode: &Mode) -> [u8; 32] {
    let branch = match mode {
        Mode::Branch { from, id } if h >= *from => *id,
        _ => 0,
    };
    let mut d = Sha256::new();
    d.update(b"mnr-drill-chain");
    d.update([branch]);
    d.update(h.to_le_bytes());
    d.finalize().into()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn header(h: u64, tip: u64, mode: &Mode) -> Value {
    let mut hash = hash_at(h, mode);
    if let Mode::LieHeader { height } = mode {
        if *height == h {
            hash[0] ^= 0xFF;
        }
    }
    let prev = if h == 0 {
        [0u8; 32]
    } else {
        hash_at(h - 1, mode)
    };
    json!({
        "block_size": 1000, "block_weight": 1000, "cumulative_difficulty": h * 1000, "depth": tip - h,
        "difficulty": 1000, "hash": hex(&hash), "height": h, "major_version": 16,
        "miner_tx_hash": hex(&[0; 32]), "minor_version": 16, "nonce": 0, "num_txes": 0,
        "prev_hash": hex(&prev), "reward": 600000000000u64, "timestamp": 1_700_000_000 + h * 120,
        "orphan_status": false,
    })
}

fn rpc_ok(id: Value, result: Value) -> Response {
    Json(json!({"id": id, "jsonrpc": "2.0", "result": result})).into_response()
}

fn rpc_err(id: Value, msg: &str) -> Response {
    Json(json!({"id": id, "jsonrpc": "2.0", "error": {"code": -1, "message": msg}})).into_response()
}

fn info(tip: u64, mode: &Mode) -> Value {
    let mut v: Value = serde_json::from_str(GET_INFO).unwrap();
    let mut r = v["result"].take();
    r["height"] = json!(tip + 1);
    r["target_height"] = json!(tip + 1);
    r["top_block_hash"] = json!(hex(&hash_at(tip, mode)));
    r["synchronized"] = json!(true);
    r["restricted"] = json!(true);
    r
}

async fn inject(State(n): State<Arc<Node>>, Json(i): Json<Inject>) -> Response {
    if let Some(t) = i.tip {
        *n.tip.lock() = t;
    }
    *n.mode.lock() = i.mode.clone();
    Json(json!({"ok": true, "mode": format!("{:?}", i.mode), "tip": *n.tip.lock()})).into_response()
}

async fn serve(State(n): State<Arc<Node>>, Path(rest): Path<String>, body: Bytes) -> Response {
    let mode = n.mode.lock().clone();
    let tip = *n.tip.lock();
    let path = format!("/{rest}");
    match path.as_str() {
        "/json_rpc" => {
            let req: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            let id = req["id"].clone();
            let p = &req["params"];
            match req["method"].as_str().unwrap_or("") {
                "get_info" => rpc_ok(id, info(tip, &mode)),
                "get_block_count" => rpc_ok(id, json!({"count": tip + 1, "status": "OK", "untrusted": true})),
                "get_last_block_header" => rpc_ok(
                    id,
                    json!({"block_header": header(tip, tip, &mode), "status": "OK", "untrusted": true}),
                ),
                "get_block_header_by_height" => match p["height"].as_u64() {
                    Some(h) if h <= tip => rpc_ok(
                        id,
                        json!({"block_header": header(h, tip, &mode), "status": "OK", "untrusted": true}),
                    ),
                    _ => rpc_err(id, "Requested block height greater than current top block height"),
                },
                "get_block_headers_range" => {
                    let (s, e) = (p["start_height"].as_u64().unwrap_or(0), p["end_height"].as_u64().unwrap_or(0));
                    if e > tip || s > e {
                        return rpc_err(id, "Invalid start/end heights.");
                    }
                    let headers: Vec<Value> = (s..=e).map(|h| header(h, tip, &mode)).collect();
                    rpc_ok(id, json!({"headers": headers, "status": "OK", "untrusted": true}))
                }
                "on_get_block_hash" => match p.as_array().and_then(|a| a.first()).and_then(Value::as_u64) {
                    Some(h) if h <= tip => rpc_ok(id, json!(hex(&hash_at(h, &mode)))),
                    _ => rpc_ok(id, json!(hex(&[0; 32]))),
                },
                "get_version" => rpc_ok(id, json!({"release": true, "status": "OK", "untrusted": true, "version": 196614})),
                "get_fee_estimate" => rpc_ok(
                    id,
                    json!({"fee": 20000, "fees": [20000, 80000, 320000, 4000000], "quantization_mask": 10000, "status": "OK", "untrusted": true}),
                ),
                other => rpc_err(id, &format!("Method not found: {other}")),
            }
        }
        "/get_info" => Json(info(tip, &mode)).into_response(),
        "/get_height" => Json(json!({"hash": hex(&hash_at(tip, &mode)), "height": tip + 1, "status": "OK", "untrusted": true})).into_response(),
        "/get_transaction_pool_stats" => Json(json!({"status": "OK", "untrusted": true, "pool_stats": {"txs_total": 0}})).into_response(),
        "/get_blocks.bin" | "/get_blocks_by_height.bin" | "/get_hashes.bin" => {
            // 2 MB of synthetic body announced either way; in drop mode the
            // connection is cut after the first 64 KB (a short read).
            let chunks = 32;
            let s = stream::iter((0..chunks).map(|_| Ok::<_, std::io::Error>(Bytes::from(vec![0xAB; 65536]))));
            let s = if matches!(mode, Mode::DropStreams) {
                // First chunk on the wire, a beat, then the cut: the client
                // has the headers and 64 KB when the connection dies.
                stream::iter(vec![Ok(Bytes::from(vec![0xAB; 65536]))])
                    .chain(stream::once(async {
                        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                        Err(std::io::Error::other("injected drop"))
                    }))
                    .boxed()
            } else {
                s.boxed()
            };
            Response::builder()
                .status(200)
                .header("content-type", "application/octet-stream")
                .header("content-length", (chunks * 65536).to_string())
                .body(Body::from_stream(s))
                .unwrap()
        }
        _ => (StatusCode::NOT_FOUND, "Not Found").into_response(),
    }
}

use futures_util::StreamExt as _;

#[tokio::main]
async fn main() {
    let listen: SocketAddr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:18191".into())
        .parse()
        .expect("listen address");
    let node = Arc::new(Node {
        mode: Mutex::new(Mode::Honest),
        tip: Mutex::new(300),
    });
    let app = Router::new()
        .route("/_inject", post(inject))
        .route("/{*rest}", any(serve))
        .with_state(node);
    let listener = tokio::net::TcpListener::bind(listen).await.expect("bind");
    eprintln!("injector: synthetic monerod on {listen} (tip 300, honest); POST /_inject to switch");
    axum::serve(listener, app).await.expect("serve");
}
