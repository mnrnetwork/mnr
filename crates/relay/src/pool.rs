//! The composed mempool listing (`docs/stage0-mvp-plan.md` §10 decision 8):
//! `/get_transaction_pool` answered by the relay from parts it can check.
//!
//! monerod serves the full pool dump only in unrestricted mode (from commit
//! 57ae55e on), so no public node offers it. The relay builds the same
//! shape itself: the pool *listing* from one upstream
//! (`/get_transaction_pool_hashes`, the relay's own node first because it
//! sees every broadcast the relay relays), then every transaction through
//! the hash-verified `/get_transactions` path. `blob_size`, `weight`, `fee`
//! and the key images are recomputed from the verified blob by
//! `mnr_core::hash::parse_tx`; `tx_json` is the node's rendering of that
//! blob and is passed through as such; `receive_time` is the moment the
//! relay first saw the hash in a listing, never a node's claim; the fields
//! a daemon fills from its own pool state are zero, false or empty.
//!
//! Verified transactions are kept by txid in the cache's pool tier for ten
//! minutes, so a client polling every few seconds pays the listing plus one
//! light call per transaction it has not seen before (charged as extra work
//! units, decision 8). Membership is never read from the tier: only the
//! fresh listing says what is in the pool now.

use std::collections::HashMap;
use std::time::Duration;

use bytes::Bytes;
use mnr_core::hash::{parse_tx, ParsedTx};
use mnr_core::wire::decode_hex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::cache::{Cache, Status};
use crate::dispatch::{self, Ctx, Outcome, Request};
use crate::upstream::Work;
use crate::verify::Verify;

/// monerod's restricted-mode ceiling on hashes per `/get_transactions`.
const BATCH: usize = 100;

/// One verified pool transaction as the tier stores it.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PoolTx {
    id_hash: String,
    tx_blob: String,
    tx_json: String,
    blob_size: u64,
    weight: u64,
    fee: u64,
    key_images: Vec<String>,
    relayed: bool,
    double_spend_seen: bool,
    /// Unix seconds when the relay first saw this hash in a listing.
    first_seen: u64,
}

impl PoolTx {
    fn from_entry(entry: &Value, parsed: &ParsedTx, blob_hex: &str, now: u64) -> Self {
        Self {
            id_hash: hex(&parsed.hash),
            tx_blob: blob_hex.to_owned(),
            tx_json: entry
                .get("as_json")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
            blob_size: parsed.blob_size,
            weight: parsed.weight,
            fee: parsed.fee.unwrap_or(0),
            key_images: parsed.key_images.iter().map(hex).collect(),
            relayed: entry
                .get("relayed")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            double_spend_seen: entry
                .get("double_spend_seen")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            first_seen: now,
        }
    }

    /// The `transactions[]` object monerod would serve.
    fn render(&self) -> Value {
        json!({
            "id_hash": self.id_hash,
            "tx_json": self.tx_json,
            "blob_size": self.blob_size,
            "weight": self.weight,
            "fee": self.fee,
            "max_used_block_id_hash": "",
            "max_used_block_height": 0,
            "kept_by_block": false,
            "last_failed_height": 0,
            "last_failed_id_hash": "0000000000000000000000000000000000000000000000000000000000000000",
            "receive_time": self.first_seen,
            "relayed": self.relayed,
            "last_relayed_time": 0,
            "do_not_relay": false,
            "double_spend_seen": self.double_spend_seen,
            "tx_blob": self.tx_blob,
        })
    }
}

fn hex(h: &[u8; 32]) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

fn header<'a>(o: &'a Outcome, name: &str) -> Option<&'a str> {
    o.headers
        .iter()
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.as_str())
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Serve `/get_transaction_pool` composed from the listing and verified
/// transactions. Errors from either upstream call are the client's answer
/// (a poll retries in seconds; a shrunken pool would mislead).
pub(crate) async fn compose(ctx: Ctx, req: Request, timeout: Duration) -> Outcome {
    let listing = dispatch::read(
        &ctx.pool,
        "/get_transaction_pool_hashes",
        "application/json",
        Bytes::from_static(b"{}"),
        timeout,
        Work::Sensitive,
    )
    .await;
    if listing.status != 200 {
        return listing;
    }
    let upstream = header(&listing, "Mnr-Upstream").map(str::to_owned);
    let parsed: Value = match serde_json::from_slice(&listing.body) {
        Ok(v) => v,
        Err(_) => return Outcome::json_error(502, "pool listing is not JSON", Verify::None),
    };
    let mut hashes: Vec<String> = Vec::new();
    for h in parsed
        .get("tx_hashes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        let h = h.to_ascii_lowercase();
        if !hashes.contains(&h) {
            hashes.push(h);
        }
    }

    let now = unix_now();
    let mut entries: HashMap<String, PoolTx> = HashMap::new();
    let mut misses: Vec<String> = Vec::new();
    for h in &hashes {
        match ctx.cache.pool_get(&Cache::pool_key(h)).await {
            Some(bytes) => match serde_json::from_slice::<PoolTx>(&bytes) {
                Ok(t) => {
                    entries.insert(h.clone(), t);
                }
                Err(_) => misses.push(h.clone()),
            },
            None => misses.push(h.clone()),
        }
    }
    // Entries from the tier and from fully verified batches count as
    // verified (k); dropped entries and entries of a partial batch count
    // toward n only.
    let mut verified = entries.len();
    let mut total = entries.len();

    for chunk in misses.chunks(BATCH) {
        let body = json!({ "txs_hashes": chunk, "decode_as_json": true });
        let fetched = dispatch::transactions(
            ctx.clone(),
            Request {
                path: "/get_transactions",
                method: "/get_transactions".into(),
                params: None,
                id: Value::Null,
                content_type: "application/json",
                body: Bytes::from(body.to_string()),
                tier: req.tier,
            },
            timeout,
        )
        .await;
        if fetched.status != 200 {
            return fetched;
        }
        let all_verified = header(&fetched, "Mnr-Verify") == Some(Verify::Hash.label());
        let answer: Value = match serde_json::from_slice(&fetched.body) {
            Ok(v) => v,
            Err(_) => return Outcome::json_error(502, "transactions are not JSON", Verify::None),
        };
        for entry in answer
            .get("txs")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            // Mined between the two calls: no longer in the pool, dropped
            // without counting (nothing about it was unverified).
            if entry.get("in_pool").and_then(Value::as_bool) != Some(true) {
                continue;
            }
            // From here an entry counts toward n; only a verified, parsed
            // one counts toward k.
            total += 1;
            let Some(blob_hex) = entry.get("as_hex").and_then(Value::as_str) else {
                continue;
            };
            let Ok(blob) = decode_hex(blob_hex) else {
                continue;
            };
            let Ok(parsed) = parse_tx(&blob) else {
                continue;
            };
            let id = hex(&parsed.hash);
            if !chunk.contains(&id) {
                continue;
            }
            let tx = PoolTx::from_entry(entry, &parsed, blob_hex, now);
            if all_verified {
                verified += 1;
                if let Ok(bytes) = serde_json::to_vec(&tx) {
                    ctx.cache
                        .pool_put(Cache::pool_key(&id), Bytes::from(bytes))
                        .await;
                }
            }
            entries.insert(id, tx);
        }
    }

    let mut transactions = Vec::with_capacity(entries.len());
    let mut spent: Vec<(String, Vec<String>)> = Vec::new();
    for h in &hashes {
        let Some(t) = entries.get(h) else { continue };
        transactions.push(t.render());
        for ki in &t.key_images {
            match spent.iter_mut().find(|(k, _)| k == ki) {
                Some((_, txs)) => txs.push(t.id_hash.clone()),
                None => spent.push((ki.clone(), vec![t.id_hash.clone()])),
            }
        }
    }
    let spent_key_images: Vec<Value> = spent
        .into_iter()
        .map(|(id_hash, txs_hashes)| json!({ "id_hash": id_hash, "txs_hashes": txs_hashes }))
        .collect();
    let body = json!({
        "credits": 0,
        "spent_key_images": spent_key_images,
        "status": "OK",
        "top_hash": "",
        "transactions": transactions,
        "untrusted": true,
    });

    let label = if verified == total {
        Verify::Hash
    } else if verified > 0 {
        Verify::Partial
    } else {
        Verify::None
    };
    let mut headers = vec![
        ("Mnr-Verify", label.label().to_owned()),
        ("Mnr-Cache", Status::Bypass.label().to_owned()),
    ];
    if let Some(u) = upstream {
        headers.push(("Mnr-Upstream", u));
    }
    if label == Verify::Partial {
        headers.push(("Mnr-Verified", format!("{verified}/{total}")));
    }
    let mut o = Outcome::json_ok(body.to_string(), headers);
    o.extra_wu = misses.len() as u64;
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Tier;
    use crate::chain::ChainStore;
    use crate::config::Config;
    use crate::upstream::{Health, Pool};
    use axum::body::Bytes as AxBytes;
    use axum::extract::Path;
    use axum::routing::post;
    use axum::Router;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    const TXS_A: &str = include_str!("../../core/fixtures/mainnet/txs-3754000-prune-false.json");
    const TXS_B: &str = include_str!("../../core/fixtures/mainnet/txs-2689608-prune-false.json");
    const POOL_ENTRY: &str = include_str!("../../core/fixtures/mainnet/pool-entries.json");

    /// `txid → (as_hex, as_json)` of every full fixture transaction, posing
    /// as pool transactions.
    fn blobs() -> Vec<(String, String, String)> {
        let mut out = Vec::new();
        for fx in [TXS_A, TXS_B] {
            let v: Value = serde_json::from_str(fx).unwrap();
            for t in v["txs"].as_array().unwrap() {
                out.push((
                    t["tx_hash"].as_str().unwrap().to_owned(),
                    t["as_hex"].as_str().unwrap().to_owned(),
                    t["as_json"].as_str().unwrap_or("").to_owned(),
                ));
            }
        }
        let p: Value = serde_json::from_str(POOL_ENTRY).unwrap();
        let t = &p["transactions"][0];
        out.push((
            t["id_hash"].as_str().unwrap().to_owned(),
            t["tx_blob"].as_str().unwrap().to_owned(),
            t["tx_json"].as_str().unwrap().to_owned(),
        ));
        out
    }

    struct Node {
        /// What `/get_transaction_pool_hashes` lists.
        listing: Vec<String>,
        /// Hashes answered as already mined (`in_pool: false`).
        mined: Vec<String>,
        /// Flip a byte of every blob (a lying node).
        tamper: bool,
        calls: Arc<AtomicUsize>,
        tx_calls: Arc<AtomicUsize>,
    }

    fn handler(n: Arc<Node>) -> impl Fn(&str, &[u8]) -> (u16, String) + Send + Sync {
        move |path, body| {
            n.calls.fetch_add(1, Ordering::SeqCst);
            match path {
                "/get_transaction_pool_hashes" => (
                    200,
                    json!({"credits": 0, "status": "OK", "top_hash": "", "tx_hashes": n.listing, "untrusted": true}).to_string(),
                ),
                "/get_transactions" => {
                    n.tx_calls.fetch_add(1, Ordering::SeqCst);
                    let req: Value = serde_json::from_slice(body).unwrap();
                    assert_eq!(req["decode_as_json"], true);
                    let want: Vec<String> = req["txs_hashes"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|h| h.as_str().unwrap().to_owned())
                        .collect();
                    assert!(want.len() <= BATCH);
                    let known = blobs();
                    let mut txs = Vec::new();
                    let mut as_hex = Vec::new();
                    let mut as_json = Vec::new();
                    let mut missed = Vec::new();
                    for h in &want {
                        match known.iter().find(|(id, ..)| id == h) {
                            Some((id, hex, js)) => {
                                let mut hex = hex.clone();
                                if n.tamper {
                                    let i = hex.len() - 12;
                                    let c = if &hex[i..i + 1] == "0" { "1" } else { "0" };
                                    hex.replace_range(i..i + 1, c);
                                }
                                let entry = if n.mined.contains(id) {
                                    json!({"tx_hash": id, "as_hex": hex, "as_json": js, "in_pool": false, "block_height": 3754000, "block_timestamp": 1, "confirmations": 5, "output_indices": [], "double_spend_seen": false, "prunable_as_hex": "", "prunable_hash": "", "pruned_as_hex": ""})
                                } else {
                                    json!({"tx_hash": id, "as_hex": hex, "as_json": js, "in_pool": true, "relayed": true, "received_timestamp": 0, "double_spend_seen": false, "prunable_as_hex": "", "prunable_hash": "", "pruned_as_hex": ""})
                                };
                                txs.push(entry);
                                as_hex.push(Value::String(hex));
                                as_json.push(Value::String(js.clone()));
                            }
                            None => missed.push(Value::String(h.clone())),
                        }
                    }
                    let mut out = json!({"credits": 0, "status": "OK", "top_hash": "", "txs": txs, "txs_as_hex": as_hex, "txs_as_json": as_json, "untrusted": true});
                    if !missed.is_empty() {
                        out["missed_tx"] = Value::Array(missed);
                    }
                    (200, out.to_string())
                }
                other => panic!("unexpected path {other}"),
            }
        }
    }

    async fn serve(n: Arc<Node>) -> SocketAddr {
        let h = Arc::new(handler(n));
        let app = Router::new().route(
            "/{*rest}",
            post(move |Path(rest): Path<String>, body: AxBytes| {
                let h = Arc::clone(&h);
                async move {
                    let (status, body) = h(&format!("/{rest}"), &body);
                    (axum::http::StatusCode::from_u16(status).unwrap(), body)
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        addr
    }

    fn node(listing: Vec<String>) -> Arc<Node> {
        Arc::new(Node {
            listing,
            mined: Vec::new(),
            tamper: false,
            calls: Arc::new(AtomicUsize::new(0)),
            tx_calls: Arc::new(AtomicUsize::new(0)),
        })
    }

    async fn env(nodes: &[Arc<Node>]) -> Ctx {
        let mut toml = String::from("[probe]\nmin_agree = 1\n");
        let mut health = Vec::new();
        for (i, n) in nodes.iter().enumerate() {
            let addr = serve(Arc::clone(n)).await;
            let kind = if i == 0 { "owned" } else { "public" };
            toml.push_str(&format!(
                "[[upstreams]]\nname = \"m{i}\"\nurl = \"http://{addr}\"\nkind = \"{kind}\"\ntransport = \"http\"\ncaps = {{ rps_light = 100, max_streams = 2, mbps = 10 }}\n"
            ));
            let mut h = Health::healthy_for_test(3_760_001, [7; 32]);
            h.rtt_ema_ms = Some(10.0 + i as f64);
            health.push(h);
        }
        let pool = Pool::from_config(&Config::parse(&toml).unwrap()).unwrap();
        pool.set_for_test(health, Some((3_760_000, [7; 32])));
        Ctx {
            pool: Arc::new(pool),
            chain: Arc::new(ChainStore::open(None).unwrap()),
            cache: Arc::new(Cache::new(1 << 24)),
        }
    }

    async fn call(ctx: &Ctx) -> Outcome {
        let policy = mnr_core::policy::lookup("/get_transaction_pool").unwrap();
        dispatch::dispatch(
            ctx.clone(),
            policy,
            Request {
                path: "/get_transaction_pool",
                method: "/get_transaction_pool".into(),
                params: None,
                id: Value::Null,
                content_type: "application/json",
                body: Bytes::from_static(b"{}"),
                tier: Tier::Pro,
            },
        )
        .await
    }

    fn body(o: &Outcome) -> Value {
        serde_json::from_slice(&o.body).unwrap()
    }

    #[tokio::test]
    async fn pool_is_composed_from_verified_transactions_and_then_served_from_the_tier() {
        let known = blobs();
        let listing: Vec<String> = known.iter().map(|(id, ..)| id.clone()).collect();
        let n = node(listing.clone());
        let ctx = env(&[Arc::clone(&n)]).await;
        let o = call(&ctx).await;
        assert_eq!(o.status, 200, "{}", String::from_utf8_lossy(&o.body));
        assert_eq!(header(&o, "Mnr-Verify"), Some("hash"));
        assert_eq!(header(&o, "Mnr-Cache"), Some("bypass"));
        assert_eq!(header(&o, "Mnr-Upstream"), Some("0"));
        assert_eq!(
            o.extra_wu,
            listing.len() as u64,
            "one light call per new tx"
        );
        assert_eq!(n.calls.load(Ordering::SeqCst), 2, "listing + one batch");
        let v = body(&o);
        let txs = v["transactions"].as_array().unwrap();
        assert_eq!(txs.len(), listing.len());
        for (t, (id, hex, js)) in txs.iter().zip(&known) {
            assert_eq!(t["id_hash"], *id, "listing order kept");
            assert_eq!(t["tx_blob"], *hex);
            assert_eq!(t["tx_json"], *js);
            let p = parse_tx(&decode_hex(hex).unwrap()).unwrap();
            assert_eq!(t["blob_size"], p.blob_size);
            assert_eq!(t["weight"], p.weight);
            assert_eq!(t["fee"], p.fee.unwrap());
            assert_eq!(
                t["receive_time"].as_u64().unwrap(),
                unix_now(),
                "first seen now"
            );
            assert_eq!(t["last_relayed_time"], 0);
            assert_eq!(t["kept_by_block"], false);
        }
        // The node's own spent_key_images entry for the pool fixture is
        // reproduced from the parsed inputs.
        let fx: Value = serde_json::from_str(POOL_ENTRY).unwrap();
        let want = &fx["spent_key_images"][0];
        let spent = v["spent_key_images"].as_array().unwrap();
        assert!(spent.iter().any(|s| s == want), "{spent:?}");
        assert_eq!(
            spent.len(),
            known
                .iter()
                .map(|(_, hex, _)| parse_tx(&decode_hex(hex).unwrap())
                    .unwrap()
                    .key_images
                    .len())
                .sum::<usize>(),
            "one entry per key image, none shared"
        );
        assert_eq!(v["status"], "OK");
        assert_eq!(v["untrusted"], true);
        // The upstream was credited once per verified answer.
        assert_eq!(ctx.pool.status().upstreams[0].verified, 1);

        // Second poll: the listing only; every transaction from the tier.
        let first_seen = txs[0]["receive_time"].as_u64().unwrap();
        let o = call(&ctx).await;
        assert_eq!(header(&o, "Mnr-Verify"), Some("hash"));
        assert_eq!(o.extra_wu, 0);
        assert_eq!(n.calls.load(Ordering::SeqCst), 3);
        let v = body(&o);
        assert_eq!(v["transactions"].as_array().unwrap().len(), listing.len());
        assert_eq!(v["transactions"][0]["receive_time"], first_seen);
        let [_, _, _, (tier, entries, _)] = ctx.cache.stats().await;
        assert_eq!((tier, entries), ("pool", listing.len() as u64));
    }

    #[tokio::test]
    async fn mined_and_missing_transactions_are_dropped_without_counting() {
        let known = blobs();
        let mut listing: Vec<String> = known.iter().map(|(id, ..)| id.clone()).collect();
        listing.push("ab".repeat(32)); // unknown to the node: missed_tx
        let mut n = Node {
            listing: listing.clone(),
            mined: vec![known[0].0.clone()],
            tamper: false,
            calls: Arc::new(AtomicUsize::new(0)),
            tx_calls: Arc::new(AtomicUsize::new(0)),
        };
        n.mined.push(known[1].0.clone());
        let ctx = env(&[Arc::new(n)]).await;
        let o = call(&ctx).await;
        assert_eq!(o.status, 200);
        assert_eq!(header(&o, "Mnr-Verify"), Some("hash"), "nothing unverified");
        let v = body(&o);
        let ids: Vec<&str> = v["transactions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["id_hash"].as_str().unwrap())
            .collect();
        assert_eq!(ids.len(), known.len() - 2);
        assert!(!ids.contains(&known[0].0.as_str()));
        assert!(!ids.contains(&known[1].0.as_str()));
        assert!(!ids.contains(&"ab".repeat(32).as_str()));
        assert_eq!(o.extra_wu, listing.len() as u64, "every miss was fetched");
    }

    #[tokio::test]
    async fn a_lying_node_is_faulted_and_the_next_one_answers() {
        let known = blobs();
        let listing: Vec<String> = known.iter().map(|(id, ..)| id.clone()).collect();
        let liar = Arc::new(Node {
            listing: listing.clone(),
            mined: Vec::new(),
            tamper: true,
            calls: Arc::new(AtomicUsize::new(0)),
            tx_calls: Arc::new(AtomicUsize::new(0)),
        });
        let honest = node(listing.clone());
        let ctx = env(&[Arc::clone(&liar), Arc::clone(&honest)]).await;
        let o = call(&ctx).await;
        assert_eq!(o.status, 200, "{}", String::from_utf8_lossy(&o.body));
        assert_eq!(header(&o, "Mnr-Verify"), Some("hash"));
        assert_eq!(
            body(&o)["transactions"].as_array().unwrap().len(),
            listing.len()
        );
        assert_eq!(liar.tx_calls.load(Ordering::SeqCst), 1);
        assert_eq!(honest.tx_calls.load(Ordering::SeqCst), 1);
        let s = ctx.pool.status();
        assert_eq!(s.upstreams[0].faults, 1);
        assert_eq!(s.upstreams[1].verified, 1);
        assert_eq!(s.faults[0].method, "/get_transactions");
    }

    #[tokio::test]
    async fn misses_are_fetched_in_batches_of_one_hundred() {
        let known = blobs();
        let mut listing: Vec<String> = known.iter().map(|(id, ..)| id.clone()).collect();
        for i in 0..(150 - listing.len()) {
            listing.push(format!("{i:064x}"));
        }
        let n = node(listing.clone());
        let ctx = env(&[Arc::clone(&n)]).await;
        let o = call(&ctx).await;
        assert_eq!(o.status, 200);
        assert_eq!(n.tx_calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            body(&o)["transactions"].as_array().unwrap().len(),
            known.len()
        );
        assert_eq!(o.extra_wu, 150);
    }

    #[tokio::test]
    async fn empty_pool_is_an_empty_verified_listing() {
        let n = node(Vec::new());
        let ctx = env(&[n]).await;
        let o = call(&ctx).await;
        assert_eq!(o.status, 200);
        assert_eq!(header(&o, "Mnr-Verify"), Some("hash"));
        let v = body(&o);
        assert_eq!(v["transactions"], json!([]));
        assert_eq!(v["spent_key_images"], json!([]));
        assert_eq!(o.extra_wu, 0);
    }
}
