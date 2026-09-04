//! In-process load test (`docs/stage0-mvp-plan.md` §7 week 4): 500 rps of
//! light calls and 10 concurrent `get_blocks.bin` syncs against the real
//! relay app over a pool of mock upstreams, for 30 s (10 s with `--quick`).
//!
//! What it proves: the relay's own caps hold under load. No public mock is
//! sent more light calls than its `rps_light` allows (any sliding second
//! holds at most twice the rate, the bucket plus one second of refill; the
//! run average stays under the rate), no more than `max_streams` streams at
//! once, and no more bytes than `mbps` over the run. Every response carries
//! `Mnr-Verify` and `Mnr-Cache`. Latency percentiles, the error mix, the
//! cache hit ratio and the work units charged are reported.
//!
//! What it does not prove: a public node's tolerance. The mocks answer
//! instantly from fixtures; the docker stagenet harness (`sim/`) is where
//! real `monerod` behaviour is exercised.
//!
//! The owned mock is capped at 50 light rps on purpose, so that a share of
//! the passthrough traffic overflows to the public mocks and their caps are
//! actually exercised; the excess is refused with 503, which is the
//! designed behaviour (rule 3), and shows up in the error mix.
//!
//! Run: `cargo run -p mnr-relay --release --example load [-- --quick]`.
//! Exit status is non-zero when a cap or header assertion fails.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes as AxBytes};
use axum::extract::Path;
use axum::routing::post;
use axum::Router;
use bytes::Bytes;
use futures_util::stream;
use mnr_relay::auth::{MemoryTokenStore, Tier, TokenStore};
use mnr_relay::cache::Cache;
use mnr_relay::chain::ChainStore;
use mnr_relay::config::Config;
use mnr_relay::ingress::{router, App};
use mnr_relay::limits::{Limiter, MemoryLimiter};
use mnr_relay::metrics::Metrics;
use mnr_relay::upstream::Pool;
use parking_lot::Mutex;
use serde_json::{json, Value};

const GET_INFO: &str = include_str!("../../core/fixtures/mainnet/get_info.json");
const BLOCK1: &str = include_str!("../../core/fixtures/mainnet/block-1.json");
const TXS: &str = include_str!("../../core/fixtures/mainnet/txs-3754000-prune-false.json");

/// Light calls per second the test drives.
const RATE: u64 = 500;
/// Concurrent syncs.
const SYNCS: usize = 10;
/// Stream body served by every mock.
const STREAM_BYTES: usize = 16 * 1024 * 1024;
const CHUNK: usize = 64 * 1024;
/// The owned mock's light cap: low enough that public caps are exercised.
const OWNED_RPS: u32 = 50;
const OWNED_STREAMS: u32 = 4;
const OWNED_MBPS: u32 = 200;
/// Public-node defaults (rule 3).
const PUBLIC_RPS: u32 = 5;
const PUBLIC_STREAMS: u32 = 2;
const PUBLIC_MBPS: u32 = 10;

/// What one mock upstream saw.
#[derive(Default)]
struct Recorder {
    /// Timestamps of light (JSON) requests, probes included.
    light: Mutex<Vec<Instant>>,
    streams_now: AtomicUsize,
    streams_max: AtomicUsize,
}

impl Recorder {
    fn light(&self) {
        self.light.lock().push(Instant::now());
    }

    fn stream_start(self: &Arc<Self>) -> StreamGuard {
        let now = self.streams_now.fetch_add(1, Ordering::SeqCst) + 1;
        self.streams_max.fetch_max(now, Ordering::SeqCst);
        StreamGuard(Arc::clone(self))
    }
}

struct StreamGuard(Arc<Recorder>);

impl Drop for StreamGuard {
    fn drop(&mut self) {
        self.0.streams_now.fetch_sub(1, Ordering::SeqCst);
    }
}

fn fixture_result(fx: &str) -> Value {
    let mut v: Value = serde_json::from_str(fx).unwrap();
    v["result"].take()
}

/// A mock monerod: fixtures for the light calls, a synthetic body for
/// streams, and a recorder for what it was asked.
async fn mock(rec: Arc<Recorder>) -> SocketAddr {
    let app = Router::new().route(
        "/{*rest}",
        post(move |Path(rest): Path<String>, body: AxBytes| {
            let rec = Arc::clone(&rec);
            async move {
                let path = format!("/{rest}");
                if path == "/get_blocks.bin" {
                    let guard = rec.stream_start();
                    let s = stream::unfold((0usize, guard), move |(i, guard)| async move {
                        if i >= STREAM_BYTES / CHUNK {
                            return None;
                        }
                        Some((
                            Ok::<_, std::io::Error>(Bytes::from(vec![0xAB; CHUNK])),
                            (i + 1, guard),
                        ))
                    });
                    return axum::response::Response::builder()
                        .status(200)
                        .header("content-type", "application/octet-stream")
                        .header("content-length", STREAM_BYTES.to_string())
                        .body(Body::from_stream(s))
                        .unwrap();
                }
                rec.light();
                let text = match path.as_str() {
                    "/json_rpc" => {
                        let req: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                        let id = req["id"].clone();
                        let result = match req["method"].as_str().unwrap_or("") {
                            "get_info" => fixture_result(GET_INFO),
                            "get_block" => fixture_result(BLOCK1),
                            "get_block_count" => {
                                json!({"count": fixture_result(GET_INFO)["height"], "status": "OK", "untrusted": true})
                            }
                            _ => {
                                return axum::response::Response::builder()
                                    .status(200)
                                    .header("content-type", "application/json")
                                    .body(Body::from(
                                        json!({"id": id, "jsonrpc": "2.0", "error": {"code": -32601, "message": "Method not found"}}).to_string(),
                                    ))
                                    .unwrap();
                            }
                        };
                        json!({"id": id, "jsonrpc": "2.0", "result": result}).to_string()
                    }
                    "/get_transactions" => {
                        let req: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                        let want: Vec<String> = req["txs_hashes"]
                            .as_array()
                            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect())
                            .unwrap_or_default();
                        let fx: Value = serde_json::from_str(TXS).unwrap();
                        let mut txs = Vec::new();
                        let mut as_hex = Vec::new();
                        for h in &want {
                            if let Some(t) = fx["txs"].as_array().unwrap().iter().find(|t| t["tx_hash"] == *h) {
                                as_hex.push(t["as_hex"].clone());
                                txs.push(t.clone());
                            }
                        }
                        json!({"credits":0,"status":"OK","top_hash":"","txs":txs,"txs_as_hex":as_hex,"untrusted":true}).to_string()
                    }
                    _ => json!({"status": "OK", "untrusted": true, "pool_stats": {"txs_total": 12}}).to_string(),
                };
                axum::response::Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(Body::from(text))
                    .unwrap()
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

/// `sub_` + 44 base58 characters; the suffix makes each one distinct.
fn token(i: usize) -> String {
    const B58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut s = String::from("sub_");
    let mut x = 0x9e37_79b9_7f4a_7c15u64.wrapping_mul(i as u64 + 1);
    for _ in 0..44 {
        s.push(B58[(x % 58) as usize] as char);
        x = x.rotate_left(7).wrapping_add(0x1234_5678);
    }
    s
}

#[derive(Default)]
struct LightStats {
    latencies: Vec<Duration>,
    status: BTreeMap<u16, u64>,
    cache: BTreeMap<String, u64>,
    missing_headers: u64,
}

#[derive(Default)]
struct StreamStats {
    /// `(upstream id, bytes)` per completed or aborted download.
    downloads: Vec<(usize, u64)>,
    errors: u64,
}

/// Longest run of timestamps inside any 1 s sliding window.
fn max_in_any_second(ts: &[Instant]) -> usize {
    let mut best = 0;
    let mut start = 0;
    for (end, t) in ts.iter().enumerate() {
        while t.duration_since(ts[start]) >= Duration::from_secs(1) {
            start += 1;
        }
        best = best.max(end - start + 1);
    }
    best
}

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let i = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[i]
}

#[tokio::main]
async fn main() {
    let quick = std::env::args().any(|a| a == "--quick");
    let run_for = if quick {
        Duration::from_secs(10)
    } else {
        Duration::from_secs(30)
    };

    // Upstreams: one owned, three public.
    let recs: Vec<Arc<Recorder>> = (0..4).map(|_| Arc::new(Recorder::default())).collect();
    let mut addrs = Vec::new();
    for r in &recs {
        addrs.push(mock(Arc::clone(r)).await);
    }
    let mut toml = String::from("[probe]\nmin_agree = 3\n");
    toml.push_str(&format!(
        "[[upstreams]]\nname = \"own\"\nurl = \"http://{}\"\nkind = \"owned\"\ntransport = \"http\"\ncaps = {{ rps_light = {OWNED_RPS}, max_streams = {OWNED_STREAMS}, mbps = {OWNED_MBPS} }}\n",
        addrs[0]
    ));
    for (i, a) in addrs.iter().enumerate().skip(1) {
        toml.push_str(&format!(
            "[[upstreams]]\nname = \"pub{i}\"\nurl = \"http://{a}\"\nkind = \"public\"\ntransport = \"http\"\n"
        ));
    }
    let cfg = Config::parse(&toml).expect("config");
    let pool = Arc::new(Pool::from_config(&cfg).expect("pool"));
    pool.probe_all().await;
    assert!(!pool.degraded(), "mocks must agree on a tip");
    tokio::spawn(Arc::clone(&pool).run_prober());

    // Tokens: 24 pro clients for light calls (25 rps burst each), 4 pro
    // clients for syncs (3 concurrent streams each), 1 free client.
    let mut store = MemoryTokenStore::new();
    let light_tokens: Vec<String> = (0..24).map(token).collect();
    let sync_tokens: Vec<String> = (100..104).map(token).collect();
    let free_token = token(200);
    for t in light_tokens.iter().chain(&sync_tokens) {
        store.insert(t, Tier::Pro);
    }
    store.insert(&free_token, Tier::Free);
    let store: Arc<dyn TokenStore> = Arc::new(store);
    let limiter: Arc<dyn Limiter> = Arc::new(MemoryLimiter::new());
    let metrics = Arc::new(Metrics::new());
    let app = Arc::new(App {
        pool: Arc::clone(&pool),
        chain: Arc::new(ChainStore::open(None).unwrap()),
        cache: Arc::new(Cache::new(1 << 28)),
        metrics: Arc::clone(&metrics),
        store,
        limiter,
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router(app)).await.unwrap() });
    let base = format!("http://{relay}/v1");
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(64)
        .build()
        .unwrap();

    let block1_hash = fixture_result(BLOCK1)["block_header"]["hash"]
        .as_str()
        .unwrap()
        .to_owned();
    let tx_hashes: Vec<String> = serde_json::from_str::<Value>(TXS).unwrap()["txs"]
        .as_array()
        .unwrap()
        .iter()
        .take(2)
        .map(|t| t["tx_hash"].as_str().unwrap().to_owned())
        .collect();

    eprintln!(
        "load: {RATE} rps light + {SYNCS} syncs for {}s against {} (owned cap {OWNED_RPS} rps)",
        run_for.as_secs(),
        relay
    );
    let started = Instant::now();
    let deadline = started + run_for;

    // Syncs run for the whole window alongside the light loop below.
    let streams = Arc::new(Mutex::new(StreamStats::default()));
    let mut sync_tasks = Vec::new();
    for n in 0..SYNCS {
        let tok = sync_tokens[n / 3].clone();
        let url = format!("{base}/{tok}/get_blocks.bin");
        let client = client.clone();
        let streams = Arc::clone(&streams);
        sync_tasks.push(tokio::spawn(async move {
            while Instant::now() < deadline {
                let r = client
                    .post(&url)
                    .header("content-type", "application/octet-stream")
                    .body("{}")
                    .send()
                    .await;
                let Ok(mut resp) = r else {
                    streams.lock().errors += 1;
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                };
                if resp.status() != 200 {
                    streams.lock().errors += 1;
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
                let up: usize = resp
                    .headers()
                    .get("mnr-upstream")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(usize::MAX);
                let mut bytes = 0u64;
                while let Ok(Some(chunk)) = resp.chunk().await {
                    bytes += chunk.len() as u64;
                    if Instant::now() >= deadline {
                        break;
                    }
                }
                streams.lock().downloads.push((up, bytes));
            }
        }));
    }
    // Light traffic.
    let light = Arc::new(Mutex::new(LightStats::default()));
    let mut light_tasks = Vec::new();
    {
        let mut tick = tokio::time::interval(Duration::from_micros(1_000_000 / RATE));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);
        let mut i = 0usize;
        while Instant::now() < deadline {
            tick.tick().await;
            let tok = light_tokens[i % light_tokens.len()].clone();
            let (path, body): (&str, String) = match i % 5 {
                0 | 1 => (
                    "json_rpc",
                    json!({"jsonrpc":"2.0","id":i,"method":"get_info"}).to_string(),
                ),
                2 => (
                    "json_rpc",
                    json!({"jsonrpc":"2.0","id":i,"method":"get_block","params":{"hash":block1_hash}}).to_string(),
                ),
                3 => (
                    "get_transactions",
                    json!({"txs_hashes": tx_hashes}).to_string(),
                ),
                _ => ("get_transaction_pool_stats", "{}".to_owned()),
            };
            let url = format!("{base}/{tok}/{path}");
            let client = client.clone();
            let light = Arc::clone(&light);
            light_tasks.push(tokio::spawn(async move {
                let t0 = Instant::now();
                let r = client
                    .post(url)
                    .header("content-type", "application/json")
                    .body(body)
                    .timeout(Duration::from_secs(5))
                    .send()
                    .await;
                let took = t0.elapsed();
                // Read everything before touching the shared stats: the
                // lock must not be held across an await.
                let seen = match r {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        let h = resp.headers();
                        let annotated = h.contains_key("mnr-verify") && h.contains_key("mnr-cache");
                        let cache = h
                            .get("mnr-cache")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("?")
                            .to_owned();
                        let _ = resp.bytes().await;
                        Some((status, annotated, cache))
                    }
                    Err(_) => None,
                };
                let mut s = light.lock();
                match seen {
                    Some((status, annotated, cache)) => {
                        if !annotated {
                            s.missing_headers += 1;
                        }
                        *s.cache.entry(cache).or_insert(0) += 1;
                        *s.status.entry(status).or_insert(0) += 1;
                    }
                    None => *s.status.entry(0).or_insert(0) += 1,
                }
                s.latencies.push(took);
            }));
            i += 1;
        }
    }

    for t in sync_tasks {
        let _ = t.await;
    }
    for t in light_tasks {
        let _ = t.await;
    }
    let elapsed = started.elapsed();

    // ── Report ──
    let mut failures = Vec::new();
    // Work units first: the render awaits, and the stats locks below are
    // plain mutexes.
    let text = metrics
        .render(&pool, &ChainStore::open(None).unwrap(), &Cache::new(1))
        .await;
    let wu: Vec<&str> = text
        .lines()
        .filter(|l| l.starts_with("mnr_wu_charged_total"))
        .collect();
    let light = std::mem::take(&mut *light.lock());
    let mut lat = light.latencies.clone();
    lat.sort();
    let total = lat.len() as u64;
    let ok = light.status.get(&200).copied().unwrap_or(0);
    eprintln!(
        "\nlight: {total} requests in {:.1}s ({:.0} rps)",
        elapsed.as_secs_f64(),
        total as f64 / elapsed.as_secs_f64()
    );
    let refused = total - ok;
    eprintln!(
        "  p50 {:?}  p95 {:?}  p99 {:?}  max {:?}  (over all {total} answers; {refused} = {:.1}% refused under the caps, by design)",
        percentile(&lat, 0.5),
        percentile(&lat, 0.95),
        percentile(&lat, 0.99),
        lat.last().copied().unwrap_or_default(),
        100.0 * refused as f64 / total.max(1) as f64
    );
    eprintln!(
        "  status: {:?}  (200 = {:.1}%)",
        light.status,
        100.0 * ok as f64 / total.max(1) as f64
    );
    eprintln!("  cache:  {:?}", light.cache);
    if light.missing_headers > 0 {
        failures.push(format!(
            "{} responses without Mnr-Verify/Mnr-Cache",
            light.missing_headers
        ));
    }

    let streams = std::mem::take(&mut *streams.lock());
    let mut per_up: BTreeMap<usize, (u64, u64)> = BTreeMap::new();
    for (up, b) in &streams.downloads {
        let e = per_up.entry(*up).or_insert((0, 0));
        e.0 += 1;
        e.1 += b;
    }
    eprintln!(
        "\nstreams: {} downloads, {} errors",
        streams.downloads.len(),
        streams.errors
    );
    for (up, (n, b)) in &per_up {
        eprintln!(
            "  upstream {up}: {n} downloads, {:.1} MB, {:.2} MB/s over the run",
            *b as f64 / 1e6,
            *b as f64 / 1e6 / elapsed.as_secs_f64()
        );
    }

    eprintln!("\ncaps:");
    for (i, r) in recs.iter().enumerate() {
        let (rps, max_streams, mbps) = if i == 0 {
            (OWNED_RPS, OWNED_STREAMS, OWNED_MBPS)
        } else {
            (PUBLIC_RPS, PUBLIC_STREAMS, PUBLIC_MBPS)
        };
        let ts = r.light.lock().clone();
        let burst = max_in_any_second(&ts);
        let avg = ts.len() as f64 / elapsed.as_secs_f64();
        let smax = r.streams_max.load(Ordering::SeqCst);
        let bytes = per_up.get(&i).map_or(0, |e| e.1) as f64;
        // Bucket capacity is one second of the rate: the run may carry that
        // much on top of rate × time.
        let byte_bound = f64::from(mbps) * 1e6 * (elapsed.as_secs_f64() + 1.0) * 1.05;
        eprintln!(
            "  upstream {i}: light {} calls, max {burst}/s (cap {rps}, burst bound {}), avg {avg:.2}/s; streams max {smax} (cap {max_streams}); {:.1} MB (bound {:.1} MB)",
            ts.len(),
            2 * rps,
            bytes / 1e6,
            byte_bound / 1e6
        );
        if burst > 2 * rps as usize {
            failures.push(format!(
                "upstream {i}: {burst} light calls in one second (cap {rps})"
            ));
        }
        // Probes (every 15 s, no token) add at most a call per 15 s.
        if avg > f64::from(rps) * 1.1 + 0.1 {
            failures.push(format!(
                "upstream {i}: {avg:.2} light calls/s sustained (cap {rps})"
            ));
        }
        if smax > max_streams as usize {
            failures.push(format!(
                "upstream {i}: {smax} concurrent streams (cap {max_streams})"
            ));
        }
        if bytes > byte_bound {
            failures.push(format!(
                "upstream {i}: {:.1} MB streamed (bound {:.1} MB)",
                bytes / 1e6,
                byte_bound / 1e6
            ));
        }
    }
    eprintln!("\nwork units: {}", wu.join("; "));

    if failures.is_empty() {
        eprintln!("\nOK: every cap held and every response was annotated");
    } else {
        eprintln!("\nFAILED:");
        for f in &failures {
            eprintln!("  {f}");
        }
        std::process::exit(1);
    }
}
