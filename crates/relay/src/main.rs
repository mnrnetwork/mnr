//! `mnr-relay` — the Stage 0 verified proxy (`docs/stage0-mvp-plan.md` §6).
//!
//! Week 2: config, upstream pool and prober, ingress with token auth and
//! limits, policy dispatch, passthrough and broadcast. Verification in the
//! request path, the cache and metrics follow in week 3.

#![forbid(unsafe_code)]

mod auth;
mod config;
mod dispatch;
mod ingress;
mod limits;
// Fault recording and the quorum accessor are consumed by verification
// (week 3).
#[allow(dead_code)]
mod upstream;

use std::path::PathBuf;
use std::sync::Arc;

use tracing_subscriber::EnvFilter;

use auth::{MemoryTokenStore, Tier};
use config::Config;
use ingress::App;
use limits::MemoryLimiter;
use upstream::Pool;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        // No request logs: the subscriber never sees paths, tokens or IPs.
        // HTTP-client internals are muted so upstream hosts do not land in
        // the log next to anything else.
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,reqwest=warn,hyper_util=warn".into()),
        )
        .init();

    let args = Args::parse().unwrap_or_else(|why| {
        eprintln!("{why}\nusage: mnr-relay --config relay.toml [--dev-token <token>[:pro]]...");
        std::process::exit(2);
    });
    let cfg = match Config::load(&args.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    let pool = Arc::new(Pool::from_config(&cfg).expect("http client"));
    tracing::info!(
        upstreams = pool.upstreams.len(),
        user_agent = cfg.user_agent(),
        "mnr-relay {} starting",
        env!("CARGO_PKG_VERSION")
    );

    // Dev tokens live in memory only; the SQLite store replaces this.
    let mut store = MemoryTokenStore::new();
    for (token, tier) in &args.dev_tokens {
        let p = store.insert(token, *tier);
        tracing::info!(handle = %p.handle, tier = tier.label(), "dev token registered");
    }
    if args.dev_tokens.is_empty() {
        tracing::warn!("no token store configured: every request will be refused with 401");
    }

    // First probe round before serving so the status feed is never empty.
    pool.probe_all().await;
    tokio::spawn(Arc::clone(&pool).run_prober());

    let app = Arc::new(App {
        pool,
        store: Arc::new(store),
        limiter: Arc::new(MemoryLimiter::new()),
    });
    let listener = tokio::net::TcpListener::bind(cfg.listen)
        .await
        .expect("bind listen address");
    tracing::info!(listen = %cfg.listen, "listening");
    axum::serve(listener, ingress::router(app))
        .await
        .expect("serve");
}

struct Args {
    config: PathBuf,
    dev_tokens: Vec<(String, Tier)>,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let mut config = None;
        let mut dev_tokens = Vec::new();
        let mut args = std::env::args().skip(1);
        while let Some(a) = args.next() {
            match a.as_str() {
                "--config" => config = args.next().map(PathBuf::from),
                "--dev-token" => {
                    let v = args.next().ok_or("--dev-token needs a value")?;
                    let (token, tier) = match v.strip_suffix(":pro") {
                        Some(t) => (t.to_owned(), Tier::Pro),
                        None => (v.strip_suffix(":free").unwrap_or(&v).to_owned(), Tier::Free),
                    };
                    if !auth::looks_like_token(&token) {
                        return Err("--dev-token must be `sub_` + base58 of 32 bytes".into());
                    }
                    dev_tokens.push((token, tier));
                }
                other => {
                    if let Some(p) = other.strip_prefix("--config=") {
                        config = Some(PathBuf::from(p));
                    } else {
                        return Err(format!("unknown argument {other}"));
                    }
                }
            }
        }
        Ok(Self {
            config: config.ok_or("--config is required")?,
            dev_tokens,
        })
    }
}
