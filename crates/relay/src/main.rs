//! `mnr-relay` — the Stage 0 verified proxy (`docs/stage0-mvp-plan.md` §6).
//!
//! Week 2 slice: config, upstream pool, prober, ranking, quorum tip, degraded
//! mode, and the status feed for the public upstreams page. RPC ingress,
//! auth, limits and dispatch follow.

#![forbid(unsafe_code)]

mod config;
// Ranking and fault recording are consumed by dispatch (next slice).
#[allow(dead_code)]
mod upstream;

use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use tracing_subscriber::EnvFilter;

use config::Config;
use upstream::{Pool, PoolStatus};

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

    let path = config_path().unwrap_or_else(|| {
        eprintln!("usage: mnr-relay --config relay.toml");
        std::process::exit(2);
    });
    let cfg = match Config::load(&path) {
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

    // First probe round before serving so the status feed is never empty.
    pool.probe_all().await;
    tokio::spawn(Arc::clone(&pool).run_prober());

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/upstreams.json", get(upstreams))
        .with_state(pool);

    let listener = tokio::net::TcpListener::bind(cfg.listen)
        .await
        .expect("bind listen address");
    tracing::info!(listen = %cfg.listen, "listening");
    axum::serve(listener, app).await.expect("serve");
}

fn config_path() -> Option<PathBuf> {
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--config" {
            return args.next().map(PathBuf::from);
        }
        if let Some(p) = a.strip_prefix("--config=") {
            return Some(PathBuf::from(p));
        }
    }
    None
}

async fn healthz(State(pool): State<Arc<Pool>>) -> (axum::http::StatusCode, &'static str) {
    if pool.degraded() {
        (axum::http::StatusCode::SERVICE_UNAVAILABLE, "degraded")
    } else {
        (axum::http::StatusCode::OK, "ok")
    }
}

async fn upstreams(State(pool): State<Arc<Pool>>) -> Json<PoolStatus> {
    Json(pool.status())
}
