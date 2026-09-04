//! `mnr-relay` binary: config, wiring, and the `token` management
//! subcommand. Everything else lives in the library (see `lib.rs`).

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::Arc;

use tracing_subscriber::EnvFilter;

use mnr_relay::auth::{self, MemoryTokenStore, Tier, TokenStore};
use mnr_relay::cache::Cache;
use mnr_relay::chain::ChainStore;
use mnr_relay::config::Config;
use mnr_relay::ingress::{self, App};
use mnr_relay::limits::{Limiter, MemoryLimiter};
use mnr_relay::metrics::{self, Metrics};
use mnr_relay::store::SqliteStore;
use mnr_relay::upstream::Pool;

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

    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("token") {
        run_token_command(&args[1..]);
        return;
    }
    let args = Args::parse(&args).unwrap_or_else(|why| {
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

    let (store, limiter): (Arc<dyn TokenStore>, Arc<dyn Limiter>) = match &cfg.auth.database {
        Some(db) => {
            if !args.dev_tokens.is_empty() {
                eprintln!("--dev-token cannot be combined with [auth] database");
                std::process::exit(2);
            }
            let s = Arc::new(SqliteStore::open(Some(db)).unwrap_or_else(|e| {
                eprintln!("{e}");
                std::process::exit(1);
            }));
            s.clone().run_flusher();
            (s.clone(), s)
        }
        None => {
            // Dev tokens live in memory only.
            let mut store = MemoryTokenStore::new();
            for (token, tier) in &args.dev_tokens {
                let p = store.insert(token, *tier);
                tracing::info!(handle = %p.handle, tier = tier.label(), "dev token registered");
            }
            if args.dev_tokens.is_empty() {
                tracing::warn!("no token store configured: every request will be refused with 401");
            }
            (Arc::new(store), Arc::new(MemoryLimiter::new()))
        }
    };

    let chain = Arc::new(
        ChainStore::open(cfg.chain.path.as_deref()).unwrap_or_else(|e| {
            eprintln!("{e}");
            std::process::exit(1);
        }),
    );
    if cfg.chain.path.is_none() {
        tracing::warn!(
            "no [chain] path: the header chain is rebuilt from the upstreams on every start"
        );
    }

    // First probe round before serving so the status feed is never empty.
    pool.probe_all().await;
    tokio::spawn(Arc::clone(&pool).run_prober());
    tokio::spawn(Arc::clone(&pool).run_opt_out_checker());
    tokio::spawn(Arc::clone(&chain).run_sync(Arc::clone(&pool), cfg.chain.batch));

    let cache = Arc::new(Cache::new(cfg.cache.max_bytes));
    let metrics = Arc::new(Metrics::new());
    if let Some(listen) = cfg.metrics.listen {
        tokio::spawn(metrics::serve(
            listen,
            Arc::new(metrics::Exporter {
                metrics: Arc::clone(&metrics),
                pool: Arc::clone(&pool),
                chain: Arc::clone(&chain),
                cache: Arc::clone(&cache),
            }),
        ));
    }

    let app = Arc::new(App {
        pool,
        chain,
        cache,
        metrics,
        store,
        limiter,
    });
    let listener = tokio::net::TcpListener::bind(cfg.listen)
        .await
        .expect("bind listen address");
    tracing::info!(listen = %cfg.listen, "listening");
    axum::serve(listener, ingress::router(app))
        .await
        .expect("serve");
}

/// `mnr-relay token issue|rotate|suspend|list ...` — management commands.
/// Issue and rotate print the raw token to stdout exactly once and nothing
/// else; suspend prints nothing on success. Errors go to stderr and exit 1.
fn run_token_command(args: &[String]) {
    let sub = match args.first().map(String::as_str) {
        Some(s) => s,
        None => {
            eprintln!("token requires a subcommand: issue|rotate|suspend|list");
            std::process::exit(2);
        }
    };
    let mut config = None;
    let mut tier = None;
    let mut days = None;
    let mut handle = None;
    let mut i = 1;
    while i < args.len() {
        let flag = args[i].as_str();
        let value = |i: &mut usize| -> String {
            *i += 1;
            args.get(*i).cloned().unwrap_or_else(|| {
                eprintln!("{flag} needs a value");
                std::process::exit(2);
            })
        };
        match flag {
            "--config" => config = Some(PathBuf::from(value(&mut i))),
            "--tier" => tier = Some(value(&mut i)),
            "--days" => days = Some(value(&mut i)),
            "--handle" => handle = Some(value(&mut i)),
            f if f.starts_with("--config=") => {
                config = Some(PathBuf::from(&f["--config=".len()..]))
            }
            other => {
                eprintln!("unknown token argument {other}");
                std::process::exit(2);
            }
        }
        i += 1;
    }
    let config = config.unwrap_or_else(|| {
        eprintln!("token subcommand requires --config");
        std::process::exit(2);
    });
    let cfg = match Config::load(&config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    let db = match cfg.auth.database.as_deref() {
        Some(db) => db,
        None => {
            eprintln!("token subcommand requires [auth] database in the config");
            std::process::exit(1);
        }
    };
    let store = match SqliteStore::open(Some(db)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    match sub {
        "issue" => {
            let tier = match tier.as_deref() {
                Some("free") => Tier::Free,
                Some("pro") => Tier::Pro,
                _ => {
                    eprintln!("token issue requires --tier free|pro");
                    std::process::exit(2);
                }
            };
            let valid_until = days.map(|d| {
                let d: u64 = d.parse().unwrap_or_else(|_| {
                    eprintln!("--days must be a number");
                    std::process::exit(2);
                });
                now_secs() + d * 86_400
            });
            println!("{}", store.issue(tier, valid_until));
        }
        "rotate" => {
            let handle = handle.unwrap_or_else(|| {
                eprintln!("token rotate requires --handle");
                std::process::exit(2);
            });
            let hash = match store.find_hash(&handle) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            };
            match store.rotate(&hash) {
                Ok(t) => println!("{t}"),
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            }
        }
        "suspend" => {
            let handle = handle.unwrap_or_else(|| {
                eprintln!("token suspend requires --handle");
                std::process::exit(2);
            });
            let hash = match store.find_hash(&handle) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            };
            if let Err(e) = store.suspend(&hash) {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
        "list" => {
            for t in store.list() {
                let until = t
                    .valid_until
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "-".to_owned());
                println!(
                    "{} {} {} {} {}",
                    t.handle,
                    t.tier.label(),
                    t.status,
                    until,
                    t.wu_used_30d
                );
            }
        }
        other => {
            eprintln!("unknown token subcommand {other}");
            std::process::exit(2);
        }
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

struct Args {
    config: PathBuf,
    dev_tokens: Vec<(String, Tier)>,
}

impl Args {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut config = None;
        let mut dev_tokens = Vec::new();
        let mut iter = args.iter();
        while let Some(a) = iter.next() {
            match a.as_str() {
                "--config" => config = iter.next().map(PathBuf::from),
                "--dev-token" => {
                    let v = iter.next().ok_or("--dev-token needs a value")?;
                    let (token, tier) = match v.strip_suffix(":pro") {
                        Some(t) => (t.to_owned(), Tier::Pro),
                        None => (v.strip_suffix(":free").unwrap_or(v).to_owned(), Tier::Free),
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
