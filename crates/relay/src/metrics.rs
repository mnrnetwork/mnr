//! Prometheus metrics on a private listener (`docs/stage0-mvp-plan.md` §6;
//! gateway plan §3.6: aggregate metrics only).
//!
//! Hand-rolled text exposition from atomics and one labelled counter map:
//! no scrape can learn who asked for what. Labels are the policy class,
//! the verification and cache labels, the HTTP status, the tier, and the
//! upstream's *name* (public on the upstreams page anyway). Never a token,
//! a handle, a path or a client address (invariant 6).
//!
//! Series:
//! - `mnr_requests_total{class,verify,cache,status}` — dispatched requests
//! - `mnr_refused_total{reason}` — requests refused before dispatch
//! - `mnr_wu_charged_total{tier}` — work units charged
//! - `mnr_upstream_requests_total{upstream}`, `mnr_upstream_stream_bytes_total{upstream}`,
//!   `mnr_upstream_wu_total{upstream}` (the load figure: RPC calls less probes plus 20 per
//!   MB streamed; its owned/public split is a Stage 1 gate), `mnr_upstream_verified_total{upstream}`,
//!   `mnr_upstream_faults_total{upstream}`, `mnr_upstream_rtt_ms{upstream}`,
//!   `mnr_upstream_healthy{upstream}`, `mnr_upstream_on_tip{upstream}`
//! - `mnr_quorum_height`, `mnr_degraded`, `mnr_chain_height`,
//!   `mnr_chain_epoch`, `mnr_reorgs_total`
//! - `mnr_cache_entries{tier}`, `mnr_cache_bytes{tier}`

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::extract::State;
use axum::routing::get;
use axum::Router;
use parking_lot::Mutex;

use crate::auth::Tier;
use crate::cache::Cache;
use crate::chain::ChainStore;
use crate::upstream::Pool;

/// `(class, verify, cache, status)`: the labels of one request series.
type RequestKey = (&'static str, String, String, u16);

/// Process-wide counters the request path updates.
#[derive(Default)]
pub struct Metrics {
    requests: Mutex<BTreeMap<RequestKey, u64>>,
    /// `reason` → count.
    refused: Mutex<BTreeMap<&'static str, u64>>,
    wu_free: AtomicU64,
    wu_pro: AtomicU64,
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    /// Count one dispatched request by what the client was told about it.
    pub fn request(&self, class: &'static str, verify: &str, cache: &str, status: u16) {
        *self
            .requests
            .lock()
            .entry((class, verify.to_owned(), cache.to_owned(), status))
            .or_insert(0) += 1;
    }

    /// Count one request refused before dispatch (`unauthorized`,
    /// `expired`, `rate_limited`, `quota`, `streams`, `denied`, `bad_request`).
    pub fn refused(&self, reason: &'static str) {
        *self.refused.lock().entry(reason).or_insert(0) += 1;
    }

    pub fn charged(&self, tier: Tier, wu: u64) {
        match tier {
            Tier::Free => &self.wu_free,
            Tier::Pro => &self.wu_pro,
        }
        .fetch_add(wu, Ordering::Relaxed);
    }

    /// The exposition text.
    pub async fn render(&self, pool: &Pool, chain: &ChainStore, cache: &Cache) -> String {
        let mut out = String::with_capacity(4096);

        let _ = writeln!(out, "# TYPE mnr_requests_total counter");
        for ((class, verify, cache, status), n) in self.requests.lock().iter() {
            line(
                &mut out,
                "mnr_requests_total",
                &format!(
                    "class=\"{class}\",verify=\"{}\",cache=\"{}\",status=\"{status}\"",
                    escape(verify),
                    escape(cache)
                ),
                n,
            );
        }
        let _ = writeln!(out, "# TYPE mnr_refused_total counter");
        for (reason, n) in self.refused.lock().iter() {
            line(
                &mut out,
                "mnr_refused_total",
                &format!("reason=\"{reason}\""),
                n,
            );
        }
        let _ = writeln!(out, "# TYPE mnr_wu_charged_total counter");
        line(
            &mut out,
            "mnr_wu_charged_total",
            "tier=\"free\"",
            self.wu_free.load(Ordering::Relaxed),
        );
        line(
            &mut out,
            "mnr_wu_charged_total",
            "tier=\"pro\"",
            self.wu_pro.load(Ordering::Relaxed),
        );

        let status = pool.status();
        for (name, help) in [
            ("mnr_upstream_requests_total", "counter"),
            ("mnr_upstream_stream_bytes_total", "counter"),
            ("mnr_upstream_wu_total", "counter"),
            ("mnr_upstream_verified_total", "counter"),
            ("mnr_upstream_faults_total", "counter"),
            ("mnr_upstream_rtt_ms", "gauge"),
            ("mnr_upstream_healthy", "gauge"),
            ("mnr_upstream_on_tip", "gauge"),
            ("mnr_upstream_ejected", "gauge"),
            ("mnr_upstream_opted_out", "gauge"),
            ("mnr_upstream_up_permille_24h", "gauge"),
        ] {
            let _ = writeln!(out, "# TYPE {name} {help}");
            for u in &status.upstreams {
                let labels = format!("upstream=\"{}\"", escape(&u.name));
                let value: u64 = match name {
                    "mnr_upstream_requests_total" => u.requests,
                    "mnr_upstream_stream_bytes_total" => u.stream_bytes,
                    "mnr_upstream_wu_total" => u.wu,
                    "mnr_upstream_verified_total" => u.verified,
                    "mnr_upstream_faults_total" => u.faults,
                    "mnr_upstream_rtt_ms" => u.rtt_ms.unwrap_or(0),
                    "mnr_upstream_healthy" => u64::from(u.ok && !u.ejected),
                    "mnr_upstream_on_tip" => u64::from(u.on_tip),
                    "mnr_upstream_ejected" => u64::from(u.ejected),
                    "mnr_upstream_opted_out" => u64::from(u.opted_out),
                    _ => u.up_24h.map_or(0, |f| (f * 1000.0).round() as u64),
                };
                line(&mut out, name, &labels, value);
            }
        }

        let _ = writeln!(out, "# TYPE mnr_quorum_height gauge");
        line(
            &mut out,
            "mnr_quorum_height",
            "",
            status.quorum_height.unwrap_or(0),
        );
        let _ = writeln!(out, "# TYPE mnr_degraded gauge");
        line(&mut out, "mnr_degraded", "", u64::from(status.degraded));
        let _ = writeln!(out, "# TYPE mnr_chain_height gauge");
        line(
            &mut out,
            "mnr_chain_height",
            "",
            chain.tip().map_or(0, |t| t.height),
        );
        let _ = writeln!(out, "# TYPE mnr_chain_epoch gauge");
        line(&mut out, "mnr_chain_epoch", "", chain.epoch());
        let _ = writeln!(out, "# TYPE mnr_reorgs_total counter");
        line(&mut out, "mnr_reorgs_total", "", chain.reorgs());

        let _ = writeln!(out, "# TYPE mnr_cache_entries gauge");
        let _ = writeln!(out, "# TYPE mnr_cache_bytes gauge");
        for (tier, entries, bytes) in cache.stats().await {
            line(
                &mut out,
                "mnr_cache_entries",
                &format!("tier=\"{tier}\""),
                entries,
            );
            line(
                &mut out,
                "mnr_cache_bytes",
                &format!("tier=\"{tier}\""),
                bytes,
            );
        }
        out
    }
}

/// One sample line.
fn line(out: &mut String, name: &str, labels: &str, value: impl std::fmt::Display) {
    if labels.is_empty() {
        let _ = writeln!(out, "{name} {value}");
    } else {
        let _ = writeln!(out, "{name}{{{labels}}} {value}");
    }
}

/// Prometheus label escaping.
fn escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// What the `/metrics` handler needs.
pub struct Exporter {
    pub metrics: Arc<Metrics>,
    pub pool: Arc<Pool>,
    pub chain: Arc<ChainStore>,
    pub cache: Arc<Cache>,
    /// The live XMR/USD rate, when the Pro price is billed at one.
    pub price: Option<Arc<crate::price::Price>>,
    /// The storefront, for its take-back counter.
    pub billing: Option<Arc<crate::billing::Billing>>,
}

/// Serve `/metrics` on `listen` (a private address; never the public one).
pub async fn serve(listen: SocketAddr, exporter: Arc<Exporter>) {
    let app = Router::new()
        .route("/metrics", get(handler))
        .with_state(exporter);
    match tokio::net::TcpListener::bind(listen).await {
        Ok(listener) => {
            tracing::info!(listen = %listen, "metrics listening");
            if let Err(e) = axum::serve(listener, app).await {
                tracing::error!(error = %e, "metrics server stopped");
            }
        }
        Err(e) => tracing::error!(error = %e, listen = %listen, "cannot bind metrics listener"),
    }
}

async fn handler(State(x): State<Arc<Exporter>>) -> ([(&'static str, &'static str); 1], String) {
    (
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        {
            let mut out = x.metrics.render(&x.pool, &x.chain, &x.cache).await;
            if let Some(p) = &x.price {
                render_price(&mut out, p);
            }
            if let Some(b) = &x.billing {
                let _ = writeln!(out, "# TYPE mnr_invoice_takebacks_total counter");
                line(&mut out, "mnr_invoice_takebacks_total", "", b.takebacks());
            }
            out
        },
    )
}

/// The XMR/USD rate behind the Pro price: the accepted rate, how many
/// sources agreed in the last round, and how old the rate is.
pub fn render_price(out: &mut String, p: &crate::price::Price) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let _ = writeln!(out, "# TYPE mnr_xmr_usd gauge");
    if let Some(r) = p.rate(now) {
        line(out, "mnr_xmr_usd", "", r.usd_per_xmr);
    }
    let _ = writeln!(out, "# TYPE mnr_price_sources_ok gauge");
    line(out, "mnr_price_sources_ok", "", p.sources_ok());
    let _ = writeln!(out, "# TYPE mnr_price_age_seconds gauge");
    if let Some(age) = p.age(now) {
        line(out, "mnr_price_age_seconds", "", age);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::upstream::Health;

    #[tokio::test]
    async fn exposition_carries_only_aggregate_series() {
        let cfg = Config::parse(
            "[probe]\nmin_agree = 1\n[[upstreams]]\nname = \"own\"\nurl = \"http://10.0.0.2:18081\"\nkind = \"owned\"\ntransport = \"http\"\n",
        )
        .unwrap();
        let pool = Pool::from_config(&cfg).unwrap();
        pool.set_for_test(
            vec![Health::healthy_for_test(101, [7; 32])],
            Some((100, [7; 32])),
        );
        pool.record_fault(0, "get_block", "hash mismatch".into());
        pool.record_verified(0);
        pool.record_verified(0);
        let chain = ChainStore::open(None).unwrap();
        let cache = Cache::new(1 << 20);
        let m = Metrics::new();
        m.request("IMMUTABLE", "chain", "miss", 200);
        m.request("IMMUTABLE", "chain", "miss", 200);
        m.request("SWR", "majority", "hit", 200);
        m.refused("rate_limited");
        m.charged(Tier::Free, 3);
        m.charged(Tier::Pro, 40);
        let text = m.render(&pool, &chain, &cache).await;
        let has = |s: &str| assert!(text.contains(s), "missing {s:?} in:\n{text}");
        has("mnr_requests_total{class=\"IMMUTABLE\",verify=\"chain\",cache=\"miss\",status=\"200\"} 2");
        has("mnr_requests_total{class=\"SWR\",verify=\"majority\",cache=\"hit\",status=\"200\"} 1");
        has("mnr_refused_total{reason=\"rate_limited\"} 1");
        has("mnr_wu_charged_total{tier=\"free\"} 3");
        has("mnr_wu_charged_total{tier=\"pro\"} 40");
        has("mnr_upstream_verified_total{upstream=\"own\"} 2");
        has("mnr_upstream_stream_bytes_total{upstream=\"own\"} 0");
        has("mnr_upstream_wu_total{upstream=\"own\"} 0");
        has("mnr_upstream_faults_total{upstream=\"own\"} 1");
        has("mnr_upstream_healthy{upstream=\"own\"} 1");
        has("mnr_upstream_on_tip{upstream=\"own\"} 1");
        has("mnr_upstream_ejected{upstream=\"own\"} 0");
        has("mnr_upstream_opted_out{upstream=\"own\"} 0");
        has("mnr_quorum_height 100");
        has("mnr_degraded 0");
        has("mnr_chain_height 0");
        has("mnr_reorgs_total 0");
        has("mnr_cache_entries{tier=\"immutable\"} 0");
        has("mnr_cache_bytes{tier=\"swr\"} 0");
        // Nothing that could identify a client or a request.
        for forbidden in ["sub_", "token", "handle", "/v1/", "127.0.0.1"] {
            assert!(!text.contains(forbidden), "{forbidden} leaked into metrics");
        }
        assert_eq!(escape("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
    }

    #[test]
    fn price_gauges_follow_the_accepted_rate() {
        let p = crate::price::Price::new(vec![], "mnr-relay/test", None).unwrap();
        let mut out = String::new();
        render_price(&mut out, &p);
        assert!(out.contains("mnr_price_sources_ok 0"));
        assert!(
            !out.contains("\nmnr_xmr_usd "),
            "no rate, no gauge line: {out}"
        );
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        p.observe(
            &[("a".into(), Ok(538.8)), ("b".into(), Ok(539.0))],
            now - 30,
        );
        let mut out = String::new();
        render_price(&mut out, &p);
        assert!(out.contains("mnr_xmr_usd 538.9"), "{out}");
        assert!(out.contains("mnr_price_sources_ok 2"));
        assert!(out.contains("mnr_price_age_seconds 3"), "{out}");
    }
}
