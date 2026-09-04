//! Response cache (`docs/stage0-mvp-plan.md` §5; invariant 2).
//!
//! Three tiers over `moka`:
//!
//! - **Immutable** — verified blocks, headers and hashes below the tip safety
//!   line, keyed by `(epoch, method, params)`, 30 d TTL, weighted by body
//!   size under `[cache] max_bytes`. The *epoch* is the header chain's: a
//!   reorg bumps it and every entry keyed on the old epoch becomes
//!   unreachable at once, no scan needed. Callers write here only when the
//!   answer was verified and the requested height is at or below
//!   `quorum_tip − TIP_SAFETY_DEPTH`, and never in degraded mode; the tier
//!   itself cannot tell, which is why [`Cache::immutable_put`] takes the
//!   epoch as an argument rather than reading it.
//! - **Tx** — one verified `/get_transactions` entry per
//!   `(epoch, tx_hash, prune, decode_as_json)`, so a batch is served as hits
//!   plus one upstream call for the misses.
//! - **SWR** — consensus state (`get_info` family) per `(method, params)`,
//!   with the freshness windows of the policy table: fresh under
//!   `max-age=1`, served stale while a background refresh runs for the next
//!   5 s, refreshed in the foreground (stale on error) for 15 s after that,
//!   then a miss. Refreshes are single-flight per key.
//!
//! Nothing here knows who asked: keys are method and params only, and the
//! body is the daemon's `result`, re-wrapped with the client's own JSON-RPC
//! id on the way out.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use moka::future::Cache as Moka;
use parking_lot::Mutex;

/// `max-age` of the SWR tier.
pub const SWR_MAX_AGE: Duration = Duration::from_secs(1);
/// `stale-while-revalidate`: served stale, refreshed in the background.
pub const SWR_REVALIDATE: Duration = Duration::from_secs(5);
/// `stale-if-error`: refreshed in the foreground, served only if that fails.
pub const SWR_IF_ERROR: Duration = Duration::from_secs(15);
/// Immutable and tx tiers: 30 days.
const IMMUTABLE_TTL: Duration = Duration::from_secs(30 * 24 * 3600);
/// The SWR tier holds one entry per distinct `(method, params)`; a thousand
/// covers every consensus method with room for odd params.
const SWR_ENTRIES: u64 = 1000;
/// Tx-tier weight is bounded alongside the immutable tier.
const TX_SHARE: u64 = 4;

/// What the `Mnr-Cache` header says about an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Served from cache, fresh.
    Hit,
    /// Served from cache past `max-age` (SWR tier only).
    Stale,
    /// Fetched from an upstream; may have been written to cache.
    Miss,
    /// Not a cacheable answer (streams, mempool, writes, errors).
    Bypass,
}

impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Self::Hit => "hit",
            Self::Stale => "stale",
            Self::Miss => "miss",
            Self::Bypass => "bypass",
        }
    }
}

/// How an SWR entry may be used right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// Under `max-age`: serve as is.
    Fresh,
    /// Serve it, and refresh in the background.
    Revalidate,
    /// Refresh in the foreground; serve this only if the refresh fails.
    IfError,
    /// Too old to serve at all.
    Expired,
}

/// A verified immutable answer: the daemon's `result` (JSON-RPC) or body
/// (legacy path) and the verification label it earned.
#[derive(Debug, Clone)]
pub struct Cached {
    pub body: Bytes,
    pub verify: &'static str,
}

/// A consensus answer with its provenance.
#[derive(Debug, Clone)]
pub struct SwrEntry {
    pub body: Bytes,
    pub verify: &'static str,
    /// `(agreeing, asked)` behind a `majority` label.
    pub agreeing: Option<(usize, usize)>,
    pub fetched: Instant,
}

impl SwrEntry {
    pub fn freshness_at(&self, now: Instant) -> Freshness {
        let age = now.saturating_duration_since(self.fetched);
        if age < SWR_MAX_AGE {
            Freshness::Fresh
        } else if age < SWR_MAX_AGE + SWR_REVALIDATE {
            Freshness::Revalidate
        } else if age < SWR_MAX_AGE + SWR_REVALIDATE + SWR_IF_ERROR {
            Freshness::IfError
        } else {
            Freshness::Expired
        }
    }
}

pub struct Cache {
    immutable: Moka<String, Arc<Cached>>,
    txs: Moka<String, Arc<Bytes>>,
    swr: Moka<String, Arc<SwrEntry>>,
    /// SWR keys with a refresh in flight (single-flight).
    refreshing: Mutex<HashSet<String>>,
}

impl Cache {
    pub fn new(max_bytes: u64) -> Self {
        let weigh_cached = |k: &String, v: &Arc<Cached>| -> u32 {
            (k.len() + v.body.len()).try_into().unwrap_or(u32::MAX)
        };
        let weigh_bytes = |k: &String, v: &Arc<Bytes>| -> u32 {
            (k.len() + v.len()).try_into().unwrap_or(u32::MAX)
        };
        Self {
            immutable: Moka::builder()
                .max_capacity(max_bytes)
                .weigher(weigh_cached)
                .time_to_live(IMMUTABLE_TTL)
                .build(),
            txs: Moka::builder()
                .max_capacity(max_bytes / TX_SHARE)
                .weigher(weigh_bytes)
                .time_to_live(IMMUTABLE_TTL)
                .build(),
            swr: Moka::builder()
                .max_capacity(SWR_ENTRIES)
                .time_to_live(SWR_MAX_AGE + SWR_REVALIDATE + SWR_IF_ERROR)
                .build(),
            refreshing: Mutex::new(HashSet::new()),
        }
    }

    /// Key for the immutable tier. `params` must already be canonical
    /// (the caller serialises the fields it verified, in a fixed order).
    pub fn immutable_key(epoch: u64, method: &str, params: &str) -> String {
        format!("{epoch}|{method}|{params}")
    }

    pub async fn immutable_get(&self, key: &str) -> Option<Arc<Cached>> {
        self.immutable.get(key).await
    }

    pub async fn immutable_put(&self, key: String, value: Cached) {
        self.immutable.insert(key, Arc::new(value)).await;
    }

    /// Key for one transaction entry.
    pub fn tx_key(epoch: u64, tx_hash: &str, prune: bool, as_json: bool) -> String {
        format!(
            "{epoch}|tx|{tx_hash}|{}{}",
            u8::from(prune),
            u8::from(as_json)
        )
    }

    pub async fn tx_get(&self, key: &str) -> Option<Arc<Bytes>> {
        self.txs.get(key).await
    }

    pub async fn tx_put(&self, key: String, entry: Bytes) {
        self.txs.insert(key, Arc::new(entry)).await;
    }

    /// Key for the SWR tier: no epoch (consensus state is refreshed every
    /// second anyway).
    pub fn swr_key(method: &str, params: &str) -> String {
        format!("{method}|{params}")
    }

    pub async fn swr_get(&self, key: &str) -> Option<Arc<SwrEntry>> {
        self.swr.get(key).await
    }

    pub async fn swr_put(&self, key: String, entry: SwrEntry) {
        self.swr.insert(key, Arc::new(entry)).await;
    }

    /// Claim the refresh of `key`. `false` means one is already running.
    pub fn begin_refresh(&self, key: &str) -> bool {
        self.refreshing.lock().insert(key.to_owned())
    }

    pub fn end_refresh(&self, key: &str) {
        self.refreshing.lock().remove(key);
    }

    /// `(entries, bytes)` per tier for metrics, after pending housekeeping.
    pub async fn stats(&self) -> [(&'static str, u64, u64); 3] {
        self.immutable.run_pending_tasks().await;
        self.txs.run_pending_tasks().await;
        self.swr.run_pending_tasks().await;
        [
            (
                "immutable",
                self.immutable.entry_count(),
                self.immutable.weighted_size(),
            ),
            ("tx", self.txs.entry_count(), self.txs.weighted_size()),
            ("swr", self.swr.entry_count(), self.swr.weighted_size()),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cached(n: usize) -> Cached {
        Cached {
            body: Bytes::from(vec![b'x'; n]),
            verify: "chain",
        }
    }

    #[tokio::test]
    async fn immutable_entries_are_keyed_by_epoch() {
        let c = Cache::new(1 << 20);
        let k1 = Cache::immutable_key(7, "get_block", "h=100");
        c.immutable_put(k1.clone(), cached(10)).await;
        assert!(c.immutable_get(&k1).await.is_some());
        // After a reorg the epoch is 8: the same request misses.
        let k2 = Cache::immutable_key(8, "get_block", "h=100");
        assert_ne!(k1, k2);
        assert!(c.immutable_get(&k2).await.is_none());
    }

    #[tokio::test]
    async fn immutable_tier_is_bounded_by_bytes() {
        let c = Cache::new(10_000);
        for i in 0..100 {
            c.immutable_put(
                Cache::immutable_key(1, "get_block", &i.to_string()),
                cached(1_000),
            )
            .await;
        }
        let [(_, entries, bytes), ..] = c.stats().await;
        assert!(bytes <= 10_000, "{bytes} bytes cached");
        assert!(entries <= 10, "{entries} entries");
        assert!(entries > 0);
    }

    #[tokio::test]
    async fn tx_entries_key_on_hash_and_request_shape() {
        let c = Cache::new(1 << 20);
        let k = Cache::tx_key(1, "ab".repeat(32).as_str(), true, false);
        c.tx_put(k.clone(), Bytes::from_static(b"{}")).await;
        assert!(c.tx_get(&k).await.is_some());
        // Same tx with a different request shape is a different entry.
        assert!(c
            .tx_get(&Cache::tx_key(1, "ab".repeat(32).as_str(), false, false))
            .await
            .is_none());
        assert!(c
            .tx_get(&Cache::tx_key(1, "ab".repeat(32).as_str(), true, true))
            .await
            .is_none());
    }

    #[test]
    fn swr_freshness_windows_follow_the_policy() {
        let t0 = Instant::now();
        let e = SwrEntry {
            body: Bytes::new(),
            verify: "majority",
            agreeing: Some((3, 3)),
            fetched: t0,
        };
        let at = |secs: u64| e.freshness_at(t0 + Duration::from_secs(secs));
        assert_eq!(at(0), Freshness::Fresh);
        assert_eq!(
            e.freshness_at(t0 + Duration::from_millis(999)),
            Freshness::Fresh
        );
        assert_eq!(at(1), Freshness::Revalidate);
        assert_eq!(at(5), Freshness::Revalidate);
        assert_eq!(at(6), Freshness::IfError);
        assert_eq!(at(20), Freshness::IfError);
        assert_eq!(at(21), Freshness::Expired);
        // A clock that went backwards is "just fetched", never a panic.
        assert_eq!(
            e.freshness_at(t0 - Duration::from_secs(5)),
            Freshness::Fresh
        );
    }

    #[tokio::test]
    async fn swr_refresh_is_single_flight() {
        let c = Cache::new(1 << 20);
        let k = Cache::swr_key("get_info", "");
        assert!(c.begin_refresh(&k));
        assert!(!c.begin_refresh(&k), "second refresher must wait");
        assert!(c.begin_refresh(&Cache::swr_key("get_height", "")));
        c.end_refresh(&k);
        assert!(c.begin_refresh(&k));
        c.swr_put(
            k.clone(),
            SwrEntry {
                body: Bytes::from_static(b"{\"height\":1}"),
                verify: "majority",
                agreeing: Some((2, 3)),
                fetched: Instant::now(),
            },
        )
        .await;
        let e = c.swr_get(&k).await.unwrap();
        assert_eq!(e.freshness_at(Instant::now()), Freshness::Fresh);
        assert_eq!(e.agreeing, Some((2, 3)));
    }

    #[test]
    fn status_labels() {
        assert_eq!(Status::Hit.label(), "hit");
        assert_eq!(Status::Stale.label(), "stale");
        assert_eq!(Status::Miss.label(), "miss");
        assert_eq!(Status::Bypass.label(), "bypass");
    }
}
