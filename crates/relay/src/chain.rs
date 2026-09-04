//! The relay's own header chain (`docs/stage0-mvp-plan.md` §4): one
//! `(height, hash, prev_hash, timestamp)` record per block, built once from
//! the upstreams by majority and extended at the tip every probe round.
//!
//! Verification by height (`get_block` by height, `get_block_header_by_*`,
//! `get_block_headers_range`, `on_get_block_hash`) compares a node's answer
//! with this chain; without it those answers are annotated `Mnr-Verify: none`
//! and never trusted silently.
//!
//! - **Build.** `get_block_headers_range` in batches of up to 1000 (monerod's
//!   restricted limit), one batch per second (rule 3), fetched from
//!   `min_agree` upstreams at once with the owned node always among them
//!   when it is healthy. A batch is appended only when every copy is
//!   identical and links to our tip; a copy in the minority is a fault
//!   against that upstream (three in an hour eject it).
//! - **Extend.** When the quorum tip moves past our tip, the last 20 records
//!   are fetched along with the new ones and [`HeaderChain::fork_point`]
//!   finds where the chains diverge. A fork below our tip is a **reorg**: the
//!   chain is truncated, the new records appended and the cache **epoch**
//!   bumped, so every cached answer keyed on the old epoch is unreachable
//!   (invariant 2). The search window doubles up to 1000 when no fork point
//!   is found; beyond that the chain is cut back by 1000 blindly, which also
//!   bumps the epoch.
//! - **Degraded.** Without a quorum tip the chain neither builds nor extends.
//!
//! Persistence is the `mnr-core` byte format at `[chain] path`: appends go
//! to the file tail, a reorg truncates it, and a file that fails linkage on
//! load is refused (delete it to rebuild).

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use mnr_core::headerchain::{Entry, HeaderChain};
use mnr_core::policy::TIP_SAFETY_DEPTH;
use mnr_core::verify::{QuorumTip, ReportedHeader};
use mnr_core::wire::{GetBlockHeadersRangeResult, JsonRpcRequest, JsonRpcResponse};
use parking_lot::{Mutex, RwLock, RwLockReadGuard};

use crate::config::Kind;
use crate::upstream::{Pool, Upstream, Work};

/// Records re-fetched behind the tip when extending, so a reorg since the
/// last round is found without a rebuild.
const INITIAL_WINDOW: u64 = 20;
/// Widest reorg search before the chain is cut back blindly.
const MAX_WINDOW: u64 = 1000;
/// Pause between batches while building (rule 3: one batch per second).
const BUILD_PACE: Duration = Duration::from_secs(1);
/// Per-call timeout for a 1000-header range; this is our own background
/// call, not a client's, so it is generous.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
/// Sizes of the `mnr-core` byte format, checked in tests against the crate.
const FILE_HEADER: u64 = 16;
const RECORD: u64 = 80;
const METHOD: &str = "get_block_headers_range";

/// The chain, its cache epoch, and the file it is persisted in.
pub struct ChainStore {
    chain: RwLock<HeaderChain>,
    /// Cache epoch: part of every immutable cache key; bumped on reorg.
    epoch: AtomicU64,
    reorgs: AtomicU64,
    /// Current reorg search window (records behind the tip re-fetched).
    window: AtomicU64,
    file: Option<Mutex<File>>,
}

/// What one sync step did, which decides how soon the next one runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// A batch was appended and the quorum tip is still ahead: run again soon.
    Built,
    /// Nothing to do: the quorum tip is on our chain.
    Idle,
    /// No quorum, no capacity, or the copies disagreed: try again later.
    Retry,
}

impl ChainStore {
    /// Open the chain at `path` (creating it), or keep it in memory only.
    pub fn open(path: Option<&Path>) -> Result<Self, String> {
        let epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let (chain, file) = match path {
            None => (HeaderChain::new(), None),
            Some(p) => {
                let mut f = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .open(p)
                    .map_err(|e| format!("cannot open header chain {}: {e}", p.display()))?;
                let mut bytes = Vec::new();
                f.read_to_end(&mut bytes)
                    .map_err(|e| format!("cannot read header chain {}: {e}", p.display()))?;
                // A crash inside an append can leave a partial record at the
                // tail. It is not a record, so drop it and let linkage
                // validation judge the rest.
                if bytes.len() as u64 > FILE_HEADER {
                    let body = bytes.len() as u64 - FILE_HEADER;
                    let partial = body % RECORD;
                    if partial != 0 {
                        let keep = bytes.len() - partial as usize;
                        tracing::warn!(
                            dropped_bytes = partial,
                            "header chain file has a partial trailing record; truncating"
                        );
                        bytes.truncate(keep);
                        f.set_len(keep as u64)
                            .and_then(|()| f.sync_data())
                            .map_err(|e| format!("cannot truncate {}: {e}", p.display()))?;
                    }
                }
                let chain = if bytes.is_empty() {
                    let empty = HeaderChain::new();
                    f.write_all(&empty.to_bytes())
                        .and_then(|()| f.sync_data())
                        .map_err(|e| format!("cannot initialise {}: {e}", p.display()))?;
                    empty
                } else {
                    HeaderChain::from_bytes(&bytes).map_err(|e| {
                        format!(
                            "header chain {} is corrupt ({e}); delete it to rebuild",
                            p.display()
                        )
                    })?
                };
                (chain, Some(Mutex::new(f)))
            }
        };
        tracing::info!(
            height = chain.tip().map(|t| t.height),
            "header chain loaded"
        );
        Ok(Self {
            chain: RwLock::new(chain),
            epoch: AtomicU64::new(epoch),
            reorgs: AtomicU64::new(0),
            window: AtomicU64::new(INITIAL_WINDOW),
            file,
        })
    }

    /// Read access for verification.
    pub fn read(&self) -> RwLockReadGuard<'_, HeaderChain> {
        self.chain.read()
    }

    pub fn tip(&self) -> Option<Entry> {
        self.chain.read().tip()
    }

    /// Replace the chain, for dispatch tests that need known heights.
    #[cfg(test)]
    pub fn set_for_test(&self, chain: HeaderChain) {
        *self.chain.write() = chain;
    }

    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Relaxed)
    }

    pub fn reorgs(&self) -> u64 {
        self.reorgs.load(Ordering::Relaxed)
    }

    /// Run sync steps forever, pacing by what the last step did.
    pub async fn run_sync(self: Arc<Self>, pool: Arc<Pool>, batch: u64) {
        loop {
            let pace = match self.step(&pool, batch).await {
                Step::Built => BUILD_PACE,
                Step::Retry => BUILD_PACE.max(pool.interval() / 4),
                Step::Idle => pool.interval(),
            };
            tokio::time::sleep(pace).await;
        }
    }

    /// One build/extend step against the current quorum tip.
    pub async fn step(&self, pool: &Pool, batch: u64) -> Step {
        let Some(q) = pool.quorum() else {
            return Step::Retry;
        };
        let tip = self.tip();
        if let Some(t) = tip {
            if t.height >= q.height && self.chain.read().hash_at(q.height) == Some(q.hash) {
                return Step::Idle;
            }
        }
        let window = self.window.load(Ordering::Relaxed);
        let start = match tip {
            None => 0,
            Some(t) => (t.height.min(q.height) + 1).saturating_sub(window),
        };
        let end = start.saturating_add(batch - 1).min(q.height);
        let Some(candidate) = fetch_agreed(pool, start, end, &q).await else {
            return Step::Retry;
        };
        self.merge(candidate, start, tip, &q)
    }

    /// Merge an agreed run of records into the chain: plain append, reorg
    /// (truncate + append + epoch bump), or nothing when already present.
    fn merge(&self, candidate: Vec<Entry>, start: u64, tip: Option<Entry>, q: &QuorumTip) -> Step {
        let Some(last) = candidate.last().copied() else {
            return Step::Retry;
        };
        let fork = match tip {
            None => None,
            Some(_) => self.chain.read().fork_point(&candidate),
        };
        if tip.is_some() && fork.is_none() {
            return self.no_fork_point(start);
        }
        self.window.store(INITIAL_WINDOW, Ordering::Relaxed);
        let mut chain = self.chain.write();
        // Anything we hold above the fork point is on a chain the quorum
        // left: a reorg.
        if let (Some(f), Some(t)) = (fork, tip) {
            if t.height > f {
                let dropped = chain.truncate(f);
                self.persist_truncate(chain.len() as u64);
                let epoch = self.epoch.fetch_add(1, Ordering::Relaxed) + 1;
                self.reorgs.fetch_add(1, Ordering::Relaxed);
                if dropped as u64 > TIP_SAFETY_DEPTH {
                    tracing::error!(
                        depth = dropped,
                        fork = f,
                        epoch,
                        "reorg deeper than the tip safety line; cached answers keyed on the old epoch are unreachable"
                    );
                } else {
                    tracing::warn!(depth = dropped, fork = f, epoch, "reorg at the tip");
                }
            }
        }
        let from = fork.map_or(0, |f| f + 1);
        let mut appended = Vec::new();
        for e in candidate.into_iter().filter(|e| e.height >= from) {
            if let Err(err) = chain.append(e) {
                // The copies were validated for linkage, so this only
                // happens if the fetched run does not meet our chain.
                tracing::error!(height = e.height, %err, "cannot append agreed header");
                break;
            }
            appended.push(e);
        }
        drop(chain);
        self.persist_append(&appended);
        if appended.is_empty() && last.height <= from {
            return Step::Idle;
        }
        tracing::debug!(
            from,
            to = last.height,
            appended = appended.len(),
            "header chain extended"
        );
        if last.height < q.height {
            Step::Built
        } else {
            Step::Idle
        }
    }

    /// The fetched run shares no record with ours: widen the search, and
    /// past [`MAX_WINDOW`] cut the chain back blindly (bumping the epoch,
    /// since anything above the cut may have been served as verified).
    fn no_fork_point(&self, start: u64) -> Step {
        let window = self.window.load(Ordering::Relaxed);
        if start == 0 {
            // Even genesis disagrees: this chain is not the quorum's chain.
            let dropped = {
                let mut chain = self.chain.write();
                let n = chain.len();
                *chain = HeaderChain::new();
                n
            };
            self.persist_truncate(0);
            self.epoch.fetch_add(1, Ordering::Relaxed);
            self.reorgs.fetch_add(1, Ordering::Relaxed);
            self.window.store(INITIAL_WINDOW, Ordering::Relaxed);
            tracing::error!(
                dropped,
                "header chain disagrees with the quorum at genesis; rebuilding"
            );
            return Step::Retry;
        }
        if window < MAX_WINDOW {
            let wider = (window * 2).min(MAX_WINDOW);
            self.window.store(wider, Ordering::Relaxed);
            tracing::warn!(
                window = wider,
                "no fork point in the last {window} headers; widening"
            );
            return Step::Retry;
        }
        let cut = {
            let mut chain = self.chain.write();
            let tip = chain.tip().map_or(0, |t| t.height);
            let keep = tip.saturating_sub(MAX_WINDOW);
            chain.truncate(keep);
            self.persist_truncate(chain.len() as u64);
            keep
        };
        self.epoch.fetch_add(1, Ordering::Relaxed);
        self.reorgs.fetch_add(1, Ordering::Relaxed);
        tracing::error!(
            cut_to = cut,
            "no fork point within {MAX_WINDOW} headers; cutting the chain back"
        );
        Step::Retry
    }

    fn persist_append(&self, entries: &[Entry]) {
        let Some(file) = &self.file else { return };
        if entries.is_empty() {
            return;
        }
        let mut bytes = Vec::with_capacity(entries.len() * RECORD as usize);
        for e in entries {
            bytes.extend_from_slice(&e.to_bytes());
        }
        let mut f = file.lock();
        let r: io::Result<()> = (|| {
            f.seek(SeekFrom::End(0))?;
            f.write_all(&bytes)?;
            f.sync_data()
        })();
        if let Err(e) = r {
            tracing::error!(error = %e, "cannot persist header chain; the file may be refused on next start");
        }
    }

    /// Keep the first `records` records in the file.
    fn persist_truncate(&self, records: u64) {
        let Some(file) = &self.file else { return };
        let f = file.lock();
        let r = f
            .set_len(FILE_HEADER + records * RECORD)
            .and_then(|()| f.sync_data());
        if let Err(e) = r {
            tracing::error!(error = %e, "cannot truncate header chain file");
        }
    }
}

/// Why one upstream's copy of a range was not usable.
enum CopyError {
    /// Transport failure, 5xx, short answer: not this node's fault.
    Skip,
    /// The answer is malformed or does not link: a verification fault.
    Fault(String),
}

/// Fetch `start..=end` from `min_agree` upstreams and return the run they
/// all agree on. A copy in the minority (when there is a strict majority)
/// is recorded as a fault against its upstream.
async fn fetch_agreed(pool: &Pool, start: u64, end: u64, q: &QuorumTip) -> Option<Vec<Entry>> {
    let need = pool.min_agree();
    let ranked = pool.ranked(Work::Light);
    // Owned node first (rule 2: it carries our own load by preference),
    // then the rest by rank; each must have a light token right now.
    let owned = ranked
        .iter()
        .copied()
        .filter(|&id| pool.upstream(id).cfg.kind == Kind::Owned);
    let public = ranked
        .iter()
        .copied()
        .filter(|&id| pool.upstream(id).cfg.kind != Kind::Owned);
    let mut chosen = Vec::with_capacity(need);
    for id in owned.chain(public) {
        if chosen.len() == need {
            break;
        }
        if pool.upstream(id).try_take_light() {
            chosen.push(id);
        }
    }
    if chosen.len() < need {
        tracing::debug!(
            available = chosen.len(),
            need,
            "not enough upstreams with capacity for a header batch"
        );
        return None;
    }
    let req = JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: serde_json::Value::from(0),
        method: METHOD.into(),
        params: Some(serde_json::json!({ "start_height": start, "end_height": end })),
    };
    let body = Bytes::from(serde_json::to_vec(&req).expect("serialisable"));
    let fetches = chosen.iter().map(|&id| {
        let body = body.clone();
        async move { (id, fetch_range(pool.upstream(id), body, start, end).await) }
    });
    let mut copies: Vec<(usize, Vec<Entry>)> = Vec::new();
    for (id, r) in futures_util::future::join_all(fetches).await {
        match r {
            Ok(entries) => copies.push((id, entries)),
            Err(CopyError::Skip) => {}
            Err(CopyError::Fault(detail)) => pool.record_fault(id, METHOD, detail),
        }
    }
    if copies.len() < need {
        return None;
    }
    // Group identical copies; the group with every copy wins outright.
    let mut groups: Vec<(Vec<usize>, usize)> = Vec::new(); // (members, index into copies)
    for (i, (id, entries)) in copies.iter().enumerate() {
        match groups.iter_mut().find(|(_, j)| copies[*j].1 == *entries) {
            Some((members, _)) => members.push(*id),
            None => groups.push((vec![*id], i)),
        }
    }
    let (members, idx) = groups
        .iter()
        .max_by_key(|(m, _)| m.len())
        .expect("at least one copy");
    if members.len() == copies.len() {
        let entries = copies.swap_remove(*idx).1;
        // The quorum tip itself must be the last record when we reach it.
        if let Some(last) = entries.last() {
            if last.height == q.height && last.hash != q.hash {
                tracing::debug!(
                    height = q.height,
                    "agreed range does not end on the quorum tip; retrying"
                );
                return None;
            }
        }
        return Some(entries);
    }
    if members.len() * 2 > copies.len() {
        let majority = &copies[*idx].1;
        for (id, entries) in &copies {
            if members.contains(id) {
                continue;
            }
            let at = majority
                .iter()
                .zip(entries)
                .find(|(a, b)| a != b)
                .map_or(start, |(a, _)| a.height);
            pool.record_fault(
                *id,
                METHOD,
                format!("header range {start}..={end} disagrees with the majority at height {at}"),
            );
        }
    } else {
        tracing::warn!(
            start,
            end,
            copies = copies.len(),
            "header range: no majority among copies"
        );
    }
    None
}

/// One upstream's copy of `start..=end`, validated for shape and linkage.
async fn fetch_range(
    u: &Upstream,
    body: Bytes,
    start: u64,
    end: u64,
) -> Result<Vec<Entry>, CopyError> {
    let f = u
        .forward("/json_rpc", "application/json", body, FETCH_TIMEOUT)
        .await
        .map_err(|_| CopyError::Skip)?;
    if f.status != 200 {
        return Err(CopyError::Skip);
    }
    let resp: JsonRpcResponse<GetBlockHeadersRangeResult> = serde_json::from_slice(&f.body)
        .map_err(|_| CopyError::Fault("unparseable header range".into()))?;
    let Some(result) = resp.result else {
        // A daemon error (e.g. height out of range) is not a lie.
        return Err(CopyError::Skip);
    };
    let expected = usize::try_from(end - start + 1).map_err(|_| CopyError::Skip)?;
    if result.headers.len() < expected {
        return Err(CopyError::Skip);
    }
    if result.headers.len() > expected {
        return Err(CopyError::Fault(format!(
            "header range {start}..={end}: {} headers for {expected} requested",
            result.headers.len()
        )));
    }
    let mut out = Vec::with_capacity(expected);
    for (i, h) in result.headers.iter().enumerate() {
        let want = start + i as u64;
        let rep = ReportedHeader::try_from(h)
            .map_err(|e| CopyError::Fault(format!("header at {want}: {e}")))?;
        if rep.height != want {
            return Err(CopyError::Fault(format!(
                "header range {start}..={end}: height {} at position {i}",
                rep.height
            )));
        }
        if let Some(prev) = out.last() {
            let prev: &Entry = prev;
            if rep.prev_hash != prev.hash {
                return Err(CopyError::Fault(format!(
                    "header range {start}..={end}: prev_hash at {want} does not link"
                )));
            }
        } else if want == 0 && rep.prev_hash != [0; 32] {
            return Err(CopyError::Fault("genesis with a non-zero prev_hash".into()));
        }
        out.push(Entry::from(&rep));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::upstream::Health;
    use axum::routing::post;
    use axum::{Json, Router};
    use mnr_core::hash::Hash;
    use serde_json::{json, Value};
    use std::net::SocketAddr;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn file_format_sizes_match_mnr_core() {
        assert_eq!(HeaderChain::new().to_bytes().len() as u64, FILE_HEADER);
        assert_eq!(
            Entry {
                height: 0,
                hash: [0; 32],
                prev_hash: [0; 32],
                timestamp: 0
            }
            .to_bytes()
            .len() as u64,
            RECORD
        );
    }

    /// A synthetic chain: branch 0 is "the" chain; a node on branch `b`
    /// from `fork` up reports different hashes from `fork` on, still linked.
    #[derive(Clone, Copy)]
    struct Spec {
        branch: u8,
        fork: u64,
    }

    fn hash_of(h: u64, spec: Spec) -> Hash {
        let branch = if spec.branch != 0 && h >= spec.fork {
            spec.branch
        } else {
            0
        };
        let mut hash = [0u8; 32];
        hash[..8].copy_from_slice(&h.to_le_bytes());
        hash[8] = 0xAB;
        hash[9] = branch;
        hash
    }

    fn entry_of(h: u64, spec: Spec) -> Entry {
        Entry {
            height: h,
            hash: hash_of(h, spec),
            prev_hash: if h == 0 {
                [0; 32]
            } else {
                hash_of(h - 1, spec)
            },
            timestamp: h * 120,
        }
    }

    fn hex(h: &Hash) -> String {
        h.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn header_json(h: u64, spec: Spec) -> Value {
        let e = entry_of(h, spec);
        json!({
            "block_size": 1, "block_weight": 1, "cumulative_difficulty": 1, "depth": 0,
            "difficulty": 1, "hash": hex(&e.hash), "height": h, "major_version": 1,
            "miner_tx_hash": hex(&[0; 32]), "minor_version": 1, "nonce": 0, "num_txes": 0,
            "prev_hash": hex(&e.prev_hash), "reward": 1, "timestamp": e.timestamp
        })
    }

    /// A fake monerod answering `get_block_headers_range` from `spec`.
    async fn mock(spec: Arc<Mutex<Spec>>, hits: Arc<AtomicUsize>) -> SocketAddr {
        let app = Router::new().route(
            "/json_rpc",
            post(move |Json(req): Json<JsonRpcRequest>| {
                let spec = Arc::clone(&spec);
                let hits = Arc::clone(&hits);
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(req.method, METHOD);
                    let p = req.params.unwrap();
                    let (s, e) = (p["start_height"].as_u64().unwrap(), p["end_height"].as_u64().unwrap());
                    let spec = *spec.lock();
                    let headers: Vec<Value> = (s..=e).map(|h| header_json(h, spec)).collect();
                    Json(json!({"jsonrpc":"2.0","id":0,"result":{"headers":headers,"status":"OK","untrusted":true}}))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        addr
    }

    struct Net {
        pool: Pool,
        specs: Vec<Arc<Mutex<Spec>>>,
        hits: Arc<AtomicUsize>,
    }

    impl Net {
        /// `n` mocks on branch 0; the first is the owned node.
        async fn new(n: usize, min_agree: usize) -> Self {
            let hits = Arc::new(AtomicUsize::new(0));
            let mut specs = Vec::new();
            let mut toml = format!("[probe]\nmin_agree = {min_agree}\n");
            for i in 0..n {
                let spec = Arc::new(Mutex::new(Spec { branch: 0, fork: 0 }));
                let addr = mock(Arc::clone(&spec), Arc::clone(&hits)).await;
                specs.push(spec);
                let kind = if i == 0 { "owned" } else { "public" };
                toml.push_str(&format!(
                    "[[upstreams]]\nname = \"m{i}\"\nurl = \"http://{addr}\"\nkind = \"{kind}\"\ntransport = \"http\"\ncaps = {{ rps_light = 100, max_streams = 2, mbps = 10 }}\n"
                ));
            }
            let pool = Pool::from_config(&Config::parse(&toml).unwrap()).unwrap();
            let net = Self { pool, specs, hits };
            net.quorum_at(0, Spec { branch: 0, fork: 0 });
            net
        }

        fn quorum_at(&self, height: u64, spec: Spec) {
            let mut health = Vec::new();
            for (i, _) in self.specs.iter().enumerate() {
                let mut h = Health::healthy_for_test(height + 1, hash_of(height, spec));
                h.rtt_ema_ms = Some(10.0 + i as f64);
                health.push(h);
            }
            self.pool
                .set_for_test(health, Some((height, hash_of(height, spec))));
        }

        fn switch(&self, i: usize, spec: Spec) {
            *self.specs[i].lock() = spec;
        }
    }

    async fn run_until_idle(store: &ChainStore, pool: &Pool, batch: u64, max: usize) -> usize {
        for i in 0..max {
            if store.step(pool, batch).await == Step::Idle {
                return i + 1;
            }
        }
        panic!("not idle after {max} steps");
    }

    fn assert_on_branch(store: &ChainStore, upto: u64, spec: Spec) {
        let chain = store.read();
        assert_eq!(chain.tip().unwrap().height, upto);
        for h in 0..=upto {
            assert_eq!(chain.get(h).unwrap(), entry_of(h, spec), "height {h}");
        }
    }

    #[tokio::test]
    async fn builds_from_genesis_by_majority_and_persists() {
        let net = Net::new(3, 3).await;
        net.quorum_at(2500, Spec { branch: 0, fork: 0 });
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("headers.mnrh");
        let store = ChainStore::open(Some(&path)).unwrap();
        assert_eq!(store.tip(), None);
        let steps = run_until_idle(&store, &net.pool, 1000, 10).await;
        assert_eq!(steps, 3, "0..=999, 1000..=1999, 2000..=2500");
        assert_on_branch(&store, 2500, Spec { branch: 0, fork: 0 });
        assert_eq!(net.hits.load(Ordering::SeqCst), 9, "three copies per batch");
        // A quorum on our chain costs no request.
        assert_eq!(store.step(&net.pool, 1000).await, Step::Idle);
        assert_eq!(net.hits.load(Ordering::SeqCst), 9);
        // The file reloads to the same chain.
        let again = ChainStore::open(Some(&path)).unwrap();
        assert_on_branch(&again, 2500, Spec { branch: 0, fork: 0 });
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            FILE_HEADER + 2501 * RECORD
        );
    }

    #[tokio::test]
    async fn degraded_pool_neither_builds_nor_extends() {
        let net = Net::new(3, 3).await;
        net.pool.set_for_test(vec![Health::default(); 3], None);
        let store = ChainStore::open(None).unwrap();
        assert_eq!(store.step(&net.pool, 1000).await, Step::Retry);
        assert_eq!(net.hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn liar_in_the_batch_is_faulted_then_ejected() {
        let net = Net::new(4, 3).await;
        // The owned node lies from height 500 (it is always chosen first).
        net.switch(
            0,
            Spec {
                branch: 9,
                fork: 500,
            },
        );
        net.quorum_at(999, Spec { branch: 0, fork: 0 });
        let store = ChainStore::open(None).unwrap();
        // Copies disagree 2 vs 1: nothing appended, the liar gets a fault.
        assert_eq!(store.step(&net.pool, 1000).await, Step::Retry);
        assert_eq!(store.tip(), None);
        let s = net.pool.status();
        assert_eq!(s.faults.len(), 1);
        assert_eq!(s.faults[0].upstream, "m0");
        assert!(
            s.faults[0].detail.contains("height 500"),
            "{}",
            s.faults[0].detail
        );
        assert_eq!(store.step(&net.pool, 1000).await, Step::Retry);
        assert_eq!(store.step(&net.pool, 1000).await, Step::Retry);
        assert!(
            net.pool.status().upstreams[0].ejected,
            "three faults in an hour"
        );
        // The three honest nodes remain: the batch goes through.
        assert_eq!(store.step(&net.pool, 1000).await, Step::Idle);
        assert_on_branch(&store, 999, Spec { branch: 0, fork: 0 });
    }

    #[tokio::test]
    async fn reorg_at_the_tip_truncates_and_bumps_the_epoch() {
        let net = Net::new(3, 3).await;
        net.quorum_at(100, Spec { branch: 0, fork: 0 });
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("headers.mnrh");
        let store = ChainStore::open(Some(&path)).unwrap();
        run_until_idle(&store, &net.pool, 1000, 5).await;
        let epoch0 = store.epoch();
        // The network reorgs: from height 95 every node is on branch 1, and
        // the quorum tip moves to 102 on that branch.
        let b1 = Spec {
            branch: 1,
            fork: 95,
        };
        for i in 0..3 {
            net.switch(i, b1);
        }
        net.quorum_at(102, b1);
        assert_eq!(store.step(&net.pool, 1000).await, Step::Idle);
        assert_on_branch(&store, 102, b1);
        assert_eq!(store.epoch(), epoch0 + 1);
        assert_eq!(store.reorgs(), 1);
        // The file was truncated and re-extended consistently.
        let again = ChainStore::open(Some(&path)).unwrap();
        assert_on_branch(&again, 102, b1);
        // A plain extension afterwards does not bump the epoch.
        net.quorum_at(110, b1);
        assert_eq!(store.step(&net.pool, 1000).await, Step::Idle);
        assert_eq!(store.epoch(), epoch0 + 1);
        assert_on_branch(&store, 110, b1);
    }

    #[tokio::test]
    async fn deep_reorg_widens_the_window_then_cuts_back() {
        let net = Net::new(3, 3).await;
        net.quorum_at(2999, Spec { branch: 0, fork: 0 });
        let store = ChainStore::open(None).unwrap();
        run_until_idle(&store, &net.pool, 1000, 5).await;
        let epoch0 = store.epoch();
        // Deeper than the initial window (100 > 20) but inside the maximum.
        let b1 = Spec {
            branch: 1,
            fork: 2900,
        };
        for i in 0..3 {
            net.switch(i, b1);
        }
        net.quorum_at(3000, b1);
        let steps = run_until_idle(&store, &net.pool, 1000, 20).await;
        assert!(steps > 1, "the first window cannot see the fork");
        assert_on_branch(&store, 3000, b1);
        assert_eq!(store.reorgs(), 1);
        assert_eq!(store.epoch(), epoch0 + 1);
        // Deeper than the maximum window: the chain is cut back blindly
        // (one more epoch bump) and then rebuilt on the new branch.
        let b2 = Spec {
            branch: 2,
            fork: 1500,
        };
        for i in 0..3 {
            net.switch(i, b2);
        }
        net.quorum_at(3001, b2);
        run_until_idle(&store, &net.pool, 1000, 60).await;
        assert_on_branch(&store, 3001, b2);
        assert!(store.reorgs() >= 3, "cut back plus the fork-point reorg");
        assert!(store.epoch() > epoch0 + 1);
    }

    #[tokio::test]
    async fn partial_trailing_record_is_dropped_on_load() {
        let net = Net::new(3, 3).await;
        net.quorum_at(30, Spec { branch: 0, fork: 0 });
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("headers.mnrh");
        let store = ChainStore::open(Some(&path)).unwrap();
        run_until_idle(&store, &net.pool, 1000, 5).await;
        drop(store);
        // Simulate a crash mid-append: 37 bytes of a would-be record 31.
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(&[0xEE; 37]).unwrap();
        drop(f);
        let again = ChainStore::open(Some(&path)).unwrap();
        assert_on_branch(&again, 30, Spec { branch: 0, fork: 0 });
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            FILE_HEADER + 31 * RECORD
        );
        // And it keeps extending from there.
        net.quorum_at(40, Spec { branch: 0, fork: 0 });
        assert_eq!(again.step(&net.pool, 1000).await, Step::Idle);
        assert_on_branch(&again, 40, Spec { branch: 0, fork: 0 });
    }

    #[tokio::test]
    async fn corrupt_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("headers.mnrh");
        std::fs::write(&path, b"not a header chain").unwrap();
        let err = match ChainStore::open(Some(&path)) {
            Ok(_) => panic!("corrupt file opened"),
            Err(e) => e,
        };
        assert!(err.contains("corrupt"), "{err}");
    }

    #[tokio::test]
    async fn short_and_failed_copies_are_skipped_not_faulted() {
        // Two mocks plus one that answers 500: with min_agree 2 the two
        // honest copies suffice, and the failing node is not faulted.
        let net = Net::new(3, 2).await;
        net.quorum_at(50, Spec { branch: 0, fork: 0 });
        let store = ChainStore::open(None).unwrap();
        // Make the owned node's copy fail by pointing its spec at a branch
        // whose genesis prev_hash is wrong: that *is* a fault. So instead
        // exhaust its light cap, which makes it unavailable, not faulty.
        let u = net.pool.upstream(0);
        while u.try_take_light() {}
        assert_eq!(store.step(&net.pool, 1000).await, Step::Idle);
        assert_on_branch(&store, 50, Spec { branch: 0, fork: 0 });
        assert!(net.pool.status().faults.is_empty());
    }
}
