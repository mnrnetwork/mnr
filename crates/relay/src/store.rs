//! Persistent token store and work-unit limiter (`docs/stage0-mvp-plan.md` §5;
//! gateway plan §3.1, §3.2).
//!
//! Raw tokens are stored as SHA-256 hashes only ([`auth::token_hash`]); the
//! raw token is returned exactly once, from [`SqliteStore::issue`] and
//! [`SqliteStore::rotate`], and is never logged, persisted or returned by any
//! query. Rotation keeps the previous hash valid for a 24 h grace window
//! (gateway plan §3.1).
//!
//! The work-unit allowance lives in the `usage` table, one row per token and
//! day; [`Limiter::admit`] refuses once the sum of the last 30 days plus the
//! unflushed in-memory delta would exceed `Tier::monthly_wu()`. Writes are
//! batched: a request only touches an in-memory delta and [`SqliteStore::run_flusher`]
//! persists it every second (or every 100 requests). The relay is a single
//! process per database, so the in-memory `persisted + delta` total is exact
//! between flushes.
//!
//! Burst buckets and stream slots are process-local and shared with
//! [`MemoryLimiter`]; only the WU usage needs to survive a restart.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use parking_lot::{Mutex, RwLock};
use rusqlite::{params, Connection};

use crate::auth::{handle, token_hash, AuthError, Principal, Tier, TokenStore};
use crate::limits::{Limiter, MemoryLimiter, StreamPermit, Verdict};
use crate::upstream::{FaultEvent, OptOutEvent};

/// Seconds the previous token stays valid after a rotation (gateway plan §3.1).
const GRACE_SECS: u64 = 24 * 3600;
/// Schema version, stored in `PRAGMA user_version`.
const SCHEMA_VERSION: i64 = 6;
/// How often the relay re-reads the token table to pick up CLI changes.
const TOKEN_RELOAD_EVERY: Duration = Duration::from_secs(30);

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS tokens(
  id INTEGER PRIMARY KEY,
  token_hash BLOB UNIQUE NOT NULL,
  prev_token_hash BLOB,
  prev_grace_until INTEGER,
  tier TEXT NOT NULL CHECK(tier IN ('free','pro')),
  status TEXT NOT NULL CHECK(status IN ('active','suspended')),
  valid_until INTEGER,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS usage(
  token_id INTEGER NOT NULL,
  day INTEGER NOT NULL,
  wu INTEGER NOT NULL,
  PRIMARY KEY(token_id, day)
);
CREATE TABLE IF NOT EXISTS upstream_stats(
  name TEXT PRIMARY KEY,
  requests INTEGER NOT NULL,
  verified INTEGER NOT NULL,
  faults INTEGER NOT NULL,
  ejected_until INTEGER,
  probes INTEGER NOT NULL DEFAULT 0,
  up INTEGER NOT NULL DEFAULT 0,
  stream_bytes INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS fault_log(
  id INTEGER PRIMARY KEY,
  at_unix INTEGER NOT NULL,
  upstream TEXT NOT NULL,
  method TEXT NOT NULL,
  detail TEXT NOT NULL,
  ejected INTEGER NOT NULL,
  ejected_until INTEGER
);
CREATE TABLE IF NOT EXISTS opt_out_log(
  at_unix INTEGER NOT NULL,
  upstream TEXT NOT NULL,
  host TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS invoices(
  id TEXT PRIMARY KEY,
  subaddr_index INTEGER NOT NULL,
  address TEXT NOT NULL,
  amount INTEGER NOT NULL,
  months INTEGER NOT NULL,
  renew_hash BLOB,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending','paid','expired')),
  received INTEGER NOT NULL DEFAULT 0,
  paid_at INTEGER,
  usd_cents INTEGER,
  rate_usd_per_xmr REAL,
  rate_at INTEGER,
  rate_sources TEXT
);
CREATE TABLE IF NOT EXISTS rates(
  id INTEGER PRIMARY KEY CHECK(id = 1),
  usd_per_xmr REAL NOT NULL,
  at_unix INTEGER NOT NULL,
  sources TEXT NOT NULL
);
";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenStatus {
    Active,
    Suspended,
}

/// A token row as the in-memory auth cache sees it. Current and (during the
/// grace window) previous hashes both map to one of these.
#[derive(Debug, Clone)]
struct TokenRow {
    id: i64,
    tier: Tier,
    status: TokenStatus,
    valid_until: Option<u64>,
    prev_hash: Option<[u8; 32]>,
    prev_grace_until: Option<u64>,
}

/// In-memory work-unit accounting: what is already in SQLite for the last
/// 30 days (`persisted`) plus what has not been flushed yet (`delta`).
#[derive(Debug, Clone, Copy, Default)]
struct UsageEntry {
    persisted: u64,
    delta: u64,
}

/// Sentinel for "reload this token's persisted total from the database".
const RELOAD: u64 = u64::MAX;

#[derive(Debug)]
struct UsageState {
    /// The day `persisted` values were computed for; a day rollover marks
    /// every entry for reload.
    day: i64,
    map: HashMap<i64, UsageEntry>,
}

impl Default for UsageState {
    fn default() -> Self {
        Self {
            day: today_unix(),
            map: HashMap::new(),
        }
    }
}

/// The persisted counters of one upstream (the public numbers).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UpstreamStats {
    pub requests: u64,
    /// Bytes pulled by block streams (lifetime), for the load figure.
    pub stream_bytes: u64,
    pub verified: u64,
    pub faults: u64,
    /// Probe rounds seen and rounds found answering on the tip (lifetime).
    pub probes: u64,
    pub up: u64,
    /// Unix seconds; `Some` while an ejection is in force.
    pub ejected_until: Option<u64>,
}

/// What the storefront needs to know about a token before renewing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenState {
    pub tier: Tier,
    pub active: bool,
    pub valid_until: Option<u64>,
}

/// One Pro invoice (plan §5 payments). Holds no client identity: the id is
/// random, the subaddress is ours, and `renew_hash` is a token hash.
#[derive(Debug, Clone, PartialEq)]
pub struct Invoice {
    pub id: String,
    pub subaddr_index: u32,
    pub address: String,
    /// Atomic units due.
    pub amount: u64,
    pub months: u32,
    /// The token this invoice extends, if it is a renewal.
    pub renew_hash: Option<[u8; 32]>,
    pub created_at: u64,
    pub expires_at: u64,
    pub status: InvoiceStatus,
    /// Atomic units seen with enough confirmations at the last check.
    pub received: u64,
    pub paid_at: Option<u64>,
    /// The USD price this invoice was for (None: fixed XMR price, or an
    /// invoice from before rates existed).
    pub usd_cents: Option<u64>,
    /// The XMR/USD rate the amount was computed at, when it was.
    pub rate_usd_per_xmr: Option<f64>,
    pub rate_at: Option<u64>,
    /// Comma-separated names of the sources that agreed on that rate.
    pub rate_sources: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvoiceStatus {
    Pending,
    Paid,
    Expired,
}

impl InvoiceStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Paid => "paid",
            Self::Expired => "expired",
        }
    }
}

/// Public view of one token for the management CLI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenSummary {
    /// First 8 hex characters of the token hash — the only handle that may be
    /// shown or logged; never the hash in full.
    pub handle: String,
    pub tier: Tier,
    /// `active` or `suspended`.
    pub status: String,
    pub valid_until: Option<u64>,
    /// Work units used in the last 30 days.
    pub wu_used_30d: u64,
}

/// Persistent [`TokenStore`] + [`Limiter`] over SQLite (`rusqlite`, bundled).
pub struct SqliteStore {
    conn: Mutex<Connection>,
    /// Auth cache: current and in-grace previous hashes → row. Reads never
    /// touch the database.
    tokens: RwLock<HashMap<[u8; 32], TokenRow>>,
    usage: Mutex<UsageState>,
    /// Burst buckets and stream slots, shared with [`MemoryLimiter`].
    burst: MemoryLimiter,
    /// Requests since the last flush; drives the 100-request early wakeup.
    pending: AtomicU64,
    flush_notify: tokio::sync::Notify,
    flush_interval: Duration,
}

impl SqliteStore {
    /// Open (creating) the token database at `path`; `None` opens an
    /// in-memory database for tests.
    pub fn open(path: Option<&Path>) -> Result<Self, String> {
        Self::open_with_flush_interval(path, Duration::from_secs(1))
    }

    pub fn open_with_flush_interval(
        path: Option<&Path>,
        flush_interval: Duration,
    ) -> Result<Self, String> {
        let conn = match path {
            Some(p) => Connection::open(p),
            None => Connection::open_in_memory(),
        }
        .map_err(|e| format!("cannot open token database: {e}"))?;
        // The relay and the `token` CLI share the file: WAL lets the CLI
        // write while the relay reads, and the busy timeout replaces
        // SQLITE_BUSY failures with a short wait.
        conn.busy_timeout(Duration::from_secs(5))
            .map_err(|e| format!("cannot set busy timeout: {e}"))?;
        if path.is_some() {
            conn.pragma_update(None, "journal_mode", "WAL")
                .map_err(|e| format!("cannot enable WAL: {e}"))?;
        }
        init_schema(&conn)?;
        let store = Self {
            conn: Mutex::new(conn),
            tokens: RwLock::new(HashMap::new()),
            usage: Mutex::new(UsageState::default()),
            burst: MemoryLimiter::new(),
            pending: AtomicU64::new(0),
            flush_notify: tokio::sync::Notify::new(),
            flush_interval,
        };
        store.load_tokens()?;
        Ok(store)
    }

    /// Run the usage flusher forever: writes pending deltas every
    /// `flush_interval` (or when 100 requests accumulate). The returned handle
    /// lets tests abort it so the store can be dropped.
    pub fn run_flusher(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(self.flush_interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await; // skip the immediate first tick
            let mut last_reload = Instant::now();
            loop {
                tokio::select! {
                    _ = interval.tick() => {}
                    _ = self.flush_notify.notified() => {}
                }
                if let Err(e) = self.flush() {
                    tracing::error!("usage flush failed: {e}");
                }
                // Suspensions and rotations done by the CLI while the relay
                // runs reach the cache within this window.
                if last_reload.elapsed() >= TOKEN_RELOAD_EVERY {
                    if let Err(e) = self.load_tokens() {
                        tracing::error!("token reload failed: {e}");
                    }
                    last_reload = Instant::now();
                }
            }
        })
    }

    /// Persist all pending deltas. Called by the flusher, and by management
    /// paths that want the numbers visible immediately.
    pub fn flush(&self) -> Result<(), String> {
        let (upserts, today) = {
            let mut usage = self.usage.lock();
            let upserts: Vec<(i64, u64)> = usage
                .map
                .iter()
                .filter(|(_, e)| e.delta > 0)
                .map(|(id, e)| (*id, e.delta))
                .collect();
            for e in usage.map.values_mut() {
                e.persisted = e.persisted.saturating_add(e.delta);
                e.delta = 0;
            }
            (upserts, today_unix())
        };
        if upserts.is_empty() {
            self.pending.store(0, Ordering::Relaxed);
            return Ok(());
        }
        let mut conn = self.conn.lock();
        let tx = conn
            .transaction()
            .map_err(|e| format!("cannot persist usage: {e}"))?;
        for (token_id, delta) in upserts {
            tx.execute(
                "INSERT INTO usage (token_id, day, wu) VALUES (?1, ?2, ?3)
                 ON CONFLICT(token_id, day) DO UPDATE SET wu = wu + excluded.wu",
                params![token_id, today, delta as i64],
            )
            .map_err(|e| format!("cannot persist usage: {e}"))?;
        }
        tx.commit()
            .map_err(|e| format!("cannot persist usage: {e}"))?;
        self.pending.store(0, Ordering::Relaxed);
        Ok(())
    }

    fn note_request(&self) {
        let n = self.pending.fetch_add(1, Ordering::Relaxed) + 1;
        if n % 100 == 0 {
            self.flush_notify.notify_one();
        }
    }

    fn ensure_day(usage: &mut UsageState) {
        let today = today_unix();
        if usage.day != today {
            for e in usage.map.values_mut() {
                e.persisted = RELOAD;
            }
            usage.day = today;
        }
    }

    /// The mutable usage entry for `token_id`, loading the persisted total
    /// from SQLite on first touch or after a day rollover.
    fn usage_entry<'a>(&self, usage: &'a mut UsageState, token_id: i64) -> &'a mut UsageEntry {
        let e = usage.map.entry(token_id).or_insert_with(|| UsageEntry {
            persisted: RELOAD,
            delta: 0,
        });
        if e.persisted == RELOAD {
            e.persisted = self.sum_usage(token_id);
        }
        e
    }

    fn sum_usage(&self, token_id: i64) -> u64 {
        let today = today_unix();
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT COALESCE(SUM(wu), 0) FROM usage WHERE token_id = ?1 AND day > ?2",
            params![token_id, today - 30],
            |r| r.get::<_, i64>(0),
        )
        .map(|v| v.max(0) as u64)
        .unwrap_or_else(|e| {
            tracing::error!(token = token_id, "cannot sum usage, treating as zero: {e}");
            0
        })
    }

    fn load_tokens(&self) -> Result<(), String> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare(
                "SELECT id, token_hash, prev_token_hash, prev_grace_until, tier, status, valid_until
                 FROM tokens",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, Option<Vec<u8>>>(2)?,
                    r.get::<_, Option<i64>>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, Option<i64>>(6)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        let now = unix_now();
        let mut tokens = HashMap::new();
        for row in rows {
            let (id, hash, prev_hash, prev_grace_until, tier, status, valid_until) =
                row.map_err(|e| e.to_string())?;
            let row = TokenRow {
                id,
                tier: parse_tier(&tier)?,
                status: parse_status(&status)?,
                valid_until: valid_until.map(|v| v as u64),
                prev_hash: prev_hash
                    .as_deref()
                    .and_then(|h| <[u8; 32]>::try_from(h).ok()),
                prev_grace_until: prev_grace_until.map(|v| v as u64),
            };
            let hash: [u8; 32] = hash
                .as_slice()
                .try_into()
                .map_err(|_| "token_hash column is not 32 bytes".to_owned())?;
            tokens.insert(hash, row.clone());
            if let Some(prev) = row.prev_hash {
                if row.prev_grace_until.is_some_and(|g| g > now) {
                    tokens.insert(prev, row);
                }
            }
        }
        drop(stmt);
        drop(conn);
        *self.tokens.write() = tokens;
        Ok(())
    }

    /// One row by current or previous hash, straight from the database. Used
    /// on a cache miss so a token issued by the CLI works immediately.
    fn lookup_db(&self, hash: &[u8; 32]) -> Option<TokenRow> {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT id, prev_token_hash, prev_grace_until, tier, status, valid_until
             FROM tokens WHERE token_hash = ?1 OR prev_token_hash = ?1",
            params![hash.as_slice()],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, Option<Vec<u8>>>(1)?,
                    r.get::<_, Option<i64>>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, Option<i64>>(5)?,
                ))
            },
        )
        .ok()
        .and_then(
            |(id, prev_hash, prev_grace_until, tier, status, valid_until)| {
                Some(TokenRow {
                    id,
                    tier: parse_tier(&tier).ok()?,
                    status: parse_status(&status).ok()?,
                    valid_until: valid_until.map(|v| v as u64),
                    prev_hash: prev_hash
                        .as_deref()
                        .and_then(|h| <[u8; 32]>::try_from(h).ok()),
                    prev_grace_until: prev_grace_until.map(|v| v as u64),
                })
            },
        )
    }

    /// Apply `f` to every cache entry of token `id` (current and, during
    /// grace, previous hash), so a status change never leaves one behind.
    fn update_cached(&self, id: i64, f: impl Fn(&mut TokenRow)) {
        for row in self.tokens.write().values_mut() {
            if row.id == id {
                f(row);
            }
        }
    }

    // ── management API ────────────────────────────────────────────────────

    /// Issue a new token. The raw token is returned exactly once; only its
    /// SHA-256 is stored. `valid_until` is a unix timestamp, `None` = never.
    pub fn issue(&self, tier: Tier, valid_until: Option<u64>) -> String {
        let token = generate_token();
        self.issue_token(&token, tier, valid_until);
        token
    }

    /// Register a raw token the caller derived (the storefront derives a
    /// Pro token from its invoice id and a secret, so nothing raw is ever
    /// at rest). Only the hash is stored, as with [`SqliteStore::issue`].
    /// A hash already present is left as it is.
    pub fn issue_token(&self, token: &str, tier: Tier, valid_until: Option<u64>) {
        let hash = token_hash(token);
        if self.tokens.read().contains_key(&hash) {
            return;
        }
        let now = unix_now();
        let row = TokenRow {
            id: 0,
            tier,
            status: TokenStatus::Active,
            valid_until,
            prev_hash: None,
            prev_grace_until: None,
        };
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO tokens (token_hash, prev_token_hash, prev_grace_until, tier, status, valid_until, created_at)
             VALUES (?1, NULL, NULL, ?2, 'active', ?3, ?4)",
            params![
                hash.as_slice(),
                tier.label(),
                valid_until.map(|v| v as i64),
                now as i64
            ],
        )
        .expect("local token database");
        let id = conn.last_insert_rowid();
        drop(conn);
        let mut row = row;
        row.id = id;
        self.tokens.write().insert(hash, row);
    }

    /// The `valid_until` of a current token, `Some(None)` for "never",
    /// `None` for an unknown token.
    pub fn valid_until(&self, hash: &[u8; 32]) -> Option<Option<u64>> {
        let cached = self.tokens.read().get(hash).map(|r| r.valid_until);
        // A previous hash past its grace is not cached but still names the
        // row (a renewal invoice may carry it; see `extend`).
        cached.or_else(|| self.lookup_db(hash).map(|r| r.valid_until))
    }

    /// `(current, previous)` hashes of the token row that `hash` names as
    /// either, so a lookup keyed on a hash survives a rotation.
    fn hashes_of(&self, hash: &[u8; 32]) -> Option<([u8; 32], Option<[u8; 32]>)> {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT token_hash, prev_token_hash FROM tokens
             WHERE token_hash = ?1 OR prev_token_hash = ?1",
            params![hash.as_slice()],
            |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Option<Vec<u8>>>(1)?)),
        )
        .ok()
        .and_then(|(cur, prev)| {
            Some((
                cur.as_slice().try_into().ok()?,
                prev.as_deref().and_then(|h| <[u8; 32]>::try_from(h).ok()),
            ))
        })
    }

    /// Both hashes of the row `hash` names, for a two-value `IN` clause;
    /// `hash` twice when it names no row.
    fn hash_pair(&self, hash: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        match self.hashes_of(hash) {
            Some((cur, prev)) => (cur, prev.unwrap_or(cur)),
            None => (*hash, *hash),
        }
    }

    /// Tier, whether it is active (not suspended), and `valid_until` of a
    /// current token (a previous hash in its grace window does not count).
    pub fn token_state(&self, hash: &[u8; 32]) -> Option<TokenState> {
        let tokens = self.tokens.read();
        let r = tokens.get(hash)?;
        if r.prev_hash == Some(*hash) {
            return None;
        }
        Some(TokenState {
            tier: r.tier,
            active: r.status == TokenStatus::Active,
            valid_until: r.valid_until,
        })
    }

    /// A pending invoice that would renew the token with this hash, if any.
    /// An invoice opened before the token was rotated is found by either
    /// hash, so a rotation neither strands it nor lets a second one open.
    pub fn pending_invoice_for(&self, hash: &[u8; 32]) -> Option<Invoice> {
        let (a, b) = self.hash_pair(hash);
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT id, subaddr_index, address, amount, months, renew_hash, created_at, expires_at, status, received, paid_at, usd_cents, rate_usd_per_xmr, rate_at, rate_sources
             FROM invoices WHERE renew_hash IN (?1, ?2) AND status = 'pending' LIMIT 1",
            params![a.as_slice(), b.as_slice()],
            Self::row_to_invoice,
        )
        .ok()
    }

    // ── upstream stats and public logs (plan §4: the numbers on the
    //    upstreams page survive a restart) ─────────────────────────────

    /// Persisted `(requests, verified, faults, ejected_until)` per upstream name.
    pub fn load_upstream_stats(&self) -> HashMap<String, UpstreamStats> {
        let conn = self.conn.lock();
        let mut stmt = match conn
            .prepare("SELECT name, requests, verified, faults, ejected_until, probes, up, stream_bytes FROM upstream_stats")
        {
            Ok(s) => s,
            Err(_) => return HashMap::new(),
        };
        stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                UpstreamStats {
                    requests: r.get::<_, i64>(1)? as u64,
                    verified: r.get::<_, i64>(2)? as u64,
                    faults: r.get::<_, i64>(3)? as u64,
                    ejected_until: r.get::<_, Option<i64>>(4)?.map(|v| v as u64),
                    probes: r.get::<_, i64>(5)? as u64,
                    up: r.get::<_, i64>(6)? as u64,
                    stream_bytes: r.get::<_, i64>(7)? as u64,
                },
            ))
        })
        .map(|rows| rows.filter_map(Result::ok).collect())
        .unwrap_or_default()
    }

    pub fn save_upstream_stats(&self, stats: &[(String, UpstreamStats)]) -> Result<(), String> {
        let conn = self.conn.lock();
        for (name, st) in stats {
            conn.execute(
                "INSERT INTO upstream_stats (name, requests, verified, faults, ejected_until, probes, up, stream_bytes)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(name) DO UPDATE SET requests = excluded.requests, verified = excluded.verified,
                   faults = excluded.faults, ejected_until = excluded.ejected_until,
                   probes = excluded.probes, up = excluded.up, stream_bytes = excluded.stream_bytes",
                params![
                    name,
                    st.requests as i64,
                    st.verified as i64,
                    st.faults as i64,
                    st.ejected_until.map(|v| v as i64),
                    st.probes as i64,
                    st.up as i64,
                    st.stream_bytes as i64
                ],
            )
            .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    pub fn append_fault(&self, f: &FaultEvent) -> Result<(), String> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO fault_log (at_unix, upstream, method, detail, ejected, ejected_until) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                f.at_unix as i64,
                f.upstream,
                f.method,
                f.detail,
                i64::from(f.ejected),
                f.ejected_until.map(|v| v as i64)
            ],
        )
        .map(|_| ())
        .map_err(|e| e.to_string())
    }

    /// Drop everything but the newest `keep` faults, so the table does not
    /// grow without bound over months.
    pub fn prune_faults(&self, keep: usize) {
        let conn = self.conn.lock();
        let _ = conn.execute(
            "DELETE FROM fault_log WHERE id NOT IN (SELECT id FROM fault_log ORDER BY id DESC LIMIT ?1)",
            params![keep as i64],
        );
    }

    /// Wipe the fault log and every upstream's fault count and ejection:
    /// the operator's tool after a verifier bug faulted honest nodes.
    /// Returns how many log rows were removed.
    pub fn clear_faults(&self) -> Result<usize, String> {
        let conn = self.conn.lock();
        let n = conn
            .execute("DELETE FROM fault_log", [])
            .map_err(|e| e.to_string())?;
        conn.execute(
            "UPDATE upstream_stats SET faults = 0, ejected_until = NULL",
            [],
        )
        .map_err(|e| e.to_string())?;
        Ok(n)
    }

    /// The newest `limit` faults, oldest first.
    pub fn load_faults(&self, limit: usize) -> Vec<FaultEvent> {
        let conn = self.conn.lock();
        let mut stmt = match conn.prepare(
            "SELECT at_unix, upstream, method, detail, ejected, ejected_until FROM fault_log ORDER BY id DESC LIMIT ?1",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let mut v: Vec<FaultEvent> = stmt
            .query_map(params![limit as i64], |r| {
                Ok(FaultEvent {
                    at_unix: r.get::<_, i64>(0)? as u64,
                    upstream: r.get(1)?,
                    method: r.get(2)?,
                    detail: r.get(3)?,
                    ejected: r.get::<_, i64>(4)? != 0,
                    ejected_until: r.get::<_, Option<i64>>(5)?.map(|v| v as u64),
                })
            })
            .map(|rows| rows.filter_map(Result::ok).collect())
            .unwrap_or_default();
        v.reverse();
        v
    }

    pub fn append_opt_out(&self, o: &OptOutEvent) -> Result<(), String> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO opt_out_log (at_unix, upstream, host) VALUES (?1, ?2, ?3)",
            params![o.at_unix as i64, o.upstream, o.host],
        )
        .map(|_| ())
        .map_err(|e| e.to_string())
    }

    pub fn load_opt_outs(&self) -> Vec<OptOutEvent> {
        let conn = self.conn.lock();
        let mut stmt = match conn
            .prepare("SELECT at_unix, upstream, host FROM opt_out_log ORDER BY at_unix")
        {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        stmt.query_map([], |r| {
            Ok(OptOutEvent {
                at_unix: r.get::<_, i64>(0)? as u64,
                upstream: r.get(1)?,
                host: r.get(2)?,
            })
        })
        .map(|rows| rows.filter_map(Result::ok).collect())
        .unwrap_or_default()
    }

    // ── invoices (storefront, plan §5) ──────────────────────────────────

    pub fn create_invoice(&self, inv: &Invoice) -> Result<(), String> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO invoices (id, subaddr_index, address, amount, months, renew_hash, created_at, expires_at, status, received, paid_at, usd_cents, rate_usd_per_xmr, rate_at, rate_sources)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'pending', 0, NULL, ?9, ?10, ?11, ?12)",
            params![
                inv.id,
                inv.subaddr_index as i64,
                inv.address,
                inv.amount as i64,
                inv.months as i64,
                inv.renew_hash.as_ref().map(|h| h.as_slice()),
                inv.created_at as i64,
                inv.expires_at as i64,
                inv.usd_cents.map(|v| v as i64),
                inv.rate_usd_per_xmr,
                inv.rate_at.map(|v| v as i64),
                inv.rate_sources.as_deref(),
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn invoice(&self, id: &str) -> Option<Invoice> {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT id, subaddr_index, address, amount, months, renew_hash, created_at, expires_at, status, received, paid_at, usd_cents, rate_usd_per_xmr, rate_at, rate_sources
             FROM invoices WHERE id = ?1",
            params![id],
            Self::row_to_invoice,
        )
        .ok()
    }

    /// Every invoice still waiting for its payment.
    pub fn pending_invoices(&self) -> Vec<Invoice> {
        let conn = self.conn.lock();
        let mut stmt = match conn.prepare(
            "SELECT id, subaddr_index, address, amount, months, renew_hash, created_at, expires_at, status, received, paid_at, usd_cents, rate_usd_per_xmr, rate_at, rate_sources
             FROM invoices WHERE status = 'pending'",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        stmt.query_map([], Self::row_to_invoice)
            .map(|rows| rows.filter_map(Result::ok).collect())
            .unwrap_or_default()
    }

    /// The most recent invoice that renewed (or created) the token with
    /// this hash, so a renewal can reuse its subaddress.
    pub fn latest_invoice_for(&self, hash: &[u8; 32]) -> Option<Invoice> {
        let (a, b) = self.hash_pair(hash);
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT id, subaddr_index, address, amount, months, renew_hash, created_at, expires_at, status, received, paid_at, usd_cents, rate_usd_per_xmr, rate_at, rate_sources
             FROM invoices WHERE renew_hash IN (?1, ?2) ORDER BY created_at DESC LIMIT 1",
            params![a.as_slice(), b.as_slice()],
            Self::row_to_invoice,
        )
        .ok()
    }

    /// The paid purchase invoice (no renewal target) whose derived token has
    /// hash `hash`, found by re-deriving over the paid purchases with
    /// `derive` (there are few, and this runs on a renewal only).
    pub fn purchase_invoice_for(
        &self,
        hash: &[u8; 32],
        derive: impl Fn(&str) -> [u8; 32],
    ) -> Option<Invoice> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare(
                "SELECT id, subaddr_index, address, amount, months, renew_hash, created_at, expires_at, status, received, paid_at, usd_cents, rate_usd_per_xmr, rate_at, rate_sources
                 FROM invoices WHERE status = 'paid' AND renew_hash IS NULL ORDER BY created_at DESC",
            )
            .ok()?;
        let rows: Vec<Invoice> = stmt
            .query_map([], Self::row_to_invoice)
            .ok()?
            .filter_map(Result::ok)
            .collect();
        rows.into_iter().find(|inv| derive(&inv.id) == *hash)
    }

    /// Record what an invoice's subaddress has received and, when `paid`,
    /// close it.
    pub fn update_invoice(&self, id: &str, received: u64, paid: bool) -> Result<(), String> {
        let conn = self.conn.lock();
        if paid {
            conn.execute(
                "UPDATE invoices SET received = ?1, status = 'paid', paid_at = ?2 WHERE id = ?3",
                params![received as i64, unix_now() as i64, id],
            )
        } else {
            conn.execute(
                "UPDATE invoices SET received = ?1 WHERE id = ?2",
                params![received as i64, id],
            )
        }
        .map(|_| ())
        .map_err(|e| e.to_string())
    }

    /// Expire pending invoices past their deadline; returns how many.
    pub fn expire_invoices(&self, now: u64) -> usize {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE invoices SET status = 'expired' WHERE status = 'pending' AND expires_at < ?1",
            params![now as i64],
        )
        .unwrap_or(0)
    }

    fn row_to_invoice(r: &rusqlite::Row<'_>) -> rusqlite::Result<Invoice> {
        let renew: Option<Vec<u8>> = r.get(5)?;
        let status: String = r.get(8)?;
        Ok(Invoice {
            id: r.get(0)?,
            subaddr_index: r.get::<_, i64>(1)? as u32,
            address: r.get(2)?,
            amount: r.get::<_, i64>(3)? as u64,
            months: r.get::<_, i64>(4)? as u32,
            renew_hash: renew.and_then(|v| v.try_into().ok()),
            created_at: r.get::<_, i64>(6)? as u64,
            expires_at: r.get::<_, i64>(7)? as u64,
            status: match status.as_str() {
                "paid" => InvoiceStatus::Paid,
                "expired" => InvoiceStatus::Expired,
                _ => InvoiceStatus::Pending,
            },
            received: r.get::<_, i64>(9)? as u64,
            paid_at: r.get::<_, Option<i64>>(10)?.map(|v| v as u64),
            usd_cents: r.get::<_, Option<i64>>(11)?.map(|v| v as u64),
            rate_usd_per_xmr: r.get::<_, Option<f64>>(12)?,
            rate_at: r.get::<_, Option<i64>>(13)?.map(|v| v as u64),
            rate_sources: r.get::<_, Option<String>>(14)?,
        })
    }

    /// The last accepted XMR/USD rate, if one was persisted.
    pub fn load_rate(&self) -> Option<crate::price::Rate> {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT usd_per_xmr, at_unix, sources FROM rates WHERE id = 1",
            [],
            |r| {
                Ok(crate::price::Rate {
                    usd_per_xmr: r.get(0)?,
                    at_unix: r.get::<_, i64>(1)? as u64,
                    sources: r
                        .get::<_, String>(2)?
                        .split(',')
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned)
                        .collect(),
                })
            },
        )
        .ok()
    }

    pub fn save_rate(&self, rate: &crate::price::Rate) -> Result<(), String> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO rates (id, usd_per_xmr, at_unix, sources) VALUES (1, ?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET usd_per_xmr = excluded.usd_per_xmr, at_unix = excluded.at_unix, sources = excluded.sources",
            params![rate.usd_per_xmr, rate.at_unix as i64, rate.sources.join(",")],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Rotate the token whose *current* hash is `hash`: the new token becomes
    /// current and `hash` stays valid as the previous hash for 24 h. Returns
    /// the new raw token; errors if `hash` is not a current token (a previous
    /// hash cannot be rotated again).
    pub fn rotate(&self, hash: &[u8; 32]) -> Result<String, String> {
        let new_token = generate_token();
        let new_hash = token_hash(&new_token);
        let grace_until = unix_now() + GRACE_SECS;
        let conn = self.conn.lock();
        let n = conn
            .execute(
                "UPDATE tokens SET token_hash = ?1, prev_token_hash = ?2, prev_grace_until = ?3
                 WHERE token_hash = ?2",
                params![new_hash.as_slice(), hash.as_slice(), grace_until as i64],
            )
            .map_err(|e| e.to_string())?;
        drop(conn);
        if n == 0 {
            return Err("unknown or already rotated token".to_owned());
        }
        let mut tokens = self.tokens.write();
        if let Some(mut row) = tokens.remove(hash) {
            if let Some(older) = row.prev_hash {
                tokens.remove(&older);
            }
            row.prev_hash = Some(*hash);
            row.prev_grace_until = Some(grace_until);
            tokens.insert(new_hash, row.clone());
            tokens.insert(*hash, row);
        }
        Ok(new_token)
    }

    /// Resolve an 8-hex handle to the current token hash. Errors if the handle
    /// is unknown or matches more than one token.
    pub fn find_hash(&self, handle_str: &str) -> Result<[u8; 32], String> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare(
                "SELECT token_hash FROM tokens WHERE LOWER(hex(substr(token_hash, 1, 4))) = ?1",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![handle_str.to_lowercase()], |r| {
                r.get::<_, Vec<u8>>(0)
            })
            .map_err(|e| e.to_string())?;
        let mut found = Vec::new();
        for row in rows {
            let bytes = row.map_err(|e| e.to_string())?;
            if let Ok(h) = <[u8; 32]>::try_from(bytes.as_slice()) {
                found.push(h);
            }
        }
        match found.len() {
            0 => Err(format!("unknown handle {handle_str}")),
            1 => Ok(found[0]),
            _ => Err(format!("ambiguous handle {handle_str}")),
        }
    }

    pub fn suspend(&self, hash: &[u8; 32]) -> Result<(), String> {
        let conn = self.conn.lock();
        let n = conn
            .execute(
                "UPDATE tokens SET status = 'suspended' WHERE token_hash = ?1",
                params![hash.as_slice()],
            )
            .map_err(|e| e.to_string())?;
        drop(conn);
        if n == 0 {
            return Err("unknown token".to_owned());
        }
        // Bind the id first: the read guard must be gone before the write.
        let id = self.tokens.read().get(hash).map(|r| r.id);
        if let Some(id) = id {
            self.update_cached(id, |r| r.status = TokenStatus::Suspended);
        }
        Ok(())
    }

    /// Extend a token's `valid_until` (unix timestamp). `hash` may be the
    /// token's current or previous hash: a renewal invoice carries the hash
    /// at the time it was opened, and the customer may rotate before paying.
    pub fn extend(&self, hash: &[u8; 32], valid_until: u64) -> Result<(), String> {
        let conn = self.conn.lock();
        let n = conn
            .execute(
                "UPDATE tokens SET valid_until = ?1 WHERE token_hash = ?2 OR prev_token_hash = ?2",
                params![valid_until as i64, hash.as_slice()],
            )
            .map_err(|e| e.to_string())?;
        drop(conn);
        if n == 0 {
            return Err("unknown token".to_owned());
        }
        let id = self.tokens.read().get(hash).map(|r| r.id);
        let id = id.or_else(|| self.lookup_db(hash).map(|r| r.id));
        if let Some(id) = id {
            self.update_cached(id, |r| r.valid_until = Some(valid_until));
        }
        Ok(())
    }

    /// Every token, with the WU it used in the last 30 days. Never reveals a
    /// hash: only the 8-character handle.
    pub fn list(&self) -> Vec<TokenSummary> {
        let conn = self.conn.lock();
        let today = today_unix();
        let mut stmt = conn
            .prepare(
                "SELECT t.id, t.token_hash, t.tier, t.status, t.valid_until,
                        COALESCE((SELECT SUM(wu) FROM usage WHERE token_id = t.id AND day > ?1), 0)
                 FROM tokens t ORDER BY t.id",
            )
            .expect("local token database");
        let rows = stmt
            .query_map(params![today - 30], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, Option<i64>>(4)?,
                    r.get::<_, i64>(5)?,
                ))
            })
            .expect("local token database");
        let mut out = Vec::new();
        for row in rows {
            let (_, hash, tier, status, valid_until, wu) = row.expect("local token database");
            let hash: [u8; 32] = hash.as_slice().try_into().unwrap_or([0; 32]);
            out.push(TokenSummary {
                handle: handle(&hash),
                tier: parse_tier(&tier).unwrap_or(Tier::Free),
                status,
                valid_until: valid_until.map(|v| v as u64),
                wu_used_30d: wu.max(0) as u64,
            });
        }
        out
    }

    #[cfg(test)]
    pub(crate) fn conn(&self) -> parking_lot::MutexGuard<'_, Connection> {
        self.conn.lock()
    }
}

impl TokenStore for SqliteStore {
    fn authenticate(&self, hash: &[u8; 32]) -> Result<Principal, AuthError> {
        let cached = self.tokens.read().get(hash).cloned();
        let row = match cached {
            Some(r) => r,
            None => {
                // Cache miss: a token the CLI issued since the last reload.
                // Only token-shaped input reaches here, so this is one
                // indexed lookup per unknown token, not per junk request.
                let row = self.lookup_db(hash).ok_or(AuthError::Unknown)?;
                self.tokens.write().insert(*hash, row.clone());
                row
            }
        };
        let now = unix_now();
        // A previous hash only authenticates while its grace window is open.
        if row.prev_hash == Some(*hash) && row.prev_grace_until.is_some_and(|g| g <= now) {
            return Err(AuthError::Unknown);
        }
        match row.status {
            TokenStatus::Suspended => return Err(AuthError::Expired),
            TokenStatus::Active => {}
        }
        if row.valid_until.is_some_and(|v| v < now) {
            return Err(AuthError::Expired);
        }
        Ok(Principal {
            id: row.id,
            tier: row.tier,
            handle: handle(hash),
        })
    }
}

impl Limiter for SqliteStore {
    fn admit(&self, principal: &Principal, wu: u64) -> Verdict {
        if let Err(retry_after_secs) = self.burst.take_burst(principal, Instant::now()) {
            return Verdict::RateLimited { retry_after_secs };
        }
        let mut usage = self.usage.lock();
        Self::ensure_day(&mut usage);
        let e = self.usage_entry(&mut usage, principal.id);
        let used = e.persisted.saturating_add(e.delta);
        if used.saturating_add(wu) > principal.tier.monthly_wu() {
            return Verdict::QuotaExceeded;
        }
        e.delta = e.delta.saturating_add(wu);
        drop(usage);
        self.note_request();
        Verdict::Allow
    }

    fn charge(&self, principal: &Principal, wu: u64) {
        let mut usage = self.usage.lock();
        Self::ensure_day(&mut usage);
        let e = self.usage_entry(&mut usage, principal.id);
        e.delta = e.delta.saturating_add(wu);
        drop(usage);
        self.note_request();
    }

    fn take_stream(&self, principal: &Principal) -> Option<StreamPermit> {
        self.burst.take_stream(principal)
    }

    #[cfg(test)]
    fn used(&self, principal: &Principal) -> u64 {
        let mut usage = self.usage.lock();
        Self::ensure_day(&mut usage);
        let e = self.usage_entry(&mut usage, principal.id);
        e.persisted.saturating_add(e.delta)
    }
}

fn init_schema(conn: &Connection) -> Result<(), String> {
    let version: i64 = conn
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .map_err(|e| e.to_string())?;
    if version > SCHEMA_VERSION {
        return Err(format!(
            "token database schema version {version} is newer than supported {SCHEMA_VERSION}"
        ));
    }
    if version < SCHEMA_VERSION {
        conn.execute_batch(SCHEMA)
            .map_err(|e| format!("cannot create token schema: {e}"))?;
        // v4: uptime counters, v5: stream bytes, on an upstream_stats table
        // that already exists (CREATE IF NOT EXISTS leaves it alone).
        let added: &[&str] = match version {
            3 => &["probes", "up", "stream_bytes"],
            4 => &["stream_bytes"],
            _ => &[],
        };
        for col in added {
            let _ = conn.execute(
                &format!("ALTER TABLE upstream_stats ADD COLUMN {col} INTEGER NOT NULL DEFAULT 0"),
                [],
            );
        }
        // v6: the rate behind each invoice, on an invoices table that has
        // existed since v2 (the rates table itself is new and created above).
        if (2..=5).contains(&version) {
            for (col, ty) in [
                ("usd_cents", "INTEGER"),
                ("rate_usd_per_xmr", "REAL"),
                ("rate_at", "INTEGER"),
                ("rate_sources", "TEXT"),
            ] {
                let _ = conn.execute(&format!("ALTER TABLE invoices ADD COLUMN {col} {ty}"), []);
            }
        }
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn parse_tier(s: &str) -> Result<Tier, String> {
    match s {
        "free" => Ok(Tier::Free),
        "pro" => Ok(Tier::Pro),
        other => Err(format!("unknown tier {other:?}")),
    }
}

fn parse_status(s: &str) -> Result<TokenStatus, String> {
    match s {
        "active" => Ok(TokenStatus::Active),
        "suspended" => Ok(TokenStatus::Suspended),
        other => Err(format!("unknown status {other:?}")),
    }
}

fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("operating system random source");
    format!("sub_{}", base58_encode(&bytes))
}

/// Base58, Bitcoin alphabet — the same one `auth::looks_like_token` accepts.
pub fn base58_encode(bytes: &[u8]) -> String {
    const B58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut zeros = 0;
    while zeros < bytes.len() && bytes[zeros] == 0 {
        zeros += 1;
    }
    let mut digits: Vec<u8> = Vec::new();
    for &b in &bytes[zeros..] {
        let mut carry = u32::from(b);
        for d in digits.iter_mut() {
            let v = (u32::from(*d) << 8) + carry;
            *d = (v % 58) as u8;
            carry = v / 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut s = String::with_capacity(bytes.len() * 2);
    for _ in 0..zeros {
        s.push('1');
    }
    for d in digits.iter().rev() {
        s.push(B58[usize::from(*d)] as char);
    }
    s
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Day number: unix seconds / 86400.
fn today_unix() -> i64 {
    (unix_now() / 86_400) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_v1_database_migrates_and_keeps_its_tokens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v1.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE tokens(id INTEGER PRIMARY KEY, token_hash BLOB UNIQUE NOT NULL, prev_token_hash BLOB, prev_grace_until INTEGER, tier TEXT NOT NULL, status TEXT NOT NULL, valid_until INTEGER, created_at INTEGER NOT NULL);
                 CREATE TABLE usage(token_id INTEGER NOT NULL, day INTEGER NOT NULL, wu INTEGER NOT NULL, PRIMARY KEY(token_id, day));
                 INSERT INTO tokens VALUES (1, X'0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20', NULL, NULL, 'pro', 'active', NULL, 1);
                 INSERT INTO usage VALUES (1, 20000, 77);
                 PRAGMA user_version = 1;",
            )
            .unwrap();
        }
        let store = SqliteStore::open(Some(&path)).unwrap();
        let hash: [u8; 32] = (1..=32u8).collect::<Vec<_>>().try_into().unwrap();
        assert_eq!(store.authenticate(&hash).unwrap().tier, Tier::Pro);
        assert_eq!(
            store.list()[0].wu_used_30d,
            0,
            "a usage day far in the past is outside the window"
        );
        assert!(
            store.pending_invoices().is_empty(),
            "invoices table exists and is empty"
        );
        let v: i64 = store
            .conn()
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
    }

    #[test]
    fn schema_v2_database_migrates_to_v3_with_empty_stats_tables() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v2.db");
        {
            let conn = Connection::open(&path).unwrap();
            // A v2 file: tokens, usage and invoices, nothing else.
            conn.execute_batch(
                "CREATE TABLE tokens(id INTEGER PRIMARY KEY, token_hash BLOB UNIQUE NOT NULL, prev_token_hash BLOB, prev_grace_until INTEGER, tier TEXT NOT NULL, status TEXT NOT NULL, valid_until INTEGER, created_at INTEGER NOT NULL);
                 CREATE TABLE usage(token_id INTEGER NOT NULL, day INTEGER NOT NULL, wu INTEGER NOT NULL, PRIMARY KEY(token_id, day));
                 CREATE TABLE invoices(id TEXT PRIMARY KEY, subaddr_index INTEGER NOT NULL, address TEXT NOT NULL, amount INTEGER NOT NULL, months INTEGER NOT NULL, renew_hash BLOB, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, status TEXT NOT NULL, received INTEGER NOT NULL DEFAULT 0, paid_at INTEGER);
                 INSERT INTO tokens VALUES (1, X'0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20', NULL, NULL, 'free', 'active', NULL, 1);
                 PRAGMA user_version = 2;",
            )
            .unwrap();
        }
        let store = SqliteStore::open(Some(&path)).unwrap();
        let v: i64 = store
            .conn()
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
        assert!(store.load_upstream_stats().is_empty());
        assert!(store.load_faults(10).is_empty());
        assert!(store.load_opt_outs().is_empty());
        let hash: [u8; 32] = (1..=32u8).collect::<Vec<_>>().try_into().unwrap();
        assert_eq!(store.authenticate(&hash).unwrap().tier, Tier::Free);
        // Pruning keeps the newest rows.
        for i in 0..20u64 {
            store
                .append_fault(&FaultEvent {
                    at_unix: i,
                    upstream: "u".into(),
                    method: "m".into(),
                    detail: i.to_string(),
                    ejected: false,
                    ejected_until: None,
                })
                .unwrap();
        }
        store.prune_faults(5);
        let kept = store.load_faults(100);
        assert_eq!(kept.len(), 5);
        assert_eq!(kept[0].detail, "15");
        assert_eq!(kept[4].detail, "19");
        store
            .save_upstream_stats(&[(
                "u".into(),
                UpstreamStats {
                    requests: 9,
                    verified: 4,
                    faults: 5,
                    probes: 100,
                    up: 97,
                    ejected_until: Some(u64::MAX),
                    stream_bytes: 0,
                },
            )])
            .unwrap();
        assert_eq!(store.clear_faults().unwrap(), 5);
        assert!(store.load_faults(10).is_empty());
        let st = store.load_upstream_stats()["u"];
        assert_eq!(
            (st.requests, st.verified, st.faults, st.ejected_until),
            (9, 4, 0, None)
        );
    }

    #[test]
    fn schema_v4_database_gains_stream_bytes_and_keeps_its_stats() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v4.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE tokens(id INTEGER PRIMARY KEY, token_hash BLOB UNIQUE NOT NULL, prev_token_hash BLOB, prev_grace_until INTEGER, tier TEXT NOT NULL, status TEXT NOT NULL, valid_until INTEGER, created_at INTEGER NOT NULL);
                 CREATE TABLE usage(token_id INTEGER NOT NULL, day INTEGER NOT NULL, wu INTEGER NOT NULL, PRIMARY KEY(token_id, day));
                 CREATE TABLE invoices(id TEXT PRIMARY KEY, subaddr_index INTEGER NOT NULL, address TEXT NOT NULL, amount INTEGER NOT NULL, months INTEGER NOT NULL, renew_hash BLOB, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, status TEXT NOT NULL, received INTEGER NOT NULL DEFAULT 0, paid_at INTEGER);
                 CREATE TABLE upstream_stats(name TEXT PRIMARY KEY, requests INTEGER NOT NULL, verified INTEGER NOT NULL, faults INTEGER NOT NULL, ejected_until INTEGER, probes INTEGER NOT NULL DEFAULT 0, up INTEGER NOT NULL DEFAULT 0);
                 INSERT INTO upstream_stats VALUES ('own-1', 500, 200, 1, NULL, 400, 399);
                 PRAGMA user_version = 4;",
            )
            .unwrap();
        }
        let store = SqliteStore::open(Some(&path)).unwrap();
        let v: i64 = store
            .conn()
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
        let got = store.load_upstream_stats();
        assert_eq!(
            got["own-1"],
            UpstreamStats {
                requests: 500,
                stream_bytes: 0,
                verified: 200,
                faults: 1,
                probes: 400,
                up: 399,
                ejected_until: None,
            }
        );
        store
            .save_upstream_stats(&[(
                "own-1".into(),
                UpstreamStats {
                    stream_bytes: 3_000_000,
                    ..got["own-1"]
                },
            )])
            .unwrap();
        assert_eq!(store.load_upstream_stats()["own-1"].stream_bytes, 3_000_000);
    }

    #[test]
    fn schema_v5_database_gains_rate_columns_and_a_rates_table() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v5.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE tokens(id INTEGER PRIMARY KEY, token_hash BLOB UNIQUE NOT NULL, prev_token_hash BLOB, prev_grace_until INTEGER, tier TEXT NOT NULL, status TEXT NOT NULL, valid_until INTEGER, created_at INTEGER NOT NULL);
                 CREATE TABLE usage(token_id INTEGER NOT NULL, day INTEGER NOT NULL, wu INTEGER NOT NULL, PRIMARY KEY(token_id, day));
                 CREATE TABLE invoices(id TEXT PRIMARY KEY, subaddr_index INTEGER NOT NULL, address TEXT NOT NULL, amount INTEGER NOT NULL, months INTEGER NOT NULL, renew_hash BLOB, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, status TEXT NOT NULL, received INTEGER NOT NULL DEFAULT 0, paid_at INTEGER);
                 CREATE TABLE upstream_stats(name TEXT PRIMARY KEY, requests INTEGER NOT NULL, verified INTEGER NOT NULL, faults INTEGER NOT NULL, ejected_until INTEGER, probes INTEGER NOT NULL DEFAULT 0, up INTEGER NOT NULL DEFAULT 0, stream_bytes INTEGER NOT NULL DEFAULT 0);
                 INSERT INTO invoices VALUES ('old1', 3, '8abc', 60000000000, 1, NULL, 1000, 90000, 'paid', 60000000000, 2000);
                 PRAGMA user_version = 5;",
            )
            .unwrap();
        }
        let store = SqliteStore::open(Some(&path)).unwrap();
        let v: i64 = store
            .conn()
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
        let old = store.invoice("old1").unwrap();
        assert_eq!(old.amount, 60_000_000_000);
        assert_eq!(
            (
                old.usd_cents,
                old.rate_usd_per_xmr,
                old.rate_at,
                old.rate_sources
            ),
            (None, None, None, None)
        );
        assert!(store.load_rate().is_none());
        let rate = crate::price::Rate {
            usd_per_xmr: 538.8,
            at_unix: 5_000,
            sources: vec!["kraken".into(), "coingecko".into()],
        };
        store.save_rate(&rate).unwrap();
        assert_eq!(store.load_rate(), Some(rate.clone()));
        store
            .save_rate(&crate::price::Rate {
                usd_per_xmr: 540.0,
                ..rate
            })
            .unwrap();
        assert_eq!(
            store.load_rate().unwrap().usd_per_xmr,
            540.0,
            "one row, replaced"
        );
    }

    #[test]
    fn invoices_round_trip_and_expire() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteStore::open(Some(&dir.path().join("i.db"))).unwrap();
        let inv = Invoice {
            id: "abc123".into(),
            subaddr_index: 7,
            address: "8xyz".into(),
            amount: 60_000_000_000,
            months: 2,
            renew_hash: Some([9; 32]),
            created_at: 1_000,
            expires_at: 2_000,
            status: InvoiceStatus::Pending,
            received: 0,
            paid_at: None,
            usd_cents: None,
            rate_usd_per_xmr: None,
            rate_at: None,
            rate_sources: None,
        };
        store.create_invoice(&inv).unwrap();
        assert_eq!(store.invoice("abc123"), Some(inv.clone()));
        assert_eq!(store.pending_invoices().len(), 1);
        assert_eq!(store.latest_invoice_for(&[9; 32]).unwrap().id, "abc123");
        store.update_invoice("abc123", 10, false).unwrap();
        assert_eq!(store.invoice("abc123").unwrap().received, 10);
        assert_eq!(store.expire_invoices(1_500), 0);
        assert_eq!(store.expire_invoices(2_500), 1);
        assert_eq!(
            store.invoice("abc123").unwrap().status,
            InvoiceStatus::Expired
        );
        assert!(store.pending_invoices().is_empty());
        let paid = Invoice {
            id: "def".into(),
            expires_at: 9_000,
            ..inv
        };
        store.create_invoice(&paid).unwrap();
        store.update_invoice("def", 60_000_000_000, true).unwrap();
        let got = store.invoice("def").unwrap();
        assert_eq!(got.status, InvoiceStatus::Paid);
        assert!(got.paid_at.is_some());
        // Derived tokens register by hash only, once.
        store.issue_token(
            "sub_derivedtoken1111111111111111111111111111",
            Tier::Pro,
            Some(5_000),
        );
        store.issue_token(
            "sub_derivedtoken1111111111111111111111111111",
            Tier::Pro,
            Some(6_000),
        );
        let h = token_hash("sub_derivedtoken1111111111111111111111111111");
        assert_eq!(store.valid_until(&h), Some(Some(5_000)));
        assert_eq!(store.valid_until(&[0; 32]), None);
    }
    use crate::auth::looks_like_token;
    use crate::limits::LIGHT_WU;

    fn open_tmp(dir: &tempfile::TempDir) -> (SqliteStore, std::path::PathBuf) {
        let db = dir.path().join("t.db");
        (SqliteStore::open(Some(&db)).unwrap(), db)
    }

    #[test]
    fn renewal_lookups_and_extend_follow_a_rotated_token() {
        let s = SqliteStore::open(None).unwrap();
        let old = s.issue(Tier::Pro, Some(1));
        let old_hash = token_hash(&old);
        let inv = Invoice {
            id: "renew1".into(),
            subaddr_index: 3,
            address: "8abc".into(),
            amount: 1,
            months: 1,
            renew_hash: Some(old_hash),
            created_at: 1_000,
            expires_at: 9_000,
            status: InvoiceStatus::Pending,
            received: 0,
            paid_at: None,
            usd_cents: None,
            rate_usd_per_xmr: None,
            rate_at: None,
            rate_sources: None,
        };
        s.create_invoice(&inv).unwrap();
        let new = s.rotate(&old_hash).unwrap();
        let new_hash = token_hash(&new);
        // The invoice is found by either hash.
        assert_eq!(s.pending_invoice_for(&new_hash).unwrap().id, "renew1");
        assert_eq!(s.pending_invoice_for(&old_hash).unwrap().id, "renew1");
        assert_eq!(s.latest_invoice_for(&new_hash).unwrap().id, "renew1");
        // Paying it extends the rotated token, whichever hash the invoice holds.
        let later = unix_now() + 5_000;
        s.extend(&old_hash, later).unwrap();
        assert_eq!(s.valid_until(&new_hash), Some(Some(later)));
        assert_eq!(s.valid_until(&old_hash), Some(Some(later)));
        assert_eq!(s.authenticate(&new_hash).unwrap().tier, Tier::Pro);
        // A hash that names no row is still unknown.
        assert_eq!(s.extend(&[1; 32], 1), Err("unknown token".to_owned()));
        assert_eq!(s.pending_invoice_for(&[1; 32]), None);
    }

    #[test]
    fn authenticate_distinguishes_current_prev_expired_suspended_unknown() {
        let s = SqliteStore::open(None).unwrap();
        let token = s.issue(Tier::Free, None);
        let hash = token_hash(&token);
        let p = s.authenticate(&hash).unwrap();
        assert_eq!(p.tier, Tier::Free);
        assert_eq!(p.handle, handle(&hash));
        assert_eq!(s.authenticate(&[9; 32]), Err(AuthError::Unknown));

        // Rotate: the old hash still authenticates inside the grace window.
        let new_token = s.rotate(&hash).unwrap();
        let new_hash = token_hash(&new_token);
        assert_eq!(s.authenticate(&new_hash).unwrap().id, p.id);
        assert_eq!(s.authenticate(&hash).unwrap().id, p.id);

        // Suspending the new token refuses it.
        s.suspend(&new_hash).unwrap();
        assert_eq!(s.authenticate(&new_hash), Err(AuthError::Expired));

        // An already-expired token is refused, not unknown.
        let t2 = s.issue(Tier::Pro, Some(unix_now() - 1));
        assert_eq!(s.authenticate(&token_hash(&t2)), Err(AuthError::Expired));
    }

    #[test]
    fn prev_token_is_unknown_after_grace_expires() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("t.db");
        let (old_token, old_hash, new_token) = {
            let s = SqliteStore::open(Some(&db)).unwrap();
            let old_token = s.issue(Tier::Free, None);
            let old_hash = token_hash(&old_token);
            let new_token = s.rotate(&old_hash).unwrap();
            (old_token, old_hash, new_token)
        };
        // Within grace, both the new and the old hash work after a reopen.
        {
            let s = SqliteStore::open(Some(&db)).unwrap();
            assert_eq!(
                s.authenticate(&token_hash(&new_token)).unwrap().tier,
                Tier::Free
            );
            assert_eq!(s.authenticate(&old_hash).unwrap().tier, Tier::Free);
        }
        // Expire the grace window directly, then reopen: the old hash is now
        // unknown, the current (rotated) token is unaffected.
        {
            let s = SqliteStore::open(Some(&db)).unwrap();
            s.conn()
                .execute(
                    "UPDATE tokens SET prev_grace_until = 1 WHERE prev_token_hash = ?1",
                    params![old_hash.as_slice()],
                )
                .unwrap();
        }
        let s = SqliteStore::open(Some(&db)).unwrap();
        assert_eq!(s.authenticate(&old_hash), Err(AuthError::Unknown));
        assert_eq!(
            s.authenticate(&token_hash(&new_token)).unwrap().tier,
            Tier::Free
        );
        let _ = old_token;
    }

    #[test]
    fn suspend_after_rotate_refuses_the_previous_token_too() {
        let s = SqliteStore::open(None).unwrap();
        let old = token_hash(&s.issue(Tier::Pro, None));
        let new = token_hash(&s.rotate(&old).unwrap());
        assert!(s.authenticate(&old).is_ok());
        s.suspend(&new).unwrap();
        assert_eq!(s.authenticate(&new), Err(AuthError::Expired));
        assert_eq!(s.authenticate(&old), Err(AuthError::Expired));
        // A previous hash cannot be rotated, and an unknown one errors.
        assert!(s.rotate(&old).is_err());
        assert!(s.rotate(&[3; 32]).is_err());
    }

    #[test]
    fn token_issued_by_another_process_authenticates_on_cache_miss() {
        let dir = tempfile::tempdir().unwrap();
        let (relay, db) = open_tmp(&dir);
        // Simulates `mnr-relay token issue` running while the relay is up.
        let cli = SqliteStore::open(Some(&db)).unwrap();
        let token = cli.issue(Tier::Free, None);
        let hash = token_hash(&token);
        assert_eq!(relay.authenticate(&hash).unwrap().tier, Tier::Free);
        // And a CLI suspension is visible after the periodic reload.
        cli.suspend(&hash).unwrap();
        assert!(relay.authenticate(&hash).is_ok(), "cached until reload");
        relay.load_tokens().unwrap();
        assert_eq!(relay.authenticate(&hash), Err(AuthError::Expired));
    }

    #[test]
    fn usage_sums_across_day_rows_and_refuses_at_the_allowance() {
        let s = SqliteStore::open(None).unwrap();
        let token = s.issue(Tier::Free, None);
        let p = s.authenticate(&token_hash(&token)).unwrap();
        let today = today_unix();
        {
            let conn = s.conn();
            for (day, wu) in [(today - 2, 100_000i64), (today - 1, 200_000)] {
                conn.execute(
                    "INSERT INTO usage (token_id, day, wu) VALUES (?1, ?2, ?3)",
                    params![p.id, day, wu],
                )
                .unwrap();
            }
        }
        assert_eq!(s.used(&p), 300_000);
        assert_eq!(s.admit(&p, 200_000), Verdict::Allow);
        assert_eq!(s.used(&p), 500_000);
        assert_eq!(s.admit(&p, LIGHT_WU), Verdict::QuotaExceeded);
    }

    #[test]
    fn flush_persists_usage_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let (s, db) = open_tmp(&dir);
        let token = s.issue(Tier::Pro, None);
        let p = s.authenticate(&token_hash(&token)).unwrap();
        assert_eq!(s.admit(&p, 10_000), Verdict::Allow);
        assert_eq!(s.used(&p), 10_000);
        s.flush().unwrap();
        drop(s);

        let s = SqliteStore::open(Some(&db)).unwrap();
        let p = s.authenticate(&token_hash(&token)).unwrap();
        assert_eq!(s.used(&p), 10_000);
    }

    #[tokio::test]
    async fn flusher_persists_on_its_own_schedule() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("t.db");
        let token;
        {
            let store = Arc::new(
                SqliteStore::open_with_flush_interval(Some(&db), Duration::from_millis(20))
                    .unwrap(),
            );
            let flusher = store.clone().run_flusher();
            token = store.issue(Tier::Free, None);
            let p = store.authenticate(&token_hash(&token)).unwrap();
            assert_eq!(store.admit(&p, 7000), Verdict::Allow);
            assert_eq!(store.admit(&p, 8000), Verdict::Allow);
            tokio::time::sleep(Duration::from_millis(150)).await;
            flusher.abort();
        }
        let store = SqliteStore::open(Some(&db)).unwrap();
        let p = store.authenticate(&token_hash(&token)).unwrap();
        assert_eq!(store.used(&p), 15_000);
    }

    #[test]
    fn stream_permits_are_limited_per_tier() {
        let s = SqliteStore::open(None).unwrap();
        let free_token = s.issue(Tier::Free, None);
        let free = s.authenticate(&token_hash(&free_token)).unwrap();
        let a = s.take_stream(&free).expect("one free stream");
        assert!(s.take_stream(&free).is_none());
        drop(a);
        assert!(s.take_stream(&free).is_some());

        let pro_token = s.issue(Tier::Pro, None);
        let pro = s.authenticate(&token_hash(&pro_token)).unwrap();
        let b1 = s.take_stream(&pro).unwrap();
        let b2 = s.take_stream(&pro).unwrap();
        let b3 = s.take_stream(&pro).unwrap();
        assert!(s.take_stream(&pro).is_none());
        drop((b1, b2, b3));
        assert!(s.take_stream(&pro).is_some());
    }

    #[test]
    fn issued_token_matches_the_expected_shape() {
        let s = SqliteStore::open(None).unwrap();
        let token = s.issue(Tier::Free, None);
        assert!(looks_like_token(&token));
        assert!(token.starts_with("sub_"));
        // Base58 of 32 bytes is 43 or 44 characters; every issue must pass
        // the same shape check the ingress applies.
        for _ in 0..16 {
            assert!(looks_like_token(&s.issue(Tier::Pro, None)));
        }
    }

    #[test]
    fn list_shows_handles_and_usage_never_tokens() {
        let dir = tempfile::tempdir().unwrap();
        let (s, _) = open_tmp(&dir);
        let token = s.issue(Tier::Pro, Some(unix_now() + 86_400));
        let p = s.authenticate(&token_hash(&token)).unwrap();
        s.admit(&p, 1234);
        s.flush().unwrap();
        let list = s.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].handle.len(), 8);
        assert_eq!(list[0].tier, Tier::Pro);
        assert_eq!(list[0].status, "active");
        assert_eq!(list[0].wu_used_30d, 1234);
        assert!(
            !list[0].handle.contains(&token),
            "raw token must never be shown"
        );
    }
}
