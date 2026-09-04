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

/// Seconds the previous token stays valid after a rotation (gateway plan §3.1).
const GRACE_SECS: u64 = 24 * 3600;
/// Schema version, stored in `PRAGMA user_version`.
const SCHEMA_VERSION: i64 = 1;
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
        let hash = token_hash(&token);
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
        token
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

    /// Extend a token's `valid_until` (unix timestamp). Part of the management
    /// API; not yet wired to a CLI subcommand.
    #[allow(dead_code)]
    pub fn extend(&self, hash: &[u8; 32], valid_until: u64) -> Result<(), String> {
        let conn = self.conn.lock();
        let n = conn
            .execute(
                "UPDATE tokens SET valid_until = ?1 WHERE token_hash = ?2",
                params![valid_until as i64, hash.as_slice()],
            )
            .map_err(|e| e.to_string())?;
        drop(conn);
        if n == 0 {
            return Err("unknown token".to_owned());
        }
        let id = self.tokens.read().get(hash).map(|r| r.id);
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
fn base58_encode(bytes: &[u8]) -> String {
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
    use crate::auth::looks_like_token;
    use crate::limits::LIGHT_WU;

    fn open_tmp(dir: &tempfile::TempDir) -> (SqliteStore, std::path::PathBuf) {
        let db = dir.path().join("t.db");
        (SqliteStore::open(Some(&db)).unwrap(), db)
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
