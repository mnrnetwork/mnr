//! Per-token limits (`docs/stage0-mvp-plan.md` §5; gateway plan §3.2).
//!
//! Two layers: a burst token bucket per principal (capacity 2 × burst rps)
//! and a work-unit allowance. 1 light request = 1 WU; 1 MB of a
//! `get_blocks.bin` stream = 20 WU. Every request counts, cached or not.
//!
//! [`Limiter`] is the persistence seam. [`MemoryLimiter`] keeps everything
//! in process and is what tests and `--dev-token` runs use; the SQLite
//! limiter (see `store`) persists the allowance so a restart does not reset
//! quotas. Burst buckets and stream slots are process-local in both: only the
//! work-unit allowance needs to survive a restart.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::Mutex;

use crate::auth::Principal;

/// Work units for one light (non-stream) request.
pub const LIGHT_WU: u64 = 1;
/// Work units per MB of stream response.
pub const STREAM_WU_PER_MB: u64 = 20;

/// WU for a stream response of `bytes` bytes, never less than one light call.
pub fn stream_wu(bytes: u64) -> u64 {
    (bytes * STREAM_WU_PER_MB).div_ceil(1_000_000).max(LIGHT_WU)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    /// Burst exceeded: HTTP 429, `Retry-After`, JSON-RPC `-32005`.
    RateLimited {
        retry_after_secs: u32,
    },
    /// Allowance used up: HTTP 429, JSON-RPC `-32005`.
    QuotaExceeded,
}

pub trait Limiter: Send + Sync {
    /// Admit one request costing `wu`, charging it if admitted.
    fn admit(&self, principal: &Principal, wu: u64) -> Verdict;
    /// Charge work discovered after admission (stream bytes). Never refuses;
    /// the next `admit` will.
    fn charge(&self, principal: &Principal, wu: u64);
    /// Take one concurrent `get_blocks.bin` stream slot for this principal,
    /// returning an RAII permit that frees it on drop, or `None` when the
    /// tier's stream cap is already reached.
    fn take_stream(&self, principal: &Principal) -> Option<StreamPermit>;
    /// Work units used by this principal in the current period.
    #[cfg(test)]
    fn used(&self, principal: &Principal) -> u64;
}

/// Concurrent-stream slots, shared by every limiter so a permit from one
/// releases against the same counter it was taken from.
#[derive(Default)]
pub(crate) struct StreamCounters {
    counts: Mutex<HashMap<i64, u32>>,
}

impl StreamCounters {
    fn take(&self, id: i64, max: u32) -> bool {
        let mut counts = self.counts.lock();
        let c = counts.entry(id).or_insert(0);
        if *c < max {
            *c += 1;
            true
        } else {
            false
        }
    }

    fn release(&self, id: i64) {
        let mut counts = self.counts.lock();
        if let Some(c) = counts.get_mut(&id) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                counts.remove(&id);
            }
        }
    }
}

/// RAII permit for one concurrent stream: the slot is returned when the
/// permit drops, so the caller never needs to remember to release it.
pub struct StreamPermit {
    counters: Arc<StreamCounters>,
    id: i64,
    armed: bool,
}

impl Drop for StreamPermit {
    fn drop(&mut self) {
        if self.armed {
            self.counters.release(self.id);
            self.armed = false;
        }
    }
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

#[derive(Default)]
pub struct MemoryLimiter {
    buckets: Mutex<HashMap<i64, Bucket>>,
    used: Mutex<HashMap<i64, u64>>,
    streams: Arc<StreamCounters>,
}

impl MemoryLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Take one token from the principal's burst bucket. `Err(retry)` when
    /// the bucket is empty. Kept `pub(crate)` so the SQLite limiter reuses
    /// the exact same burst behaviour.
    pub(crate) fn take_burst(&self, principal: &Principal, now: Instant) -> Result<(), u32> {
        let rate = f64::from(principal.tier.burst_rps());
        let capacity = 2.0 * rate;
        let mut buckets = self.buckets.lock();
        let b = buckets.entry(principal.id).or_insert(Bucket {
            tokens: capacity,
            last: now,
        });
        let elapsed = now.duration_since(b.last).as_secs_f64();
        b.tokens = (b.tokens + elapsed * rate).min(capacity);
        b.last = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            Ok(())
        } else {
            Err(((1.0 - b.tokens) / rate).ceil().max(1.0) as u32)
        }
    }

    fn admit_at(&self, principal: &Principal, wu: u64, now: Instant) -> Verdict {
        if let Err(retry_after_secs) = self.take_burst(principal, now) {
            return Verdict::RateLimited { retry_after_secs };
        }
        let mut used = self.used.lock();
        let u = used.entry(principal.id).or_insert(0);
        if *u + wu > principal.tier.monthly_wu() {
            return Verdict::QuotaExceeded;
        }
        *u += wu;
        Verdict::Allow
    }
}

impl Limiter for MemoryLimiter {
    fn admit(&self, principal: &Principal, wu: u64) -> Verdict {
        self.admit_at(principal, wu, Instant::now())
    }

    fn charge(&self, principal: &Principal, wu: u64) {
        *self.used.lock().entry(principal.id).or_insert(0) += wu;
    }

    fn take_stream(&self, principal: &Principal) -> Option<StreamPermit> {
        let max = principal.tier.max_streams();
        self.streams.take(principal.id, max).then(|| StreamPermit {
            counters: Arc::clone(&self.streams),
            id: principal.id,
            armed: true,
        })
    }

    #[cfg(test)]
    fn used(&self, principal: &Principal) -> u64 {
        self.used.lock().get(&principal.id).copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Tier;
    use std::time::Duration;

    fn free() -> Principal {
        Principal {
            id: 1,
            tier: Tier::Free,
            handle: "deadbeef".into(),
        }
    }

    #[test]
    fn stream_wu_is_twenty_per_mb_rounded_up() {
        assert_eq!(stream_wu(0), 1);
        assert_eq!(stream_wu(1), 1);
        assert_eq!(stream_wu(1_000_000), 20);
        assert_eq!(stream_wu(1_000_001), 21);
        assert_eq!(stream_wu(2_500_000), 50);
    }

    #[test]
    fn burst_allows_twice_the_rate_then_refills() {
        let l = MemoryLimiter::new();
        let p = free();
        let t0 = Instant::now();
        for _ in 0..10 {
            assert_eq!(l.admit_at(&p, 1, t0), Verdict::Allow);
        }
        assert!(matches!(
            l.admit_at(&p, 1, t0),
            Verdict::RateLimited {
                retry_after_secs: 1
            }
        ));
        // 5 rps: after 400 ms two tokens are back.
        let t1 = t0 + Duration::from_millis(400);
        assert_eq!(l.admit_at(&p, 1, t1), Verdict::Allow);
        assert_eq!(l.admit_at(&p, 1, t1), Verdict::Allow);
        assert!(matches!(l.admit_at(&p, 1, t1), Verdict::RateLimited { .. }));
        assert_eq!(l.used(&p), 12);
    }

    #[test]
    fn quota_refuses_once_the_allowance_is_spent() {
        let l = MemoryLimiter::new();
        let p = free();
        let t0 = Instant::now();
        l.charge(&p, Tier::Free.monthly_wu() - 1);
        assert_eq!(l.admit_at(&p, 1, t0), Verdict::Allow);
        assert_eq!(l.admit_at(&p, 1, t0), Verdict::QuotaExceeded);
        // A different principal is unaffected.
        let other = Principal { id: 2, ..free() };
        assert_eq!(l.admit_at(&other, 1, t0), Verdict::Allow);
    }

    #[test]
    fn stream_permits_enforce_the_tier_cap_and_free_on_drop() {
        let l = MemoryLimiter::new();
        let p = free();
        let a = l.take_stream(&p).expect("free tier allows one stream");
        assert!(l.take_stream(&p).is_none(), "free tier cap is one");
        drop(a);
        assert!(l.take_stream(&p).is_some(), "slot is free again after drop");

        let pro = Principal {
            tier: Tier::Pro,
            ..free()
        };
        let s1 = l.take_stream(&pro).unwrap();
        let s2 = l.take_stream(&pro).unwrap();
        let s3 = l.take_stream(&pro).unwrap();
        assert!(l.take_stream(&pro).is_none(), "pro tier cap is three");
        drop((s1, s2, s3));
        assert!(l.take_stream(&pro).is_some());
    }
}
