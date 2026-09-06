//! Streaming bodies for the `get_blocks.bin` family (`docs/stage0-mvp-plan.md`
//! §5; rule 3 of `.claude/rules/public-nodes.md`).
//!
//! A stream answer is not buffered. Chunks are pulled from the upstream and
//! handed to the client through two wrappers:
//!
//! - [`Throttled`] (upstream side): takes each chunk's bytes from the
//!   upstream's **bandwidth bucket** (`caps.mbps`, capacity one second of
//!   the rate, refilled continuously) and waits when they are not there yet;
//!   ends the stream when the upstream sends nothing for [`IDLE_TIMEOUT`]
//!   (measured between chunk reads from the upstream, so a slow client or
//!   our own throttling never trips it), or past [`MAX_STREAM_BYTES`]. It
//!   owns the upstream's stream slot for its whole life.
//! - [`Accounted`] (client side): counts the bytes that reach the client,
//!   holds the client's concurrent-stream permit, and on completion or drop
//!   charges `stream_wu(bytes) − LIGHT_WU` exactly once (admission already
//!   charged one light unit). A client that disconnects mid-stream pays for
//!   what it received.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use futures_util::stream::{BoxStream, Stream, StreamExt};
use parking_lot::Mutex;
use tokio::sync::OwnedSemaphorePermit;
// tokio's Instant follows the paused clock under `test-util`, so the
// throttle tests run in virtual time.
use tokio::time::Instant;

use crate::auth::Principal;
use crate::limits::{stream_wu, Limiter, StreamPermit, LIGHT_WU};
use crate::metrics::Metrics;
use crate::upstream::ForwardError;

/// Longest silence from the upstream before a stream is cut (policy note:
/// idle timeout 15 s).
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(15);
/// Ceiling on one streamed answer. monerod's own chunking keeps a
/// `get_blocks.bin` answer far below this; it bounds a broken or hostile
/// upstream that would otherwise trickle forever under the bandwidth cap.
pub const MAX_STREAM_BYTES: u64 = 1 << 30;

/// Byte token bucket: capacity is one second of the rate, so a burst can
/// never exceed the published ceiling, and a chunk larger than the bucket
/// simply waits for its bytes.
pub struct ByteBucket {
    tokens: f64,
    rate: f64,
    last: Instant,
}

impl ByteBucket {
    pub fn new(bytes_per_sec: u64) -> Self {
        let rate = bytes_per_sec.max(1) as f64;
        Self {
            tokens: rate,
            rate,
            last: Instant::now(),
        }
    }

    /// Take `n` bytes now, returning how long the caller must wait before
    /// sending them. The debt is recorded immediately so concurrent streams
    /// on the same upstream share the rate rather than each seeing a full
    /// bucket.
    pub fn take(&mut self, n: usize, now: Instant) -> Duration {
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.rate);
        self.last = now;
        self.tokens -= n as f64;
        if self.tokens >= 0.0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64(-self.tokens / self.rate)
        }
    }
}

/// Where a throttled stream ended, for the accounting side and for logs.
fn io_err(e: ForwardError) -> io::Error {
    io::Error::other(e.to_string())
}

/// The upstream-side wrapper. Built by [`throttled`].
pub struct Throttled {
    inner: BoxStream<'static, Result<Bytes, ForwardError>>,
    bucket: Arc<Mutex<ByteBucket>>,
    idle: Duration,
    total: u64,
    max: u64,
    /// Sleep in progress for the bandwidth cap.
    delay: Option<Pin<Box<tokio::time::Sleep>>>,
    /// The chunk waiting behind `delay`.
    pending: Option<Bytes>,
    /// Armed when a chunk is awaited from the upstream.
    idle_timer: Option<Pin<Box<tokio::time::Sleep>>>,
    done: bool,
    _slot: OwnedSemaphorePermit,
    /// The upstream's lifetime stream-byte counter (its load figure).
    counter: Arc<AtomicU64>,
}

/// Wrap an upstream byte stream with the cap, the idle timeout and the
/// ceiling. `slot` is the upstream's concurrent-stream permit, released
/// when the returned stream drops.
pub fn throttled(
    inner: BoxStream<'static, Result<Bytes, ForwardError>>,
    bucket: Arc<Mutex<ByteBucket>>,
    slot: OwnedSemaphorePermit,
    counter: Arc<AtomicU64>,
) -> Throttled {
    Throttled {
        counter,
        inner,
        bucket,
        idle: IDLE_TIMEOUT,
        total: 0,
        max: MAX_STREAM_BYTES,
        delay: None,
        pending: None,
        idle_timer: None,
        done: false,
        _slot: slot,
    }
}

impl Throttled {
    #[cfg(test)]
    fn with_limits(mut self, idle: Duration, max: u64) -> Self {
        self.idle = idle;
        self.max = max;
        self
    }
}

impl Stream for Throttled {
    type Item = Result<Bytes, io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;
        if this.done {
            return Poll::Ready(None);
        }
        // A chunk is waiting for its bandwidth.
        if let Some(delay) = this.delay.as_mut() {
            match delay.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(()) => {
                    this.delay = None;
                    let chunk = this.pending.take().expect("pending chunk behind delay");
                    return Poll::Ready(Some(Ok(chunk)));
                }
            }
        }
        // Pull the next chunk, with the idle timer armed on the upstream.
        let idle = this.idle;
        let timer = this
            .idle_timer
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(idle)));
        match this.inner.poll_next_unpin(cx) {
            Poll::Pending => match timer.as_mut().poll(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(()) => {
                    this.done = true;
                    Poll::Ready(Some(Err(io_err(ForwardError::Timeout))))
                }
            },
            Poll::Ready(None) => {
                this.done = true;
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(e))) => {
                this.done = true;
                Poll::Ready(Some(Err(io_err(e))))
            }
            Poll::Ready(Some(Ok(chunk))) => {
                this.idle_timer = None;
                this.total += chunk.len() as u64;
                this.counter
                    .fetch_add(chunk.len() as u64, Ordering::Relaxed);
                if this.total > this.max {
                    this.done = true;
                    return Poll::Ready(Some(Err(io_err(ForwardError::Other(
                        "stream exceeds the size ceiling".into(),
                    )))));
                }
                let wait = this.bucket.lock().take(chunk.len(), Instant::now());
                if wait.is_zero() {
                    Poll::Ready(Some(Ok(chunk)))
                } else {
                    this.pending = Some(chunk);
                    let mut sleep = Box::pin(tokio::time::sleep(wait));
                    // Register the waker; the sleep is not ready yet.
                    match sleep.as_mut().poll(cx) {
                        Poll::Ready(()) => {
                            Poll::Ready(Some(Ok(this.pending.take().expect("just stored"))))
                        }
                        Poll::Pending => {
                            this.delay = Some(sleep);
                            Poll::Pending
                        }
                    }
                }
            }
        }
    }
}

/// The client-side wrapper: counts bytes, holds the client's stream permit,
/// charges once on drop.
pub struct Accounted {
    inner: BoxStream<'static, Result<Bytes, io::Error>>,
    bytes: u64,
    limiter: Arc<dyn Limiter>,
    metrics: Arc<Metrics>,
    principal: Principal,
    _permit: Option<StreamPermit>,
}

impl Accounted {
    pub fn new(
        inner: BoxStream<'static, Result<Bytes, io::Error>>,
        limiter: Arc<dyn Limiter>,
        metrics: Arc<Metrics>,
        principal: Principal,
        permit: Option<StreamPermit>,
    ) -> Self {
        Self {
            inner,
            bytes: 0,
            limiter,
            metrics,
            principal,
            _permit: permit,
        }
    }
}

impl Stream for Accounted {
    type Item = Result<Bytes, io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let r = self.inner.poll_next_unpin(cx);
        if let Poll::Ready(Some(Ok(chunk))) = &r {
            self.bytes += chunk.len() as u64;
        }
        r
    }
}

impl Drop for Accounted {
    fn drop(&mut self) {
        // The quota (limiter) and the aggregate gauge both see the stream's
        // work units; the light unit was charged at admission. `charge` is
        // an in-memory delta in both limiters (the SQLite one flushes from
        // a task), so nothing blocks on this drop path.
        let wu = stream_wu(self.bytes).saturating_sub(LIGHT_WU);
        if wu > 0 {
            self.limiter.charge(&self.principal, wu);
            self.metrics.charged(self.principal.tier, wu);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Tier;
    use crate::limits::MemoryLimiter;
    use futures_util::stream;
    use tokio::sync::Semaphore;

    #[test]
    fn bucket_waits_for_bytes_beyond_one_second_of_rate() {
        let t0 = Instant::now();
        let mut b = ByteBucket::new(1_000_000);
        assert_eq!(b.take(500_000, t0), Duration::ZERO);
        assert_eq!(b.take(500_000, t0), Duration::ZERO);
        // The bucket is empty: 250 KB more means a 250 ms wait.
        let w = b.take(250_000, t0);
        assert!((w.as_millis() as i64 - 250).abs() <= 1, "{w:?}");
        // After 300 ms the debt is paid and 50 KB are banked.
        let w = b.take(50_000, t0 + Duration::from_millis(300));
        assert_eq!(w, Duration::ZERO);
        // A chunk larger than the bucket waits proportionally.
        let w = b.take(3_000_000, t0 + Duration::from_secs(10));
        assert!((w.as_millis() as i64 - 2000).abs() <= 1, "{w:?}");
        // Idle time never banks more than one second.
        let mut b = ByteBucket::new(10);
        assert_eq!(b.take(10, t0 + Duration::from_secs(100)), Duration::ZERO);
        assert!(b.take(1, t0 + Duration::from_secs(100)) > Duration::ZERO);
    }

    fn counter() -> Arc<AtomicU64> {
        Arc::new(AtomicU64::new(0))
    }

    fn slot() -> OwnedSemaphorePermit {
        Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap()
    }

    fn chunks(n: usize, size: usize) -> BoxStream<'static, Result<Bytes, ForwardError>> {
        stream::iter((0..n).map(move |_| Ok(Bytes::from(vec![0u8; size])))).boxed()
    }

    #[tokio::test(start_paused = true)]
    async fn throttled_stream_paces_to_the_cap() {
        // 3 MB at 1 MB/s: the first MB is free (bucket), the rest waits 2 s.
        let bucket = Arc::new(Mutex::new(ByteBucket::new(1_000_000)));
        let mut s = throttled(chunks(6, 500_000), bucket, slot(), counter());
        let t0 = Instant::now();
        let mut total = 0;
        while let Some(c) = s.next().await {
            total += c.unwrap().len();
        }
        assert_eq!(total, 3_000_000);
        let took = t0.elapsed();
        assert!(took >= Duration::from_millis(1990), "{took:?}");
        assert!(took <= Duration::from_millis(2100), "{took:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_upstream_is_cut_at_the_idle_timeout_and_frees_the_slot() {
        let sem = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&sem).try_acquire_owned().unwrap();
        // One chunk, then silence forever.
        let inner = stream::iter(vec![Ok(Bytes::from_static(b"abc"))])
            .chain(stream::pending())
            .boxed();
        let bucket = Arc::new(Mutex::new(ByteBucket::new(1 << 30)));
        let mut s = throttled(inner, bucket, permit, counter())
            .with_limits(Duration::from_secs(15), u64::MAX);
        assert_eq!(s.next().await.unwrap().unwrap(), Bytes::from_static(b"abc"));
        assert_eq!(sem.available_permits(), 0, "slot held while streaming");
        let t0 = Instant::now();
        let e = s.next().await.unwrap().unwrap_err();
        assert!(e.to_string().contains("timeout"), "{e}");
        assert!(t0.elapsed() >= Duration::from_secs(15));
        assert!(s.next().await.is_none());
        drop(s);
        assert_eq!(sem.available_permits(), 1, "slot released on drop");
    }

    #[tokio::test(start_paused = true)]
    async fn throttling_does_not_count_as_idle() {
        // 4 MB at 1 MB/s takes 3 s of throttling; an idle limit of 1 s must
        // not fire, because the upstream itself never stalls.
        let bucket = Arc::new(Mutex::new(ByteBucket::new(1_000_000)));
        let mut s = throttled(chunks(4, 1_000_000), bucket, slot(), counter())
            .with_limits(Duration::from_secs(1), u64::MAX);
        let mut n = 0;
        while let Some(c) = s.next().await {
            c.unwrap();
            n += 1;
        }
        assert_eq!(n, 4);
    }

    #[tokio::test(start_paused = true)]
    async fn ceiling_ends_the_stream() {
        let bucket = Arc::new(Mutex::new(ByteBucket::new(1 << 30)));
        let mut s =
            throttled(chunks(10, 100), bucket, slot(), counter()).with_limits(IDLE_TIMEOUT, 250);
        let mut ok = 0;
        let mut err = None;
        while let Some(c) = s.next().await {
            match c {
                Ok(_) => ok += 1,
                Err(e) => err = Some(e),
            }
        }
        assert_eq!(ok, 2);
        assert!(err.unwrap().to_string().contains("ceiling"));
    }

    #[tokio::test]
    async fn accounted_stream_charges_once_for_the_bytes_delivered() {
        let limiter: Arc<dyn Limiter> = Arc::new(MemoryLimiter::new());
        let p = Principal {
            id: 7,
            tier: Tier::Pro,
            handle: "cafebabe".into(),
        };
        let permit = limiter.take_stream(&p);
        let metrics = Arc::new(Metrics::new());
        let inner = stream::iter((0..5).map(|_| Ok(Bytes::from(vec![0u8; 500_000])))).boxed();
        let mut s = Accounted::new(
            inner,
            Arc::clone(&limiter),
            Arc::clone(&metrics),
            p.clone(),
            permit,
        );
        // The client reads 1.5 MB and disconnects.
        for _ in 0..3 {
            s.next().await.unwrap().unwrap();
        }
        assert_eq!(limiter.used(&p), 0, "nothing charged before drop");
        drop(s);
        assert_eq!(limiter.used(&p), stream_wu(1_500_000) - LIGHT_WU);
        // The aggregate gauge saw the same work units, under the tier.
        let text = metrics
            .render(
                &crate::upstream::Pool::from_config(
                    &crate::config::Config::parse(
                        "[probe]\nmin_agree = 1\n[[upstreams]]\nname = \"o\"\nurl = \"http://10.0.0.2:18081\"\nkind = \"owned\"\ntransport = \"http\"\n",
                    )
                    .unwrap(),
                )
                .unwrap(),
                &crate::chain::ChainStore::open(None).unwrap(),
                &crate::cache::Cache::new(1),
            )
            .await;
        assert!(
            text.contains(&format!(
                "mnr_wu_charged_total{{tier=\"pro\"}} {}",
                stream_wu(1_500_000) - LIGHT_WU
            )),
            "{text}"
        );
        // The permit came back with the drop: all three pro slots are free.
        let _a = limiter.take_stream(&p).unwrap();
        let _b = limiter.take_stream(&p).unwrap();
        let _c = limiter.take_stream(&p).unwrap();
        assert!(limiter.take_stream(&p).is_none(), "pro cap is three");
    }
}
