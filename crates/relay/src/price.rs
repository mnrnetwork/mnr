//! The XMR/USD rate behind the Pro price (`docs/stage0-mvp-plan.md` §10
//! decision 1, amended 2026-09-07): the price is $9 a month, billed in XMR
//! at the rate when the invoice is created.
//!
//! The rate is the **median of independent public sources**, with the same
//! attitude the relay takes to RPC answers: no single source is trusted.
//! Each round asks every configured source; a source that fails, times out
//! or returns nonsense is skipped; the median of the rest is taken; any
//! source more than 15% from that median is dropped and the median
//! recomputed; at least two sources must remain, or the round yields
//! nothing. A new median more than 30% from the last accepted rate is held
//! back until three consecutive rounds agree with each other (within 15%),
//! so one bad round cannot reprice invoices. The last accepted rate is
//! persisted so a restart does not start blind, and a rate older than 24 h
//! is not used at all: invoice creation then refuses rather than misprices.
//!
//! Outbound requests carry the relay's identifying `User-Agent` and nothing
//! else; no client data is involved.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::{Mutex, RwLock};
use serde_json::Value;

use crate::store::SqliteStore;

/// Sources more than this far from the round's median are dropped.
pub const AGREEMENT: f64 = 0.15;
/// A new rate this far from the last accepted one is held back.
pub const JUMP: f64 = 0.30;
/// Rounds that must agree with each other before a held-back jump is taken.
pub const JUMP_ROUNDS: usize = 3;
/// Sources that must survive the agreement filter.
pub const MIN_SOURCES: usize = 2;
/// A rate older than this is not used.
pub const MAX_AGE: Duration = Duration::from_secs(24 * 3600);
/// Time between rounds.
pub const REFRESH: Duration = Duration::from_secs(10 * 60);
/// An explorer's latest hourly point older than this is not a quote.
const EXPLORER_MAX_AGE: u64 = 3 * 3600;
const FETCH_TIMEOUT: Duration = Duration::from_secs(8);

/// The source names the config accepts.
pub const SOURCES: &[&str] = &["kraken", "coingecko", "kucoin", "xmrclub", "monerospace"];

/// An accepted rate.
#[derive(Debug, Clone, PartialEq)]
pub struct Rate {
    pub usd_per_xmr: f64,
    pub at_unix: u64,
    /// The sources that agreed, in the order they were configured.
    pub sources: Vec<String>,
}

/// One source's answer in a round.
pub type Quote = (String, Result<f64, String>);

pub struct Price {
    current: RwLock<Option<Rate>>,
    /// Consecutive held-back medians while a jump is being confirmed.
    held: Mutex<Vec<f64>>,
    /// Sources that answered and agreed in the last round.
    last_round_ok: Mutex<usize>,
    store: Option<Arc<SqliteStore>>,
    sources: Vec<String>,
    client: reqwest::Client,
}

impl Price {
    /// A price handle that starts from the persisted rate, if any.
    pub fn new(
        sources: Vec<String>,
        user_agent: &str,
        store: Option<Arc<SqliteStore>>,
    ) -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .user_agent(user_agent)
            .timeout(FETCH_TIMEOUT)
            .build()
            .map_err(|e| e.to_string())?;
        let current = store.as_ref().and_then(|s| s.load_rate());
        if let Some(r) = &current {
            tracing::info!(
                usd_per_xmr = r.usd_per_xmr,
                at = r.at_unix,
                "price: persisted rate loaded"
            );
        }
        Ok(Self {
            current: RwLock::new(current),
            held: Mutex::new(Vec::new()),
            last_round_ok: Mutex::new(0),
            store,
            sources,
            client,
        })
    }

    /// The rate to bill at, if one is known and fresh.
    pub fn rate(&self, now: u64) -> Option<Rate> {
        self.current
            .read()
            .clone()
            .filter(|r| now.saturating_sub(r.at_unix) <= MAX_AGE.as_secs())
    }

    /// Seconds since the accepted rate, for metrics; `None` without one.
    pub fn age(&self, now: u64) -> Option<u64> {
        self.current
            .read()
            .as_ref()
            .map(|r| now.saturating_sub(r.at_unix))
    }

    pub fn sources_ok(&self) -> usize {
        *self.last_round_ok.lock()
    }

    /// Reduce one round of quotes to the agreed median, or nothing.
    pub fn agree(quotes: &[Quote]) -> Option<(f64, Vec<String>)> {
        let mut valid: Vec<(&str, f64)> = quotes
            .iter()
            .filter_map(|(name, q)| match q {
                Ok(v) if v.is_finite() && *v > 0.0 => Some((name.as_str(), *v)),
                _ => None,
            })
            .collect();
        if valid.len() < MIN_SOURCES {
            return None;
        }
        let m = median(valid.iter().map(|(_, v)| *v));
        valid.retain(|(_, v)| (v - m).abs() / m <= AGREEMENT);
        if valid.len() < MIN_SOURCES {
            return None;
        }
        let m = median(valid.iter().map(|(_, v)| *v));
        Some((m, valid.iter().map(|(n, _)| (*n).to_owned()).collect()))
    }

    /// Feed one round's quotes; returns the rate now in force.
    pub fn observe(&self, quotes: &[Quote], now: u64) -> Option<Rate> {
        let Some((candidate, sources)) = Self::agree(quotes) else {
            *self.last_round_ok.lock() = 0;
            tracing::warn!("price: no agreement among sources this round");
            return self.current.read().clone();
        };
        *self.last_round_ok.lock() = sources.len();
        let last = self.current.read().clone();
        if let Some(last) = &last {
            let jump = (candidate - last.usd_per_xmr).abs() / last.usd_per_xmr;
            if jump > JUMP {
                let mut held = self.held.lock();
                held.push(candidate);
                let agree_among_held = held.len() >= JUMP_ROUNDS && {
                    let m = median(held.iter().copied());
                    held.iter().all(|h| (h - m).abs() / m <= AGREEMENT)
                };
                if !agree_among_held {
                    tracing::warn!(
                        candidate,
                        last = last.usd_per_xmr,
                        rounds = held.len(),
                        "price: rate moved more than 30%, holding until three rounds agree"
                    );
                    return Some(last.clone());
                }
                held.clear();
            } else {
                self.held.lock().clear();
            }
        }
        let rate = Rate {
            usd_per_xmr: candidate,
            at_unix: now,
            sources,
        };
        if let Some(s) = &self.store {
            if let Err(e) = s.save_rate(&rate) {
                tracing::error!(error = %e, "price: cannot persist rate");
            }
        }
        *self.current.write() = Some(rate.clone());
        Some(rate)
    }

    /// Ask every configured source once.
    pub async fn fetch_all(&self, now: u64) -> Vec<Quote> {
        let asks = self.sources.iter().map(|name| {
            let name = name.clone();
            async move {
                let q = fetch_one(&self.client, &name, now).await;
                (name, q)
            }
        });
        futures_util::future::join_all(asks).await
    }

    /// Fetch and observe at start, then every ten minutes.
    pub async fn run(self: Arc<Self>) {
        loop {
            let now = unix_now();
            let quotes = self.fetch_all(now).await;
            for (n, q) in &quotes {
                if let Err(e) = q {
                    tracing::debug!(source = %n, error = %e, "price: source skipped");
                }
            }
            if let Some(r) = self.observe(&quotes, now) {
                tracing::debug!(usd_per_xmr = r.usd_per_xmr, sources = ?r.sources, "price: rate in force");
            }
            tokio::time::sleep(REFRESH).await;
        }
    }
}

/// The USD price of one XMR from one source. Parsing is strict: a shape
/// change is a skipped source, never a wrong number.
async fn fetch_one(client: &reqwest::Client, source: &str, now: u64) -> Result<f64, String> {
    let url = match source {
        "kraken" => "https://api.kraken.com/0/public/Ticker?pair=XMRUSD",
        "coingecko" => "https://api.coingecko.com/api/v3/simple/price?ids=monero&vs_currencies=usd",
        "kucoin" => "https://api.kucoin.com/api/v1/market/orderbook/level1?symbol=XMR-USDT",
        "xmrclub" => "https://explorer.xmr.club/api/v1/historical-price",
        "monerospace" => "https://monerospace.org/api/v1/historical-price",
        other => return Err(format!("unknown source {other}")),
    };
    let v: Value = client
        .get(url)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())?;
    parse_quote(source, &v, now)
}

/// Extract the quote from a source's JSON.
pub fn parse_quote(source: &str, v: &Value, now: u64) -> Result<f64, String> {
    let num = |x: &Value| -> Option<f64> {
        x.as_f64()
            .or_else(|| x.as_str().and_then(|s| s.parse().ok()))
    };
    let got = match source {
        "kraken" => num(&v["result"]["XXMRZUSD"]["c"][0]),
        "coingecko" => num(&v["monero"]["usd"]),
        "kucoin" => num(&v["data"]["price"]),
        "xmrclub" | "monerospace" => {
            let last = v["prices"].as_array().and_then(|a| a.last());
            let at = last.and_then(|p| p["time"].as_u64()).unwrap_or(0);
            if now.saturating_sub(at) > EXPLORER_MAX_AGE {
                return Err(format!("latest point is {} s old", now.saturating_sub(at)));
            }
            last.and_then(|p| num(&p["USD"]))
        }
        _ => None,
    };
    match got {
        Some(x) if x.is_finite() && x > 0.0 => Ok(x),
        _ => Err("unexpected shape".into()),
    }
}

fn median(it: impl Iterator<Item = f64>) -> f64 {
    let mut v: Vec<f64> = it.collect();
    v.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
    let n = v.len();
    if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    }
}

/// Atomic units for `usd` at `usd_per_xmr`, rounded **up** to the next
/// 0.0001 XMR so the amount always covers the price and the URI stays short.
pub fn atomic_for(usd: f64, usd_per_xmr: f64) -> u64 {
    const STEP: f64 = 1e8;
    let exact = usd / usd_per_xmr * 1e12;
    ((exact / STEP).ceil() * STEP) as u64
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn q(name: &str, v: f64) -> Quote {
        (name.into(), Ok(v))
    }
    fn bad(name: &str) -> Quote {
        (name.into(), Err("down".into()))
    }
    fn price() -> Price {
        Price::new(vec![], "mnr-relay/test", None).unwrap()
    }

    #[test]
    fn median_of_three_with_one_outlier_dropped() {
        let (m, s) = Price::agree(&[q("a", 538.0), q("b", 540.0), q("c", 700.0)]).unwrap();
        assert_eq!(m, 539.0);
        assert_eq!(s, vec!["a", "b"]);
    }

    #[test]
    fn two_agreeing_sources_are_the_minimum() {
        assert_eq!(
            Price::agree(&[q("a", 538.0), q("b", 540.0), bad("c")])
                .unwrap()
                .0,
            539.0,
            "two valid sources are enough, a failed one is skipped"
        );
        assert!(
            Price::agree(&[q("a", 538.0), bad("b")]).is_none(),
            "one valid source is not a rate"
        );
        assert!(Price::agree(&[q("a", 538.0)]).is_none());
        assert!(
            Price::agree(&[q("a", 100.0), q("b", 500.0)]).is_none(),
            "two that disagree"
        );
        assert!(Price::agree(&[q("a", 0.0), q("b", -1.0), q("c", f64::NAN)]).is_none());
        assert!(Price::agree(&[]).is_none());
    }

    #[test]
    fn jump_guard_holds_a_big_move_for_three_agreeing_rounds() {
        let p = price();
        assert_eq!(
            p.observe(&[q("a", 500.0), q("b", 500.0)], 1000)
                .unwrap()
                .usd_per_xmr,
            500.0
        );
        // +40%: held.
        for t in [2000, 3000] {
            let r = p.observe(&[q("a", 700.0), q("b", 700.0)], t).unwrap();
            assert_eq!(
                r.usd_per_xmr, 500.0,
                "still the old rate after round at {t}"
            );
        }
        let r = p.observe(&[q("a", 700.0), q("b", 700.0)], 4000).unwrap();
        assert_eq!(r.usd_per_xmr, 700.0, "third agreeing round is accepted");
        assert_eq!(r.at_unix, 4000);
        // A one-off spike never lands.
        assert_eq!(
            p.observe(&[q("a", 2000.0), q("b", 2000.0)], 5000)
                .unwrap()
                .usd_per_xmr,
            700.0
        );
        assert_eq!(
            p.observe(&[q("a", 710.0), q("b", 710.0)], 6000)
                .unwrap()
                .usd_per_xmr,
            710.0
        );
        assert!(p.held.lock().is_empty());
    }

    #[test]
    fn no_agreement_keeps_the_last_rate_and_staleness_drops_it() {
        let p = price();
        assert!(p.rate(0).is_none());
        p.observe(&[q("a", 500.0), q("b", 505.0)], 1_000_000);
        assert_eq!(
            p.observe(&[bad("a"), bad("b")], 1_000_600)
                .unwrap()
                .usd_per_xmr,
            502.5
        );
        assert_eq!(p.sources_ok(), 0);
        assert!(p.rate(1_000_000 + 24 * 3600).is_some());
        assert!(
            p.rate(1_000_000 + 24 * 3600 + 1).is_none(),
            "24 h old is not used"
        );
        assert_eq!(p.age(1_000_100), Some(100));
    }

    #[test]
    fn quotes_parse_strictly() {
        let now = 1_788_750_000;
        assert_eq!(
            parse_quote(
                "kraken",
                &json!({"result":{"XXMRZUSD":{"c":["538.10","1.0"]}}}),
                now
            )
            .unwrap(),
            538.10
        );
        assert_eq!(
            parse_quote("coingecko", &json!({"monero":{"usd":538.8}}), now).unwrap(),
            538.8
        );
        assert_eq!(
            parse_quote("kucoin", &json!({"data":{"price":"537.9"}}), now).unwrap(),
            537.9
        );
        let fresh = json!({"prices":[{"time": now - 7200, "USD": 500.0}, {"time": now - 300, "USD": 537.58}]});
        assert_eq!(parse_quote("xmrclub", &fresh, now).unwrap(), 537.58);
        let stale = json!({"prices":[{"time": now - 4 * 3600, "USD": 537.58}]});
        assert!(parse_quote("monerospace", &stale, now).is_err());
        assert!(parse_quote("kraken", &json!({"result":{}}), now).is_err());
        assert!(parse_quote("coingecko", &json!({"monero":{"usd":"oops"}}), now).is_err());
        assert!(parse_quote("nope", &json!({}), now).is_err());
    }

    #[test]
    fn atomic_amount_rounds_up_to_a_ten_thousandth() {
        // $9 at 538.8: 16,704,158,130 exact, up to 0.0168 XMR.
        assert_eq!(atomic_for(9.0, 538.8), 16_800_000_000);
        assert_eq!(
            atomic_for(27.0, 538.8),
            50_200_000_000,
            "three months multiply before rounding"
        );
        assert_eq!(atomic_for(9.0, 900.0), 10_000_000_000, "exact tenth stays");
        assert!(atomic_for(9.0, 538.8) as f64 >= 9.0 / 538.8 * 1e12);
    }
}
