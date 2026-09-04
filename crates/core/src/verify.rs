//! `verify` — the Stage 0 verification rules as pure functions
//! (`docs/stage0-mvp-plan.md` §4, `docs/stage2-network-protocol-architecture.md` §3.4).
//!
//! | Data | Check |
//! |---|---|
//! | `get_block` blob | [`verify_block`]: recomputed hash equals the requested hash, or the header chain at the requested height |
//! | `get_block_header_by_height` / `_by_hash` | [`verify_header_by_height`] / [`verify_header_by_hash`]: reported fields equal the header chain |
//! | `/get_transactions` | [`verify_tx`]: Keccak(tx blob) equals the txid; a confirmed height is at or below the tip |
//! | `get_info` / `get_height` | [`quorum_tip`]: highest height on which at least `min_agree` upstreams agree on the hash |
//! | fee estimate | [`median`] |
//!
//! Nothing here does I/O or trusts an input it did not check. What cannot be
//! checked is returned as [`TxVerdict::NotVerifiable`], never silently passed.

use std::fmt;

use crate::hash::{self, Hash, HashError, ParsedBlock};
use crate::headerchain::HeaderChain;

/// Why a response failed verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// The blob could not be parsed or hashed.
    Hash(HashError),
    /// The recomputed hash differs from what was requested or what our chain says.
    HashMismatch { expected: Hash, got: Hash },
    /// The response is for a different height than requested.
    HeightMismatch { expected: u64, got: u64 },
    /// The response claims a previous-block hash our chain does not have at that height.
    PrevHashMismatch {
        height: u64,
        expected: Hash,
        got: Hash,
    },
    /// Our header chain does not reach this height yet; extend it first.
    UnknownHeight(u64),
    /// A transaction claims a confirmation height above the quorum tip.
    AboveTip { height: u64, tip: u64 },
}

impl From<HashError> for VerifyError {
    fn from(e: HashError) -> Self {
        Self::Hash(e)
    }
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hash(e) => write!(f, "{e}"),
            Self::HashMismatch { expected, got } => write!(
                f,
                "hash mismatch: expected {} got {}",
                hex8(expected),
                hex8(got)
            ),
            Self::HeightMismatch { expected, got } => {
                write!(f, "height mismatch: expected {expected} got {got}")
            }
            Self::PrevHashMismatch {
                height,
                expected,
                got,
            } => write!(
                f,
                "prev hash mismatch at {height}: expected {} got {}",
                hex8(expected),
                hex8(got)
            ),
            Self::UnknownHeight(h) => write!(f, "header chain does not reach height {h}"),
            Self::AboveTip { height, tip } => {
                write!(f, "claimed height {height} is above quorum tip {tip}")
            }
        }
    }
}

impl std::error::Error for VerifyError {}

fn hex8(h: &Hash) -> String {
    h[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// What a block response was asked for, and therefore what it must match.
#[derive(Debug, Clone, Copy)]
pub enum Expected<'a> {
    /// Requested by hash: the recomputed hash must equal it.
    Hash(Hash),
    /// Requested by height: the recomputed hash must equal our header chain
    /// at that height, and the block must carry that height.
    Height { height: u64, chain: &'a HeaderChain },
}

/// Verify a `get_block` blob against what was requested.
pub fn verify_block(blob: &[u8], expected: Expected<'_>) -> Result<ParsedBlock, VerifyError> {
    let parsed = hash::parse_block(blob)?;
    match expected {
        Expected::Hash(want) => {
            if parsed.hash != want {
                return Err(VerifyError::HashMismatch {
                    expected: want,
                    got: parsed.hash,
                });
            }
        }
        Expected::Height { height, chain } => {
            if parsed.height != height {
                return Err(VerifyError::HeightMismatch {
                    expected: height,
                    got: parsed.height,
                });
            }
            let want = chain
                .hash_at(height)
                .ok_or(VerifyError::UnknownHeight(height))?;
            if parsed.hash != want {
                return Err(VerifyError::HashMismatch {
                    expected: want,
                    got: parsed.hash,
                });
            }
        }
    }
    Ok(parsed)
}

/// The fields of a `block_header` object that our header chain can check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportedHeader {
    pub height: u64,
    pub hash: Hash,
    pub prev_hash: Hash,
    pub timestamp: u64,
}

/// Verify a `get_block_header_by_height` answer: every field we hold must
/// equal what the node reported.
pub fn verify_header_by_height(
    height: u64,
    reported: &ReportedHeader,
    chain: &HeaderChain,
) -> Result<(), VerifyError> {
    if reported.height != height {
        return Err(VerifyError::HeightMismatch {
            expected: height,
            got: reported.height,
        });
    }
    check_header_against_chain(reported, chain)
}

/// Verify a `get_block_header_by_hash` answer: the reported hash must be the
/// requested one, and the header must sit in our chain where it claims to.
pub fn verify_header_by_hash(
    requested: Hash,
    reported: &ReportedHeader,
    chain: &HeaderChain,
) -> Result<(), VerifyError> {
    if reported.hash != requested {
        return Err(VerifyError::HashMismatch {
            expected: requested,
            got: reported.hash,
        });
    }
    check_header_against_chain(reported, chain)
}

fn check_header_against_chain(
    reported: &ReportedHeader,
    chain: &HeaderChain,
) -> Result<(), VerifyError> {
    let ours = chain
        .get(reported.height)
        .ok_or(VerifyError::UnknownHeight(reported.height))?;
    if reported.hash != ours.hash {
        return Err(VerifyError::HashMismatch {
            expected: ours.hash,
            got: reported.hash,
        });
    }
    if reported.prev_hash != ours.prev_hash {
        return Err(VerifyError::PrevHashMismatch {
            height: reported.height,
            expected: ours.prev_hash,
            got: reported.prev_hash,
        });
    }
    if reported.timestamp != ours.timestamp {
        // A wrong timestamp with a right hash is impossible for an honest
        // chain; treat it as the node lying about the header.
        return Err(VerifyError::HashMismatch {
            expected: ours.hash,
            got: reported.hash,
        });
    }
    Ok(())
}

/// The form a `/get_transactions` entry arrived in.
#[derive(Debug, Clone, Copy)]
pub enum TxForm<'a> {
    /// `as_hex`, decoded.
    Full(&'a [u8]),
    /// `pruned_as_hex`, decoded, plus the node's `prunable_hash`.
    Pruned { blob: &'a [u8], prunable_hash: Hash },
}

/// Where the node says the transaction is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxLocation {
    /// Confirmed at this height (`block_height`).
    Block(u64),
    /// In the mempool (`in_pool: true`).
    Pool,
}

/// Outcome of a transaction check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxVerdict {
    /// The blob hashes to the requested txid.
    Verified,
    /// The form given cannot be hashed (pruned v1). The relay must re-fetch
    /// it unpruned or annotate the answer `Mnr-Verify: none`.
    NotVerifiable,
}

/// Verify one `/get_transactions` entry: the blob must hash to `txid`, and a
/// confirmed transaction must not claim a height above `tip`.
pub fn verify_tx(
    form: TxForm<'_>,
    txid: Hash,
    location: TxLocation,
    tip: u64,
) -> Result<TxVerdict, VerifyError> {
    if let TxLocation::Block(height) = location {
        if height > tip {
            return Err(VerifyError::AboveTip { height, tip });
        }
    }
    let got = match form {
        TxForm::Full(blob) => hash::tx_hash(blob)?,
        TxForm::Pruned {
            blob,
            prunable_hash,
        } => match hash::pruned_tx_hash(blob, prunable_hash) {
            Ok(h) => h,
            Err(HashError::NotVerifiable) => return Ok(TxVerdict::NotVerifiable),
            Err(e) => return Err(e.into()),
        },
    };
    if got != txid {
        return Err(VerifyError::HashMismatch {
            expected: txid,
            got,
        });
    }
    Ok(TxVerdict::Verified)
}

/// One upstream's view of the tip, from its `get_info` probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TipReport {
    /// Opaque upstream index (never a URL).
    pub upstream: usize,
    pub height: u64,
    pub hash: Hash,
}

/// The agreed tip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuorumTip {
    pub height: u64,
    pub hash: Hash,
    /// Upstreams that reported exactly this tip, ascending by index.
    pub agreeing: Vec<usize>,
}

/// The highest height on which at least `min_agree` upstreams report the
/// same top hash (plan §3: `min_agree` = 3). `None` means degraded mode: no
/// height has enough agreement, and the caller must fall back to the owned
/// node and suspend cache writes.
///
/// A report is one upstream's `(height, top_block_hash)`. Ties on height with
/// different hashes are each counted separately; the one with enough votes
/// wins, and if several qualify the one with more votes does.
pub fn quorum_tip(reports: &[TipReport], min_agree: usize) -> Option<QuorumTip> {
    if min_agree == 0 {
        return None;
    }
    let mut groups: Vec<QuorumTip> = Vec::new();
    for r in reports {
        match groups
            .iter_mut()
            .find(|g| g.height == r.height && g.hash == r.hash)
        {
            Some(g) => {
                if !g.agreeing.contains(&r.upstream) {
                    g.agreeing.push(r.upstream);
                }
            }
            None => groups.push(QuorumTip {
                height: r.height,
                hash: r.hash,
                agreeing: vec![r.upstream],
            }),
        }
    }
    groups
        .into_iter()
        .filter(|g| g.agreeing.len() >= min_agree)
        .max_by(|a, b| {
            a.height
                .cmp(&b.height)
                .then(a.agreeing.len().cmp(&b.agreeing.len()))
        })
        .map(|mut g| {
            g.agreeing.sort_unstable();
            g
        })
}

/// Median of a set of upstream values (fee estimates). Lower-middle on even
/// counts, so the result is always a value some upstream actually reported.
pub fn median(values: &[u64]) -> Option<u64> {
    if values.is_empty() {
        return None;
    }
    let mut v = values.to_vec();
    v.sort_unstable();
    Some(v[(v.len() - 1) / 2])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::headerchain::Entry;
    use serde_json::Value;

    const BLOCK0: &str = include_str!("../fixtures/mainnet/block-0.json");
    const BLOCK1: &str = include_str!("../fixtures/mainnet/block-1.json");
    const TXS_FULL: &str = include_str!("../fixtures/mainnet/txs-3754000-prune-false.json");
    const TXS_PRUNED: &str = include_str!("../fixtures/mainnet/txs-3754000-prune-true.json");
    const TXS_V1_PRUNED: &str = include_str!("../fixtures/mainnet/txs-202612-prune-true.json");

    fn json(s: &str) -> Value {
        serde_json::from_str(s).unwrap()
    }

    fn h32(s: &str) -> Hash {
        hex::decode(s).unwrap().as_slice().try_into().unwrap()
    }

    fn blob(fixture: &str) -> Vec<u8> {
        hex::decode(json(fixture)["result"]["blob"].as_str().unwrap()).unwrap()
    }

    fn chain_0_1() -> HeaderChain {
        let mut c = HeaderChain::new();
        c.append(Entry::from(&hash::parse_block(&blob(BLOCK0)).unwrap()))
            .unwrap();
        c.append(Entry::from(&hash::parse_block(&blob(BLOCK1)).unwrap()))
            .unwrap();
        c
    }

    fn header_of(fixture: &str) -> ReportedHeader {
        let h = &json(fixture)["result"]["block_header"];
        ReportedHeader {
            height: h["height"].as_u64().unwrap(),
            hash: h32(h["hash"].as_str().unwrap()),
            prev_hash: h32(h["prev_hash"].as_str().unwrap()),
            timestamp: h["timestamp"].as_u64().unwrap(),
        }
    }

    fn hh(n: u8) -> Hash {
        [n; 32]
    }

    #[test]
    fn block_by_hash_passes_and_wrong_hash_fails() {
        let b = blob(BLOCK1);
        let want = header_of(BLOCK1).hash;
        assert_eq!(verify_block(&b, Expected::Hash(want)).unwrap().height, 1);
        assert!(matches!(
            verify_block(&b, Expected::Hash(hh(9))),
            Err(VerifyError::HashMismatch { .. })
        ));
    }

    #[test]
    fn block_by_height_checks_chain_and_height() {
        let chain = chain_0_1();
        let b = blob(BLOCK1);
        assert!(verify_block(
            &b,
            Expected::Height {
                height: 1,
                chain: &chain
            }
        )
        .is_ok());
        // Node answered with block 1 when block 0 was asked for.
        assert_eq!(
            verify_block(
                &b,
                Expected::Height {
                    height: 0,
                    chain: &chain
                }
            ),
            Err(VerifyError::HeightMismatch {
                expected: 0,
                got: 1
            })
        );
        // Our chain does not reach the height yet.
        assert_eq!(
            verify_block(
                &b,
                Expected::Height {
                    height: 5,
                    chain: &chain
                }
            ),
            Err(VerifyError::HeightMismatch {
                expected: 5,
                got: 1
            })
        );
        let short = HeaderChain::new();
        assert_eq!(
            verify_block(
                &b,
                Expected::Height {
                    height: 1,
                    chain: &short
                }
            ),
            Err(VerifyError::UnknownHeight(1))
        );
    }

    #[test]
    fn block_by_height_detects_a_chain_that_disagrees() {
        // A chain whose entry at height 1 is a different block.
        let mut chain = HeaderChain::new();
        chain
            .append(Entry::from(&hash::parse_block(&blob(BLOCK0)).unwrap()))
            .unwrap();
        let genesis = chain.tip().unwrap();
        chain
            .append(Entry {
                height: 1,
                hash: hh(7),
                prev_hash: genesis.hash,
                timestamp: 1,
            })
            .unwrap();
        assert!(matches!(
            verify_block(
                &blob(BLOCK1),
                Expected::Height {
                    height: 1,
                    chain: &chain
                }
            ),
            Err(VerifyError::HashMismatch { .. })
        ));
    }

    #[test]
    fn malformed_block_blob_is_a_hash_error() {
        assert!(matches!(
            verify_block(&[1, 2, 3], Expected::Hash(hh(0))),
            Err(VerifyError::Hash(_))
        ));
    }

    #[test]
    fn header_by_height_and_by_hash() {
        let chain = chain_0_1();
        let h1 = header_of(BLOCK1);
        assert!(verify_header_by_height(1, &h1, &chain).is_ok());
        assert!(verify_header_by_hash(h1.hash, &h1, &chain).is_ok());

        assert_eq!(
            verify_header_by_height(0, &h1, &chain),
            Err(VerifyError::HeightMismatch {
                expected: 0,
                got: 1
            })
        );
        assert!(matches!(
            verify_header_by_hash(hh(1), &h1, &chain),
            Err(VerifyError::HashMismatch { .. })
        ));

        let mut wrong_prev = h1;
        wrong_prev.prev_hash = hh(2);
        assert!(matches!(
            verify_header_by_height(1, &wrong_prev, &chain),
            Err(VerifyError::PrevHashMismatch { height: 1, .. })
        ));

        let mut wrong_ts = h1;
        wrong_ts.timestamp += 1;
        assert!(verify_header_by_height(1, &wrong_ts, &chain).is_err());

        let mut beyond = h1;
        beyond.height = 2;
        assert_eq!(
            verify_header_by_height(2, &beyond, &chain),
            Err(VerifyError::UnknownHeight(2))
        );
    }

    #[test]
    fn full_and_pruned_txs_verify_against_txid_and_tip() {
        let full = json(TXS_FULL);
        let pruned = json(TXS_PRUNED);
        let tip = 3_754_000;
        for (f, p) in full["txs"]
            .as_array()
            .unwrap()
            .iter()
            .zip(pruned["txs"].as_array().unwrap())
        {
            let txid = h32(f["tx_hash"].as_str().unwrap());
            let height = f["block_height"].as_u64().unwrap();
            let fb = hex::decode(f["as_hex"].as_str().unwrap()).unwrap();
            let pb = hex::decode(p["pruned_as_hex"].as_str().unwrap()).unwrap();
            let prunable = h32(p["prunable_hash"].as_str().unwrap());

            assert_eq!(
                verify_tx(TxForm::Full(&fb), txid, TxLocation::Block(height), tip),
                Ok(TxVerdict::Verified)
            );
            assert_eq!(
                verify_tx(
                    TxForm::Pruned {
                        blob: &pb,
                        prunable_hash: prunable
                    },
                    txid,
                    TxLocation::Block(height),
                    tip
                ),
                Ok(TxVerdict::Verified)
            );
            // Wrong txid requested → mismatch, never "verified".
            assert!(matches!(
                verify_tx(TxForm::Full(&fb), hh(0), TxLocation::Pool, tip),
                Err(VerifyError::HashMismatch { .. })
            ));
            // Claimed height above the quorum tip is rejected before hashing.
            assert_eq!(
                verify_tx(TxForm::Full(&fb), txid, TxLocation::Block(tip + 1), tip),
                Err(VerifyError::AboveTip {
                    height: tip + 1,
                    tip
                })
            );
        }
    }

    #[test]
    fn pruned_v1_tx_is_not_verifiable_not_verified() {
        let p = &json(TXS_V1_PRUNED)["txs"][0];
        let pb = hex::decode(p["pruned_as_hex"].as_str().unwrap()).unwrap();
        let txid = h32(p["tx_hash"].as_str().unwrap());
        assert_eq!(
            verify_tx(
                TxForm::Pruned {
                    blob: &pb,
                    prunable_hash: [0; 32]
                },
                txid,
                TxLocation::Block(202_612),
                3_754_000
            ),
            Ok(TxVerdict::NotVerifiable)
        );
    }

    fn rep(upstream: usize, height: u64, hash: u8) -> TipReport {
        TipReport {
            upstream,
            height,
            hash: hh(hash),
        }
    }

    #[test]
    fn quorum_needs_min_agree_on_the_same_hash() {
        // Three agree at 100/a, one is ahead at 101/b, one is forked at 100/c.
        let reports = [
            rep(0, 100, 0xa),
            rep(1, 100, 0xa),
            rep(2, 101, 0xb),
            rep(3, 100, 0xc),
            rep(4, 100, 0xa),
        ];
        let q = quorum_tip(&reports, 3).unwrap();
        assert_eq!((q.height, q.hash), (100, hh(0xa)));
        assert_eq!(q.agreeing, vec![0, 1, 4]);

        // Only two agree anywhere → degraded.
        assert_eq!(quorum_tip(&reports[..4], 3), None);
        assert_eq!(quorum_tip(&[], 3), None);
        assert_eq!(quorum_tip(&reports, 0), None);
    }

    #[test]
    fn quorum_prefers_highest_qualifying_height_then_most_votes() {
        let reports = [
            rep(0, 100, 0xa),
            rep(1, 100, 0xa),
            rep(2, 100, 0xa),
            rep(3, 100, 0xa),
            rep(4, 101, 0xb),
            rep(5, 101, 0xb),
            rep(6, 101, 0xb),
        ];
        // 101 has 3 votes, 100 has 4: highest qualifying height wins.
        assert_eq!(quorum_tip(&reports, 3).unwrap().height, 101);
        // With min_agree 4 only height 100 qualifies.
        assert_eq!(quorum_tip(&reports, 4).unwrap().height, 100);

        // Same height, two competing hashes: the one with more votes wins.
        let split = [
            rep(0, 50, 1),
            rep(1, 50, 1),
            rep(2, 50, 1),
            rep(3, 50, 2),
            rep(4, 50, 2),
            rep(5, 50, 2),
            rep(6, 50, 2),
        ];
        assert_eq!(quorum_tip(&split, 3).unwrap().hash, hh(2));
    }

    #[test]
    fn duplicate_reports_from_one_upstream_count_once() {
        let reports = [rep(0, 10, 1), rep(0, 10, 1), rep(0, 10, 1), rep(1, 10, 1)];
        assert_eq!(quorum_tip(&reports, 3), None);
    }

    #[test]
    fn median_is_a_reported_value() {
        assert_eq!(median(&[]), None);
        assert_eq!(median(&[7]), Some(7));
        assert_eq!(median(&[3, 1, 2]), Some(2));
        assert_eq!(median(&[4, 1, 3, 2]), Some(2));
        assert_eq!(median(&[1, 1, 1000]), Some(1));
    }
}
