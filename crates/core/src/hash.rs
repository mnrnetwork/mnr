//! `hash` — block and transaction hashing for mnr — an RPC network for Monero.
//!
//! Everything here is a pure function over bytes. The serialization and
//! Keccak work is delegated to the `monero-oxide` crate; this module is the
//! only place that names it, so a crate swap never touches the relay.
//!
//! What the relay needs, and gets from here:
//!
//! - [`parse_block`]: a block blob → its hash, height, previous hash and tx
//!   hashes, so `get_block` / `get_block_header_*` answers can be checked
//!   against the requested hash or the header chain (plan §4).
//! - [`tx_hash`]: a full tx blob → its txid, for `/get_transactions`.
//! - [`pruned_tx_hash`]: a pruned v2 tx blob plus the node-supplied prunable
//!   hash → its txid. Pruned **v1** transactions cannot be verified at all and
//!   return [`HashError::NotVerifiable`]; the relay must fetch them unpruned or
//!   annotate them.
//!
//! Every function rejects trailing bytes: a blob that parses but is longer
//! than the structure it encodes is treated as malformed, so an upstream cannot
//! smuggle data past the hash check.

use std::fmt;
use std::io::Cursor;

use monero_oxide::block::Block;
use monero_oxide::transaction::{NotPruned, Pruned, Transaction};

pub use monero_oxide::primitives::keccak256;

/// A 32-byte Keccak-256 hash (block hash, txid, tree-hash node).
pub type Hash = [u8; 32];

/// Why a blob could not be hashed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashError {
    /// The blob does not decode as the expected structure.
    Malformed(String),
    /// The blob decoded, but `n` bytes were left over.
    TrailingBytes(usize),
    /// The structure decodes but its hash cannot be recomputed from what was
    /// given (a pruned v1 transaction: its ring signatures are gone and there
    /// is no prunable-hash form for v1).
    NotVerifiable,
}

impl fmt::Display for HashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(why) => write!(f, "malformed blob: {why}"),
            Self::TrailingBytes(n) => write!(f, "{n} trailing bytes after structure"),
            Self::NotVerifiable => f.write_str("hash cannot be recomputed from the given form"),
        }
    }
}

impl std::error::Error for HashError {}

/// What the relay learns from a block blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedBlock {
    /// The block hash, including monerod's special case for block 202612.
    pub hash: Hash,
    /// Height, taken from the miner transaction's generation input.
    pub height: u64,
    /// Hash of the previous block.
    pub prev_hash: Hash,
    /// Block timestamp, seconds since the epoch.
    pub timestamp: u64,
    /// Hard-fork version (`major_version` in monerod).
    pub major_version: u8,
    /// Hard-fork vote (`minor_version` in monerod).
    pub minor_version: u8,
    /// Hash of the miner (coinbase) transaction.
    pub miner_tx_hash: Hash,
    /// Hashes of the non-coinbase transactions, in block order.
    pub tx_hashes: Vec<Hash>,
}

/// Parse a block blob and compute its hash.
pub fn parse_block(blob: &[u8]) -> Result<ParsedBlock, HashError> {
    let mut cursor = Cursor::new(blob);
    let block = Block::read(&mut cursor).map_err(|e| HashError::Malformed(e.to_string()))?;
    reject_trailing(&cursor)?;

    let height = u64::try_from(block.number())
        .map_err(|_| HashError::Malformed("block height exceeds u64".to_owned()))?;

    Ok(ParsedBlock {
        hash: block.hash(),
        height,
        prev_hash: block.header.previous,
        timestamp: block.header.timestamp,
        major_version: block.header.hardfork_version,
        minor_version: block.header.hardfork_signal,
        miner_tx_hash: block.miner_transaction().hash(),
        tx_hashes: block.transactions,
    })
}

/// The hash of a block blob. See [`parse_block`] for the rest of the fields.
pub fn block_hash(blob: &[u8]) -> Result<Hash, HashError> {
    parse_block(blob).map(|b| b.hash)
}

/// The txid of a full (unpruned) transaction blob, v1 or v2.
pub fn tx_hash(blob: &[u8]) -> Result<Hash, HashError> {
    let mut cursor = Cursor::new(blob);
    let tx = Transaction::<NotPruned>::read(&mut cursor)
        .map_err(|e| HashError::Malformed(e.to_string()))?;
    reject_trailing(&cursor)?;
    Ok(tx.hash())
}

/// The txid of a pruned transaction blob, given the prunable hash the node
/// reports alongside it (`prunable_hash` in `/get_transactions`).
///
/// Only v2 transactions have a prunable-hash form. For a v2 transaction whose
/// RingCT type is `Null` (coinbase: no prunable part) the hash uses an
/// **all-zero** prunable hash, while monerod's `/get_transactions` reports
/// `prunable_hash` as the Keccak of the empty string for it; callers must
/// pass zeros for that case (see `mnr-relay`'s verifier, which retries with
/// zeros when the reported value does not match).
///
/// Returns [`HashError::NotVerifiable`] for v1 transactions.
pub fn pruned_tx_hash(pruned_blob: &[u8], prunable_hash: Hash) -> Result<Hash, HashError> {
    let mut cursor = Cursor::new(pruned_blob);
    let tx = Transaction::<Pruned>::read(&mut cursor)
        .map_err(|e| HashError::Malformed(e.to_string()))?;
    reject_trailing(&cursor)?;
    tx.hash_with_prunable_hash(prunable_hash)
        .ok_or(HashError::NotVerifiable)
}

/// Monero's transaction tree hash over an ordered list of tx hashes (miner tx
/// first). `None` for an empty list.
pub fn tx_tree_hash(hashes: Vec<Hash>) -> Option<Hash> {
    monero_oxide::merkle::merkle_root(hashes)
}

fn reject_trailing(cursor: &Cursor<&[u8]>) -> Result<(), HashError> {
    let consumed = usize::try_from(cursor.position()).unwrap_or(usize::MAX);
    let total = cursor.get_ref().len();
    if consumed < total {
        return Err(HashError::TrailingBytes(total - consumed));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Fixture tests against real mainnet data fetched from a public node on
    //! 2026-09-04 (`fixtures/mainnet/`). Blocks: genesis, block 1, the
    //! special-cased block 202612, every hard-fork boundary v2..v16, and a
    //! recent block. Transactions: full and pruned forms for v1, pre-RingCT
    //! and RingCT eras.

    use super::*;
    use serde_json::Value;

    macro_rules! fixture {
        ($name:literal) => {
            include_str!(concat!("../fixtures/mainnet/", $name))
        };
    }

    const BLOCKS: &[(u64, &str)] = &[
        (0, fixture!("block-0.json")),
        (1, fixture!("block-1.json")),
        (202612, fixture!("block-202612.json")),
        (1009827, fixture!("block-1009827.json")),
        (1141317, fixture!("block-1141317.json")),
        (1220516, fixture!("block-1220516.json")),
        (1288616, fixture!("block-1288616.json")),
        (1400000, fixture!("block-1400000.json")),
        (1546000, fixture!("block-1546000.json")),
        (1685555, fixture!("block-1685555.json")),
        (1686275, fixture!("block-1686275.json")),
        (1788000, fixture!("block-1788000.json")),
        (1788720, fixture!("block-1788720.json")),
        (1978433, fixture!("block-1978433.json")),
        (2210000, fixture!("block-2210000.json")),
        (2210720, fixture!("block-2210720.json")),
        (2688888, fixture!("block-2688888.json")),
        (2689608, fixture!("block-2689608.json")),
        (3754000, fixture!("block-3754000.json")),
    ];

    /// (height, full-form response, pruned-form response)
    const TXS: &[(u64, &str, &str)] = &[
        (
            202612,
            fixture!("txs-202612-prune-false.json"),
            fixture!("txs-202612-prune-true.json"),
        ),
        (
            1009827,
            fixture!("txs-1009827-prune-false.json"),
            fixture!("txs-1009827-prune-true.json"),
        ),
        (
            1400000,
            fixture!("txs-1400000-prune-false.json"),
            fixture!("txs-1400000-prune-true.json"),
        ),
        (
            2689608,
            fixture!("txs-2689608-prune-false.json"),
            fixture!("txs-2689608-prune-true.json"),
        ),
        (
            3754000,
            fixture!("txs-3754000-prune-false.json"),
            fixture!("txs-3754000-prune-true.json"),
        ),
    ];

    fn h32(s: &str) -> Hash {
        let v = hex::decode(s).expect("hex");
        v.as_slice().try_into().expect("32 bytes")
    }

    fn json(s: &str) -> Value {
        serde_json::from_str(s).expect("fixture is JSON")
    }

    #[test]
    fn every_fixture_block_hashes_to_its_reported_hash() {
        for (height, raw) in BLOCKS {
            let r = &json(raw)["result"];
            let hdr = &r["block_header"];
            let blob = hex::decode(r["blob"].as_str().unwrap()).unwrap();
            let parsed = parse_block(&blob).unwrap_or_else(|e| panic!("block {height}: {e}"));

            assert_eq!(
                parsed.hash,
                h32(hdr["hash"].as_str().unwrap()),
                "hash @{height}"
            );
            assert_eq!(parsed.height, *height, "height @{height}");
            assert_eq!(parsed.height, hdr["height"].as_u64().unwrap());
            assert_eq!(
                parsed.prev_hash,
                h32(hdr["prev_hash"].as_str().unwrap()),
                "prev @{height}"
            );
            assert_eq!(parsed.timestamp, hdr["timestamp"].as_u64().unwrap());
            assert_eq!(
                u64::from(parsed.major_version),
                hdr["major_version"].as_u64().unwrap()
            );
            assert_eq!(
                u64::from(parsed.minor_version),
                hdr["minor_version"].as_u64().unwrap()
            );
            assert_eq!(
                parsed.miner_tx_hash,
                h32(hdr["miner_tx_hash"].as_str().unwrap()),
                "miner tx @{height}"
            );
            let want: Vec<Hash> = r["tx_hashes"]
                .as_array()
                .map(|a| a.iter().map(|v| h32(v.as_str().unwrap())).collect())
                .unwrap_or_default();
            assert_eq!(parsed.tx_hashes, want, "tx hashes @{height}");
            assert_eq!(
                parsed.tx_hashes.len() as u64,
                hdr["num_txes"].as_u64().unwrap()
            );
        }
    }

    #[test]
    fn block_202612_uses_monerods_special_case_hash() {
        // monerod substitutes a fixed hash for this block; the naive Keccak
        // result differs. Guard that the wrapper carries the special case.
        let r = &json(BLOCKS[2].1)["result"];
        let blob = hex::decode(r["blob"].as_str().unwrap()).unwrap();
        assert_eq!(
            block_hash(&blob).unwrap(),
            h32("bbd604d2ba11ba27935e006ed39c9bfdd99b76bf4a50654bc1e1e61217962698")
        );
    }

    #[test]
    fn genesis_block_is_coinbase_only() {
        let r = &json(BLOCKS[0].1)["result"];
        let blob = hex::decode(r["blob"].as_str().unwrap()).unwrap();
        let parsed = parse_block(&blob).unwrap();
        assert_eq!(parsed.height, 0);
        assert_eq!(parsed.prev_hash, [0u8; 32]);
        assert!(parsed.tx_hashes.is_empty());
        assert_eq!(
            tx_tree_hash(vec![parsed.miner_tx_hash]).unwrap(),
            parsed.miner_tx_hash,
            "tree hash of a single leaf is the leaf"
        );
    }

    #[test]
    fn block_blob_with_trailing_bytes_is_rejected() {
        let r = &json(BLOCKS[3].1)["result"];
        let mut blob = hex::decode(r["blob"].as_str().unwrap()).unwrap();
        blob.push(0);
        assert_eq!(parse_block(&blob), Err(HashError::TrailingBytes(1)));
    }

    #[test]
    fn truncated_block_blob_is_malformed() {
        let r = &json(BLOCKS[3].1)["result"];
        let blob = hex::decode(r["blob"].as_str().unwrap()).unwrap();
        let cut = &blob[..blob.len() / 2];
        assert!(matches!(parse_block(cut), Err(HashError::Malformed(_))));
    }

    #[test]
    fn corrupted_block_blob_does_not_hash_to_reported_hash() {
        let r = &json(BLOCKS[18].1)["result"];
        let mut blob = hex::decode(r["blob"].as_str().unwrap()).unwrap();
        // Flip one bit in the nonce (bytes after the 32-byte prev hash).
        let nonce_at = blob.len() - 1;
        blob[nonce_at] ^= 0x01;
        let want = h32(r["block_header"]["hash"].as_str().unwrap());
        // An unparsable result is also acceptable: the corruption may break decoding.
        if let Ok(p) = parse_block(&blob) {
            assert_ne!(p.hash, want);
        }
    }

    #[test]
    fn every_full_fixture_tx_hashes_to_its_txid() {
        let mut checked = 0;
        for (height, full, _) in TXS {
            for tx in json(full)["txs"].as_array().unwrap() {
                let blob = hex::decode(tx["as_hex"].as_str().unwrap()).unwrap();
                let want = h32(tx["tx_hash"].as_str().unwrap());
                let got = tx_hash(&blob).unwrap_or_else(|e| panic!("tx @{height}: {e}"));
                assert_eq!(got, want, "txid @{height}");
                assert_eq!(tx["block_height"].as_u64().unwrap(), *height);
                checked += 1;
            }
        }
        assert!(
            checked >= 15,
            "expected a meaningful number of txs, got {checked}"
        );
    }

    #[test]
    fn pruned_v2_txs_hash_with_prunable_hash_and_pruned_v1_are_not_verifiable() {
        let mut v1 = 0;
        let mut v2 = 0;
        for (height, full, pruned) in TXS {
            let full_txs = json(full);
            let versions: Vec<u8> = full_txs["txs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|t| hex::decode(t["as_hex"].as_str().unwrap()).unwrap()[0])
                .collect();
            for (tx, version) in json(pruned)["txs"].as_array().unwrap().iter().zip(versions) {
                let blob = hex::decode(tx["pruned_as_hex"].as_str().unwrap()).unwrap();
                let prunable = h32(tx["prunable_hash"].as_str().unwrap());
                let want = h32(tx["tx_hash"].as_str().unwrap());
                let got = pruned_tx_hash(&blob, prunable);
                match version {
                    1 => {
                        assert_eq!(got, Err(HashError::NotVerifiable), "v1 pruned @{height}");
                        v1 += 1;
                    }
                    2 => {
                        assert_eq!(got.unwrap(), want, "v2 pruned txid @{height}");
                        v2 += 1;
                    }
                    v => panic!("unexpected tx version {v}"),
                }
            }
        }
        assert!(v1 >= 1, "fixtures should include pruned v1 txs");
        assert!(v2 >= 5, "fixtures should include pruned v2 txs, got {v2}");
    }

    #[test]
    fn wrong_prunable_hash_changes_the_txid() {
        let (_, _, pruned) = TXS[3];
        let tx = &json(pruned)["txs"][0];
        let blob = hex::decode(tx["pruned_as_hex"].as_str().unwrap()).unwrap();
        let want = h32(tx["tx_hash"].as_str().unwrap());
        let mut prunable = h32(tx["prunable_hash"].as_str().unwrap());
        prunable[0] ^= 0xff;
        assert_ne!(pruned_tx_hash(&blob, prunable).unwrap(), want);
    }

    #[test]
    fn tx_blob_with_trailing_bytes_is_rejected() {
        let tx = &json(TXS[4].1)["txs"][0];
        let mut blob = hex::decode(tx["as_hex"].as_str().unwrap()).unwrap();
        blob.extend_from_slice(&[0, 0]);
        assert_eq!(tx_hash(&blob), Err(HashError::TrailingBytes(2)));
    }

    #[test]
    fn keccak256_matches_known_vector() {
        // Keccak-256 (original padding), not SHA3-256: empty input.
        assert_eq!(
            keccak256([]),
            h32("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        );
    }
}
