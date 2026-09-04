//! `headerchain` — the relay's header chain store.
//!
//! For every height from genesis the chain holds `(hash, prev_hash, timestamp,
//! height)` — 80 bytes per record, ~3.5 M records ≈ 280 MB on disk
//! (`docs/stage2-network-protocol-architecture.md` §3.4). Records are stored
//! contiguously as a [`Vec<Entry>`] where each [`Entry`] is exactly 80 bytes
//! inline (no boxed structs, no hash map), so lookup by height is O(1)
//! indexing and the whole chain serialises to `16 + 80·n` bytes.
//!
//! Genesis is the special case: height 0 with an all-zero `prev_hash`. Every
//! other record must link: `height == tip + 1` and `prev_hash == tip.hash`
//! ([`HeaderChain::append`] enforces this, and [`HeaderChain::from_bytes`]
//! re-enforces it on load so a poisoned file cannot load).
//!
//! There is **no I/O** in this crate: [`HeaderChain::to_bytes`] /
//! [`HeaderChain::from_bytes`] hand bytes to the relay, which owns the disk.

use std::fmt;

use crate::hash::{Hash, ParsedBlock};

/// File magic: `mnrh`.
const MAGIC: [u8; 4] = *b"mnrh";
/// Byte-format version; bump on any layout change.
const FORMAT_VERSION: u32 = 1;
/// Network id in the file header; 0 = mainnet (1 = stagenet reserved).
const NETWORK_ID_MAINNET: u8 = 0;
/// Size of the file header: 4 magic + 4 version + 1 network + 7 reserved.
const HEADER_SIZE: usize = 16;
/// Size of one record: 8 height + 32 hash + 32 prev_hash + 8 timestamp.
const ENTRY_SIZE: usize = 80;

/// One header-chain record: the hash, previous hash and timestamp of the block
/// at `height`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    /// Block height, from genesis (0).
    pub height: u64,
    /// The block hash.
    pub hash: Hash,
    /// Hash of the previous block; all-zero for genesis.
    pub prev_hash: Hash,
    /// Block timestamp, seconds since the epoch.
    pub timestamp: u64,
}

impl From<&ParsedBlock> for Entry {
    fn from(b: &ParsedBlock) -> Self {
        Self {
            height: b.height,
            hash: b.hash,
            prev_hash: b.prev_hash,
            timestamp: b.timestamp,
        }
    }
}

impl Entry {
    /// Serialise to the 80-byte record: `height` u64 LE, `hash`, `prev_hash`,
    /// `timestamp` u64 LE.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 80] {
        let mut out = [0u8; 80];
        out[0..8].copy_from_slice(&self.height.to_le_bytes());
        out[8..40].copy_from_slice(&self.hash);
        out[40..72].copy_from_slice(&self.prev_hash);
        out[72..80].copy_from_slice(&self.timestamp.to_le_bytes());
        out
    }

    /// Deserialise an 80-byte record. Linkage is **not** checked here; that is
    /// the job of [`HeaderChain::from_bytes`].
    #[must_use]
    pub fn from_bytes(raw: &[u8; 80]) -> Self {
        let mut height = [0u8; 8];
        height.copy_from_slice(&raw[0..8]);
        let mut timestamp = [0u8; 8];
        timestamp.copy_from_slice(&raw[72..80]);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&raw[8..40]);
        let mut prev_hash = [0u8; 32];
        prev_hash.copy_from_slice(&raw[40..72]);
        Self {
            height: u64::from_le_bytes(height),
            hash,
            prev_hash,
            timestamp: u64::from_le_bytes(timestamp),
        }
    }
}

/// Why a record could not be appended, or a chain could not be loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// `height` is not exactly `tip + 1` (or, on an empty chain, not 0).
    HeightGap { expected: u64, got: u64 },
    /// `prev_hash` does not equal the tip's hash.
    PrevMismatch { height: u64 },
    /// The first record is height 0 but has a non-zero `prev_hash`.
    BadGenesis,
    /// A stored chain failed its header or linkage checks.
    Corrupt(String),
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeightGap { expected, got } => {
                write!(f, "height gap: expected {expected}, got {got}")
            }
            Self::PrevMismatch { height } => write!(f, "previous hash mismatch at height {height}"),
            Self::BadGenesis => f.write_str("genesis must have an all-zero previous hash"),
            Self::Corrupt(why) => write!(f, "corrupt header chain: {why}"),
        }
    }
}

impl std::error::Error for ChainError {}

/// The header chain: records in height order, stored contiguously.
///
/// `entries[i]` is the record for height `i` (the invariant `append` and
/// `from_bytes` maintain), so lookup by height is a single Vec index.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeaderChain {
    entries: Vec<Entry>,
}

impl HeaderChain {
    /// An empty chain at genesis-1.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Number of records (one per height, from genesis). `len == tip.height + 1`.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when no records have been appended yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The tip record, or `None` for an empty chain.
    #[must_use]
    pub fn tip(&self) -> Option<Entry> {
        self.entries.last().copied()
    }

    /// The record at `height`, or `None` if the chain does not reach it.
    #[must_use]
    pub fn get(&self, height: u64) -> Option<Entry> {
        let i = usize::try_from(height).ok()?;
        self.entries.get(i).copied()
    }

    /// The block hash at `height`, or `None` if the chain does not reach it.
    #[must_use]
    pub fn hash_at(&self, height: u64) -> Option<Hash> {
        self.get(height).map(|e| e.hash)
    }

    /// Append a record. The chain must link: on an empty chain the first record
    /// must be genesis (height 0, all-zero `prev_hash`); otherwise `height`
    /// must equal `tip + 1` and `prev_hash` must equal the tip's hash.
    pub fn append(&mut self, entry: Entry) -> Result<(), ChainError> {
        match self.entries.last() {
            None => {
                if entry.height != 0 {
                    return Err(ChainError::HeightGap {
                        expected: 0,
                        got: entry.height,
                    });
                }
                if entry.prev_hash != [0u8; 32] {
                    return Err(ChainError::BadGenesis);
                }
            }
            Some(tip) => {
                let expected = tip.height.saturating_add(1);
                if entry.height != expected {
                    return Err(ChainError::HeightGap {
                        expected,
                        got: entry.height,
                    });
                }
                if entry.prev_hash != tip.hash {
                    return Err(ChainError::PrevMismatch {
                        height: entry.height,
                    });
                }
            }
        }
        self.entries.push(entry);
        Ok(())
    }

    /// Keep only entries at `height` and below, returning how many were
    /// dropped. A no-op when `height` is at or beyond the tip.
    pub fn truncate(&mut self, height: u64) -> usize {
        let keep = usize::try_from(height.saturating_add(1)).unwrap_or(usize::MAX);
        let keep = keep.min(self.entries.len());
        let dropped = self.entries.len() - keep;
        self.entries.truncate(keep);
        dropped
    }

    /// The highest height at which `self` and `candidate` agree: the last
    /// `candidate` entry whose hash equals ours at the same height. Used for
    /// reorg detection against a contiguous run of entries from another node.
    #[must_use]
    pub fn fork_point(&self, candidate: &[Entry]) -> Option<u64> {
        let mut highest = None;
        for e in candidate {
            if self.hash_at(e.height) == Some(e.hash) {
                highest = Some(e.height);
            }
        }
        highest
    }

    /// The highest immutable height: the tip minus `depth`, saturating at
    /// genesis. Pass [`crate::policy::TIP_SAFETY_DEPTH`] as `depth` for the
    /// tip−10 rule. `None` when the chain is empty.
    #[must_use]
    pub fn safety_line(&self, depth: u64) -> Option<u64> {
        self.tip().map(|t| t.height.saturating_sub(depth))
    }

    /// Serialise to bytes: a 16-byte header (`mnrh`, format version 1 u32 LE,
    /// network id 0 = mainnet, 7 reserved zero bytes) followed by one 80-byte
    /// record per height.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_SIZE + self.entries.len() * ENTRY_SIZE);
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        out.push(NETWORK_ID_MAINNET);
        out.extend_from_slice(&[0u8; 7]);
        for e in &self.entries {
            out.extend_from_slice(&e.to_bytes());
        }
        out
    }

    /// Load from [`HeaderChain::to_bytes`] output. Checks the magic and format
    /// version, requires the body to be a whole number of 80-byte records, and
    /// re-validates the linkage of every record (genesis, height and prev-hash
    /// chain) so a poisoned file cannot load.
    pub fn from_bytes(data: &[u8]) -> Result<Self, ChainError> {
        if data.len() < HEADER_SIZE {
            return Err(ChainError::Corrupt(
                "shorter than the 16-byte header".to_owned(),
            ));
        }
        let magic: [u8; 4] = data[0..4].try_into().expect("header length checked");
        if magic != MAGIC {
            return Err(ChainError::Corrupt("bad magic".to_owned()));
        }
        let version: [u8; 4] = data[4..8].try_into().expect("header length checked");
        let version = u32::from_le_bytes(version);
        if version != FORMAT_VERSION {
            return Err(ChainError::Corrupt(format!(
                "unsupported format version {version}"
            )));
        }
        // Only mainnet files exist in version 1, and the reserved bytes must
        // be zero so that a loaded file always serialises back byte-for-byte.
        if data[8] != NETWORK_ID_MAINNET {
            return Err(ChainError::Corrupt(format!(
                "unsupported network id {}",
                data[8]
            )));
        }
        if data[9..HEADER_SIZE].iter().any(|&b| b != 0) {
            return Err(ChainError::Corrupt(
                "reserved header bytes are not zero".to_owned(),
            ));
        }

        let body = &data[HEADER_SIZE..];
        if body.len() % ENTRY_SIZE != 0 {
            return Err(ChainError::Corrupt(format!(
                "body length {} is not a multiple of 80",
                body.len()
            )));
        }

        let mut chain = HeaderChain {
            entries: Vec::with_capacity(body.len() / ENTRY_SIZE),
        };
        for chunk in body.chunks_exact(ENTRY_SIZE) {
            let entry = Entry::from_bytes(chunk.try_into().expect("chunk is 80 bytes"));
            chain
                .append(entry)
                .map_err(|e| ChainError::Corrupt(format!("invalid record: {e}")))?;
        }
        Ok(chain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn entry(height: u64, hash: Hash, timestamp: u64) -> Entry {
        Entry {
            height,
            hash,
            prev_hash: [0u8; 32],
            timestamp,
        }
    }

    /// A deterministic hash for height `h` on the "real" chain (byte 8 = 0xAB).
    fn real_hash(h: u64) -> Hash {
        let mut hash = [0u8; 32];
        hash[..8].copy_from_slice(&h.to_le_bytes());
        hash[8] = 0xAB;
        hash
    }

    /// A deterministic hash for height `h` on an alternate (diverging) chain.
    fn alt_hash(h: u64) -> Hash {
        let mut hash = [0u8; 32];
        hash[..8].copy_from_slice(&h.to_le_bytes());
        hash[8] = 0xFE;
        hash
    }

    fn synthetic_chain(n: u64) -> HeaderChain {
        let mut chain = HeaderChain::new();
        for h in 0..n {
            let prev = if h == 0 {
                [0u8; 32]
            } else {
                chain.tip().expect("previous appended").hash
            };
            chain
                .append(Entry {
                    height: h,
                    hash: real_hash(h),
                    prev_hash: prev,
                    timestamp: h * 1000 + 1,
                })
                .unwrap();
        }
        chain
    }

    #[test]
    fn synthetic_chain_appends_and_round_trips() {
        let chain = synthetic_chain(1000);
        assert_eq!(chain.len(), 1000);
        assert!(!chain.is_empty());
        assert_eq!(chain.tip().unwrap().height, 999);
        assert_eq!(chain.get(0).unwrap().prev_hash, [0u8; 32]);
        assert_eq!(chain.hash_at(42), chain.get(42).map(|e| e.hash));
        assert_eq!(chain.get(1000), None);
        assert_eq!(
            chain.safety_line(crate::policy::TIP_SAFETY_DEPTH),
            Some(999 - crate::policy::TIP_SAFETY_DEPTH)
        );

        // An empty chain also round-trips.
        assert_eq!(
            HeaderChain::from_bytes(&HeaderChain::new().to_bytes()).unwrap(),
            HeaderChain::new()
        );

        let bytes = chain.to_bytes();
        assert_eq!(bytes.len(), 16 + 1000 * 80);
        let restored = HeaderChain::from_bytes(&bytes).unwrap();
        assert_eq!(restored, chain);
        assert_eq!(restored.to_bytes(), bytes);

        // The single-record format is 80 bytes and round-trips.
        let raw = chain.get(7).unwrap().to_bytes();
        assert_eq!(raw.len(), 80);
        assert_eq!(Entry::from_bytes(&raw), chain.get(7).unwrap());
    }

    #[test]
    fn rejects_height_gap() {
        let mut chain = HeaderChain::new();
        assert_eq!(
            chain.append(entry(1, real_hash(1), 1)),
            Err(ChainError::HeightGap {
                expected: 0,
                got: 1
            })
        );
        chain.append(entry(0, real_hash(0), 0)).unwrap();
        assert_eq!(
            chain.append(entry(2, real_hash(2), 2)),
            Err(ChainError::HeightGap {
                expected: 1,
                got: 2
            })
        );
        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn rejects_prev_mismatch() {
        let mut chain = HeaderChain::new();
        chain.append(entry(0, real_hash(0), 0)).unwrap();
        let bad = Entry {
            height: 1,
            hash: real_hash(1),
            prev_hash: [9u8; 32],
            timestamp: 1,
        };
        assert_eq!(
            chain.append(bad),
            Err(ChainError::PrevMismatch { height: 1 })
        );
        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn rejects_nonzero_genesis_prev() {
        let mut chain = HeaderChain::new();
        let genesis = Entry {
            height: 0,
            hash: real_hash(0),
            prev_hash: [7u8; 32],
            timestamp: 0,
        };
        assert_eq!(chain.append(genesis), Err(ChainError::BadGenesis));
        assert!(chain.is_empty());
    }

    #[test]
    fn truncate_then_reappend() {
        let mut chain = synthetic_chain(10);
        assert_eq!(chain.truncate(4), 5); // drops heights 5..=9
        assert_eq!(chain.len(), 5);
        assert_eq!(chain.tip().unwrap().height, 4);

        // Height 5 can be re-appended because it links to the new tip.
        let prev = chain.tip().unwrap().hash;
        chain
            .append(Entry {
                height: 5,
                hash: real_hash(5),
                prev_hash: prev,
                timestamp: 5 * 1000 + 1,
            })
            .unwrap();
        assert_eq!(chain.tip().unwrap().height, 5);

        // Truncating beyond the tip is a no-op.
        assert_eq!(chain.truncate(1000), 0);
        assert_eq!(chain.len(), 6);
    }

    #[test]
    fn fork_point_finds_divergence() {
        let ours = synthetic_chain(20);
        // A 20-entry candidate sharing heights 0..=11 with us, diverging at 12.
        let mut candidate = Vec::new();
        for h in 0..20u64 {
            let (hash, prev) = if h < 12 {
                let e = ours.get(h).unwrap();
                (e.hash, e.prev_hash)
            } else if h == 12 {
                (alt_hash(h), ours.get(11).unwrap().hash)
            } else {
                (alt_hash(h), alt_hash(h - 1))
            };
            candidate.push(Entry {
                height: h,
                hash,
                prev_hash: prev,
                timestamp: h,
            });
        }
        assert_eq!(ours.fork_point(&candidate), Some(11));
        assert_eq!(ours.fork_point(&[]), None);
    }

    #[test]
    fn safety_line_is_none_for_empty_chain() {
        assert_eq!(
            HeaderChain::new().safety_line(crate::policy::TIP_SAFETY_DEPTH),
            None
        );
        assert_eq!(HeaderChain::new().safety_line(10), None);
    }

    #[test]
    fn from_bytes_rejects_corrupt_data() {
        let bytes = synthetic_chain(3).to_bytes();

        // Bad magic.
        let mut bad = bytes.clone();
        bad[0] ^= 0xff;
        assert!(matches!(
            HeaderChain::from_bytes(&bad),
            Err(ChainError::Corrupt(_))
        ));

        // Wrong format version.
        let mut bad = bytes.clone();
        bad[4] = 2;
        assert!(matches!(
            HeaderChain::from_bytes(&bad),
            Err(ChainError::Corrupt(_))
        ));

        // Wrong network id, or non-zero reserved bytes (found by fuzzing:
        // these loaded fine but did not round-trip).
        let mut bad = bytes.clone();
        bad[8] = 1;
        assert!(matches!(
            HeaderChain::from_bytes(&bad),
            Err(ChainError::Corrupt(_))
        ));
        let mut bad = bytes.clone();
        bad[15] = 0x9d;
        assert!(matches!(
            HeaderChain::from_bytes(&bad),
            Err(ChainError::Corrupt(_))
        ));

        // Truncated body: no longer a whole number of 80-byte records.
        let bad = &bytes[..bytes.len() - 40];
        assert!(matches!(
            HeaderChain::from_bytes(bad),
            Err(ChainError::Corrupt(_))
        ));

        // A record whose prev_hash was flipped breaks linkage on load.
        let mut bad = bytes.clone();
        let off = HEADER_SIZE + ENTRY_SIZE + 40; // record 1's prev_hash
        bad[off] ^= 1;
        assert!(matches!(
            HeaderChain::from_bytes(&bad),
            Err(ChainError::Corrupt(_))
        ));
    }

    fn entry_from_fixture(raw: &str) -> Entry {
        let r = &serde_json::from_str::<Value>(raw).expect("fixture is JSON")["result"];
        let blob = hex::decode(r["blob"].as_str().expect("blob hex")).expect("hex blob");
        Entry::from(&crate::hash::parse_block(&blob).expect("parses as a block"))
    }

    #[test]
    fn real_genesis_and_block_one_link() {
        let genesis = entry_from_fixture(include_str!("../fixtures/mainnet/block-0.json"));
        let block_one = entry_from_fixture(include_str!("../fixtures/mainnet/block-1.json"));

        assert_eq!(genesis.height, 0);
        assert_eq!(genesis.prev_hash, [0u8; 32]);
        assert_eq!(block_one.height, 1);
        assert_eq!(
            block_one.prev_hash, genesis.hash,
            "block 1's prev_hash must equal genesis's hash"
        );

        let mut chain = HeaderChain::new();
        chain.append(genesis).unwrap();
        chain.append(block_one).unwrap();
        assert_eq!(chain.tip().unwrap().height, 1);
        assert_eq!(chain.hash_at(0), Some(genesis.hash));
        assert_eq!(chain.hash_at(1), Some(block_one.hash));
        assert_eq!(chain.get(1).unwrap().prev_hash, chain.hash_at(0).unwrap());
    }
}
