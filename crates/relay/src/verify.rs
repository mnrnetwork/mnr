//! Verification of upstream answers in the request path
//! (`docs/stage0-mvp-plan.md` §4; invariant 1: verify, don't trust).
//!
//! The pure rules live in `mnr_core::verify`; this module reads what the
//! client asked for and what the node answered, applies them, and says one
//! of three things:
//!
//! - **verified**, with the label the answer earned (`Mnr-Verify`):
//!   `chain` when the header chain confirmed it, `hash` when only the
//!   recomputed hash matched the request, `partial` when some entries of a
//!   batch could not be checked;
//! - **not verifiable** (`none`): our chain does not reach the height, or
//!   the data has no self-authenticating form. Served annotated, never cached;
//! - a **fault**: the node's answer is wrong. It is never returned to the
//!   client; the caller records it against the upstream and asks another.
//!
//! A daemon-level error in the answer (unknown hash, height too high) is
//! not a fault: it is passed through as `none`.

use mnr_core::hash::Hash;
use mnr_core::headerchain::HeaderChain;
use mnr_core::verify::{
    self as rules, Expected, ReportedHeader, TxForm, TxLocation, TxVerdict, VerifyError,
};
use mnr_core::wire::{
    decode_hex, decode_hex32, GetBlockHeaderResult, GetBlockHeadersRangeResult, GetBlockResult,
    GetTransactionsResult, JsonRpcResponse,
};
use serde_json::Value;

/// The `Mnr-Verify` label, in precedence order (strongest first).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verify {
    /// Confirmed against the relay's header chain.
    Chain,
    /// The recomputed hash matched what the client asked for.
    Hash,
    /// Consensus state agreed by a majority of upstreams.
    Majority,
    /// Identical answers from the number of upstreams the tier requires.
    Agreement,
    /// Some entries of a batch verified, some could not be (see `Mnr-Verified`).
    Partial,
    /// Not verifiable; annotated and never trusted silently.
    None,
    /// Every upstream's answer failed verification (error response only).
    Failed,
}

impl Verify {
    pub fn label(self) -> &'static str {
        match self {
            Self::Chain => "chain",
            Self::Hash => "hash",
            Self::Majority => "majority",
            Self::Agreement => "agreement",
            Self::Partial => "partial",
            Self::None => "none",
            Self::Failed => "failed",
        }
    }
}

/// What verification learned about an acceptable answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub verify: Verify,
    /// The highest block height the answer depends on, when known. The
    /// caller caches only if this is at or below the tip safety line.
    pub height: Option<u64>,
    /// `(verified, total)` behind a `partial` label.
    pub counted: Option<(usize, usize)>,
}

impl Verified {
    fn none() -> Self {
        Self {
            verify: Verify::None,
            height: None,
            counted: None,
        }
    }

    fn at(verify: Verify, height: u64) -> Self {
        Self {
            verify,
            height: Some(height),
            counted: None,
        }
    }
}

/// A wrong answer: the detail goes to the public fault log (no client data
/// in it, only what the node said and what it should have said).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fault(pub String);

/// The canonical name of a JSON-RPC method or legacy path, so aliases
/// monerod registers (`getblock`, `/gettransactions`) verify the same way.
pub fn canonical(method: &str) -> &str {
    const CANONICAL: &[&str] = &[
        "get_block",
        "get_block_header_by_hash",
        "get_block_header_by_height",
        "get_block_headers_range",
        "on_get_block_hash",
        "/get_transactions",
        "/get_height",
        "/get_info",
        "get_last_block_header",
        "get_block_count",
    ];
    let bare: String = method.chars().filter(|c| *c != '_').collect();
    CANONICAL
        .iter()
        .copied()
        .find(|c| c.chars().filter(|ch| *ch != '_').eq(bare.chars()))
        .unwrap_or(method)
}

/// Verify a JSON-RPC answer for one of the immutable methods. Methods this
/// module does not know are `none`.
pub fn verify_jsonrpc(
    method: &str,
    params: Option<&Value>,
    body: &[u8],
    chain: &HeaderChain,
) -> Result<Verified, Fault> {
    match canonical(method) {
        "get_block" => verify_get_block(params, body, chain),
        "get_block_header_by_height" => verify_header_by_height(params, body, chain),
        "get_block_header_by_hash" => verify_header_by_hash(params, body, chain),
        "get_block_headers_range" => verify_headers_range(params, body, chain),
        "on_get_block_hash" => verify_block_hash(params, body, chain),
        _ => Ok(Verified::none()),
    }
}

/// Parse a JSON-RPC envelope; a daemon error is `Ok(None)` (pass through as
/// `none`), a body that is not a JSON-RPC response is a fault.
fn envelope<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<Option<T>, Fault> {
    let resp: JsonRpcResponse<T> = serde_json::from_slice(body)
        .map_err(|_| Fault("answer is not a JSON-RPC response of the expected shape".into()))?;
    Ok(resp.result)
}

fn param_u64(params: Option<&Value>, key: &str) -> Option<u64> {
    params?.get(key)?.as_u64()
}

/// A hash the *client* supplied. A malformed one is the client's problem,
/// never the upstream's: the daemon's error answer passes through as
/// `none`, and no fault is recorded (the public fault log counts wrong
/// answers only).
fn param_hash(params: Option<&Value>, key: &str) -> Option<Hash> {
    let s = params?.get(key)?.as_str()?;
    if s.is_empty() {
        return None;
    }
    decode_hex32(s).ok()
}

fn hex(h: &Hash) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

fn verify_get_block(
    params: Option<&Value>,
    body: &[u8],
    chain: &HeaderChain,
) -> Result<Verified, Fault> {
    let Some(result) = envelope::<GetBlockResult>(body)? else {
        return Ok(Verified::none());
    };
    // monerod serves by hash when one is given, else by height. A hash we
    // cannot decode cannot be checked against anything.
    let hash_given = params
        .and_then(|p| p.get("hash"))
        .and_then(Value::as_str)
        .is_some_and(|h| !h.is_empty());
    let by_hash = param_hash(params, "hash");
    if hash_given && by_hash.is_none() {
        return Ok(Verified::none());
    }
    let blob = decode_hex(&result.blob).map_err(|_| Fault("block blob is not hex".into()))?;
    let by_height = param_u64(params, "height");
    let (parsed, verify) = match (by_hash, by_height) {
        (Some(want), _) => {
            let parsed = rules::verify_block(&blob, Expected::Hash(want))
                .map_err(|e| Fault(e.to_string()))?;
            // On our chain at that height too: the block is canonical.
            let label = if chain.hash_at(parsed.height) == Some(parsed.hash) {
                Verify::Chain
            } else {
                Verify::Hash
            };
            (parsed, label)
        }
        (None, Some(height)) => {
            match rules::verify_block(&blob, Expected::Height { height, chain }) {
                Ok(parsed) => (parsed, Verify::Chain),
                Err(VerifyError::UnknownHeight(_)) => {
                    // Our chain stops short: the blob is self-consistent and at
                    // the requested height, but we cannot say it is canonical.
                    let parsed =
                        mnr_core::hash::parse_block(&blob).map_err(|e| Fault(e.to_string()))?;
                    if parsed.height != height {
                        return Err(Fault(format!(
                            "block at height {} answered for height {height}",
                            parsed.height
                        )));
                    }
                    (parsed, Verify::None)
                }
                Err(e) => return Err(Fault(e.to_string())),
            }
        }
        (None, None) => return Ok(Verified::none()),
    };
    // The header object must describe the blob it came with.
    let h = &result.block_header;
    let reported =
        ReportedHeader::try_from(h).map_err(|_| Fault("block_header hashes are not hex".into()))?;
    if reported.hash != parsed.hash
        || reported.height != parsed.height
        || reported.prev_hash != parsed.prev_hash
        || reported.timestamp != parsed.timestamp
        || h.major_version != parsed.major_version
        || h.minor_version != parsed.minor_version
    {
        return Err(Fault(format!(
            "block_header disagrees with the blob at height {}",
            parsed.height
        )));
    }
    if result.miner_tx_hash != hex(&parsed.miner_tx_hash) || h.miner_tx_hash != result.miner_tx_hash
    {
        return Err(Fault(format!(
            "miner_tx_hash disagrees with the blob at height {}",
            parsed.height
        )));
    }
    if let Some(list) = &result.tx_hashes {
        let ours: Vec<String> = parsed.tx_hashes.iter().map(hex).collect();
        if *list != ours {
            return Err(Fault(format!(
                "tx_hashes disagree with the blob at height {}",
                parsed.height
            )));
        }
    }
    if h.num_txes != parsed.tx_hashes.len() as u64 {
        return Err(Fault(format!(
            "num_txes disagrees with the blob at height {}",
            parsed.height
        )));
    }
    Ok(Verified::at(verify, parsed.height))
}

fn verify_header_by_height(
    params: Option<&Value>,
    body: &[u8],
    chain: &HeaderChain,
) -> Result<Verified, Fault> {
    let Some(height) = param_u64(params, "height") else {
        return Ok(Verified::none());
    };
    let Some(result) = envelope::<GetBlockHeaderResult>(body)? else {
        return Ok(Verified::none());
    };
    let reported = ReportedHeader::try_from(&result.block_header)
        .map_err(|_| Fault("block_header hashes are not hex".into()))?;
    match rules::verify_header_by_height(height, &reported, chain) {
        Ok(()) => Ok(Verified::at(Verify::Chain, height)),
        Err(VerifyError::UnknownHeight(_)) => Ok(Verified::at(Verify::None, height)),
        Err(e) => Err(Fault(e.to_string())),
    }
}

fn verify_header_by_hash(
    params: Option<&Value>,
    body: &[u8],
    chain: &HeaderChain,
) -> Result<Verified, Fault> {
    // The `hashes: [...]` batch form returns `block_headers`; not checked.
    // Nor is a request hash we cannot decode.
    let Some(requested) = param_hash(params, "hash") else {
        return Ok(Verified::none());
    };
    let Some(result) = envelope::<GetBlockHeaderResult>(body)? else {
        return Ok(Verified::none());
    };
    let reported = ReportedHeader::try_from(&result.block_header)
        .map_err(|_| Fault("block_header hashes are not hex".into()))?;
    if reported.hash != requested {
        return Err(Fault(format!(
            "header {} answered for hash {}",
            &hex(&reported.hash)[..8],
            &hex(&requested)[..8]
        )));
    }
    match rules::verify_header_by_hash(requested, &reported, chain) {
        Ok(()) => Ok(Verified::at(Verify::Chain, reported.height)),
        Err(VerifyError::UnknownHeight(_)) => Ok(Verified::at(Verify::None, reported.height)),
        // Our chain has another block at that height: an orphan answered by
        // hash is honest only if the node says so.
        Err(VerifyError::HashMismatch { .. })
            if result.block_header.orphan_status != Some(false) =>
        {
            Ok(Verified::at(Verify::None, reported.height))
        }
        Err(e) => Err(Fault(e.to_string())),
    }
}

fn verify_headers_range(
    params: Option<&Value>,
    body: &[u8],
    chain: &HeaderChain,
) -> Result<Verified, Fault> {
    let (Some(start), Some(end)) = (
        param_u64(params, "start_height"),
        param_u64(params, "end_height"),
    ) else {
        return Ok(Verified::none());
    };
    let Some(result) = envelope::<GetBlockHeadersRangeResult>(body)? else {
        return Ok(Verified::none());
    };
    if end < start {
        return Ok(Verified::none());
    }
    if result.headers.len() as u64 != end - start + 1 {
        return Err(Fault(format!(
            "{} headers answered for {start}..={end}",
            result.headers.len()
        )));
    }
    let mut on_chain = true;
    let mut prev: Option<ReportedHeader> = None;
    for (i, h) in result.headers.iter().enumerate() {
        let want = start + i as u64;
        let reported = ReportedHeader::try_from(h)
            .map_err(|_| Fault("block_header hashes are not hex".into()))?;
        if reported.height != want {
            return Err(Fault(format!(
                "height {} at position {i} of {start}..={end}",
                reported.height
            )));
        }
        if let Some(p) = prev {
            if reported.prev_hash != p.hash {
                return Err(Fault(format!("headers do not link at height {want}")));
            }
        }
        match rules::verify_header_by_height(want, &reported, chain) {
            Ok(()) => {}
            Err(VerifyError::UnknownHeight(_)) => on_chain = false,
            Err(e) => return Err(Fault(e.to_string())),
        }
        prev = Some(reported);
    }
    // No partial trust on a range: either every header is on our chain or
    // the answer is annotated as unverified.
    Ok(Verified::at(
        if on_chain {
            Verify::Chain
        } else {
            Verify::None
        },
        end,
    ))
}

fn verify_block_hash(
    params: Option<&Value>,
    body: &[u8],
    chain: &HeaderChain,
) -> Result<Verified, Fault> {
    let Some(height) = params
        .and_then(|p| p.as_array())
        .and_then(|a| a.first())
        .and_then(Value::as_u64)
    else {
        return Ok(Verified::none());
    };
    let Some(result) = envelope::<String>(body)? else {
        return Ok(Verified::none());
    };
    let Some(ours) = chain.hash_at(height) else {
        return Ok(Verified::at(Verify::None, height));
    };
    let got = decode_hex32(&result).map_err(|_| Fault("block hash is not hex".into()))?;
    if got != ours {
        return Err(Fault(format!(
            "hash mismatch at height {height}: expected {} got {}",
            &hex(&ours)[..8],
            &hex(&got)[..8]
        )));
    }
    Ok(Verified::at(Verify::Chain, height))
}

/// One `/get_transactions` entry's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxCheck {
    /// Hashes to its txid; `height` is where the node says it is confirmed.
    Verified { height: Option<u64> },
    /// No hashable form (pruned v1 tx): not a fault, not verified.
    Unverifiable,
}

/// How far above the quorum tip a confirmed height may be before it is a
/// lie. The quorum tip lags a probe round (15 s) behind the network, and a
/// node on the real tip answers honestly with the newest block's height;
/// two blocks in one round happens, three is rare, more is a claim no honest
/// node makes. Found in the beta: without slack, every node was faulted and
/// ejected for telling the truth about the newest block.
pub const TIP_SLACK: u64 = 3;

/// Verify every entry of a `/get_transactions` answer against the request.
/// `tip` is the quorum tip height; a confirmed height more than
/// [`TIP_SLACK`] above it is a lie. Returns one verdict per entry, in answer
/// order.
pub fn verify_transactions(
    requested: &[String],
    result: &GetTransactionsResult,
    tip: Option<u64>,
) -> Result<Vec<TxCheck>, Fault> {
    // The parallel arrays a wallet may read instead of `txs[i]` must carry
    // the same bytes as the entries that were hashed, or a node could pass
    // a txid-valid entry next to a different blob.
    if result.txs_as_hex.len() != result.txs.len() {
        return Err(Fault(format!(
            "{} txs_as_hex for {} txs",
            result.txs_as_hex.len(),
            result.txs.len()
        )));
    }
    if let Some(as_json) = &result.txs_as_json {
        if as_json.len() != result.txs.len() {
            return Err(Fault(format!(
                "{} txs_as_json for {} txs",
                as_json.len(),
                result.txs.len()
            )));
        }
    }
    let mut out = Vec::with_capacity(result.txs.len());
    for (i, e) in result.txs.iter().enumerate() {
        if result.txs_as_hex[i] != e.as_hex {
            return Err(Fault(format!("txs_as_hex disagrees with txs[{i}].as_hex")));
        }
        if let Some(as_json) = &result.txs_as_json {
            if as_json[i] != e.as_json {
                return Err(Fault(format!(
                    "txs_as_json disagrees with txs[{i}].as_json"
                )));
            }
        }
        if !requested.iter().any(|r| r.eq_ignore_ascii_case(&e.tx_hash)) {
            return Err(Fault(format!(
                "unrequested tx {} in answer",
                &e.tx_hash[..e.tx_hash.len().min(8)]
            )));
        }
        let txid = decode_hex32(&e.tx_hash).map_err(|_| Fault("tx_hash is not hex".into()))?;
        let location = if e.in_pool {
            TxLocation::Pool
        } else {
            TxLocation::Block(e.block_height)
        };
        let full;
        let pruned;
        let form = if !e.as_hex.is_empty() {
            full = decode_hex(&e.as_hex).map_err(|_| Fault("as_hex is not hex".into()))?;
            TxForm::Full(&full)
        } else if let Some(p) = e.pruned_as_hex.as_deref().filter(|p| !p.is_empty()) {
            pruned = decode_hex(p).map_err(|_| Fault("pruned_as_hex is not hex".into()))?;
            let prunable_hash = match e.prunable_hash.as_deref().filter(|h| !h.is_empty()) {
                Some(h) => decode_hex32(h).map_err(|_| Fault("prunable_hash is not hex".into()))?,
                None => [0; 32],
            };
            TxForm::Pruned {
                blob: &pruned,
                prunable_hash,
            }
        } else {
            out.push(TxCheck::Unverifiable);
            continue;
        };
        let bound = tip.map_or(u64::MAX, |t| t.saturating_add(TIP_SLACK));
        let mut verdict = rules::verify_tx(form, txid, location, bound);
        // A coinbase (RingCT type Null) hashes with an all-zero prunable
        // hash, but monerod reports `prunable_hash` as the hash of nothing.
        // Retry with zeros before calling a mismatch a lie.
        if let (Err(VerifyError::HashMismatch { .. }), TxForm::Pruned { blob, .. }) =
            (&verdict, form)
        {
            verdict = rules::verify_tx(
                TxForm::Pruned {
                    blob,
                    prunable_hash: [0; 32],
                },
                txid,
                location,
                bound,
            );
        }
        match verdict {
            Ok(TxVerdict::Verified) => out.push(TxCheck::Verified {
                height: (!e.in_pool).then_some(e.block_height),
            }),
            Ok(TxVerdict::NotVerifiable) => out.push(TxCheck::Unverifiable),
            Err(e) => return Err(Fault(e.to_string())),
        }
    }
    if let Some(missed) = &result.missed_tx {
        for m in missed {
            if !requested.iter().any(|r| r.eq_ignore_ascii_case(m)) {
                return Err(Fault("unrequested tx in missed_tx".into()));
            }
        }
    }
    Ok(out)
}

/// The label a batch earns from its entry verdicts.
pub fn batch_label(checks: &[TxCheck]) -> (Verify, Option<(usize, usize)>) {
    let n = checks.len();
    let k = checks
        .iter()
        .filter(|c| matches!(c, TxCheck::Verified { .. }))
        .count();
    if n == 0 || k == 0 {
        (Verify::None, None)
    } else if k == n {
        (Verify::Hash, None)
    } else {
        (Verify::Partial, Some((k, n)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mnr_core::headerchain::Entry;
    use serde_json::json;

    const BLOCK0: &str = include_str!("../../core/fixtures/mainnet/block-0.json");
    const BLOCK1: &str = include_str!("../../core/fixtures/mainnet/block-1.json");
    const BLOCK_HIGH: &str = include_str!("../../core/fixtures/mainnet/block-3754000.json");
    const TXS_FULL: &str = include_str!("../../core/fixtures/mainnet/txs-3754000-prune-false.json");
    const TXS_PRUNED: &str =
        include_str!("../../core/fixtures/mainnet/txs-3754000-prune-true.json");
    const TXS_V1_PRUNED: &str =
        include_str!("../../core/fixtures/mainnet/txs-202612-prune-true.json");
    const TXS_COINBASE: &str =
        include_str!("../../core/fixtures/mainnet/txs-coinbase-3756163.json");

    fn chain_0_1() -> HeaderChain {
        let mut c = HeaderChain::new();
        for fx in [BLOCK0, BLOCK1] {
            let v: Value = serde_json::from_str(fx).unwrap();
            let blob = decode_hex(v["result"]["blob"].as_str().unwrap()).unwrap();
            let p = mnr_core::hash::parse_block(&blob).unwrap();
            c.append(Entry::from(&p)).unwrap();
        }
        c
    }

    fn fixture_hash(fx: &str) -> String {
        let v: Value = serde_json::from_str(fx).unwrap();
        v["result"]["block_header"]["hash"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    /// The fixture with one hex digit of the blob flipped.
    fn tampered(fx: &str) -> String {
        let mut v: Value = serde_json::from_str(fx).unwrap();
        let blob = v["result"]["blob"].as_str().unwrap().to_owned();
        let mut chars: Vec<char> = blob.chars().collect();
        let i = chars.len() - 10;
        chars[i] = if chars[i] == '0' { '1' } else { '0' };
        v["result"]["blob"] = Value::String(chars.into_iter().collect());
        v.to_string()
    }

    #[test]
    fn aliases_verify_as_their_canonical_method() {
        assert_eq!(canonical("getblock"), "get_block");
        assert_eq!(
            canonical("getblockheaderbyhash"),
            "get_block_header_by_hash"
        );
        assert_eq!(canonical("/gettransactions"), "/get_transactions");
        assert_eq!(canonical("/getheight"), "/get_height");
        assert_eq!(canonical("getlastblockheader"), "get_last_block_header");
        assert_eq!(canonical("get_info"), "get_info");
    }

    #[test]
    fn block_by_height_on_our_chain_is_chain_verified() {
        let chain = chain_0_1();
        let v = verify_jsonrpc(
            "get_block",
            Some(&json!({"height": 1})),
            BLOCK1.as_bytes(),
            &chain,
        )
        .unwrap();
        assert_eq!(v, Verified::at(Verify::Chain, 1));
        // The alias behaves identically.
        let v = verify_jsonrpc(
            "getblock",
            Some(&json!({"height": 1})),
            BLOCK1.as_bytes(),
            &chain,
        )
        .unwrap();
        assert_eq!(v.verify, Verify::Chain);
        // Beyond our chain: self-consistent but unverified, height known.
        let v = verify_jsonrpc(
            "get_block",
            Some(&json!({"height": 3754000})),
            BLOCK_HIGH.as_bytes(),
            &chain,
        )
        .unwrap();
        assert_eq!(v, Verified::at(Verify::None, 3_754_000));
        // The node answered block 1 for height 0: a fault.
        let f = verify_jsonrpc(
            "get_block",
            Some(&json!({"height": 0})),
            BLOCK1.as_bytes(),
            &chain,
        )
        .unwrap_err();
        assert!(f.0.contains("height"), "{}", f.0);
    }

    #[test]
    fn block_by_hash_is_hash_verified_and_chain_when_canonical() {
        let chain = chain_0_1();
        let h1 = fixture_hash(BLOCK1);
        let v = verify_jsonrpc(
            "get_block",
            Some(&json!({"hash": h1})),
            BLOCK1.as_bytes(),
            &chain,
        )
        .unwrap();
        assert_eq!(v.verify, Verify::Chain);
        let hh = fixture_hash(BLOCK_HIGH);
        let v = verify_jsonrpc(
            "get_block",
            Some(&json!({"hash": hh})),
            BLOCK_HIGH.as_bytes(),
            &chain,
        )
        .unwrap();
        assert_eq!(v, Verified::at(Verify::Hash, 3_754_000));
        // Wrong block for the hash.
        let f = verify_jsonrpc(
            "get_block",
            Some(&json!({"hash": h1})),
            BLOCK_HIGH.as_bytes(),
            &chain,
        )
        .unwrap_err();
        assert!(f.0.contains("hash mismatch"), "{}", f.0);
    }

    #[test]
    fn tampered_blob_and_disagreeing_header_are_faults() {
        let chain = chain_0_1();
        let hh = fixture_hash(BLOCK_HIGH);
        let body = tampered(BLOCK_HIGH);
        let f = verify_jsonrpc(
            "get_block",
            Some(&json!({"hash": hh})),
            body.as_bytes(),
            &chain,
        )
        .unwrap_err();
        assert!(f.0.contains("hash mismatch"), "{}", f.0);
        // Correct blob, header object lies about the timestamp.
        let mut v: Value = serde_json::from_str(BLOCK_HIGH).unwrap();
        v["result"]["block_header"]["timestamp"] = json!(1);
        let f = verify_jsonrpc(
            "get_block",
            Some(&json!({"hash": hh})),
            v.to_string().as_bytes(),
            &chain,
        )
        .unwrap_err();
        assert!(f.0.contains("block_header disagrees"), "{}", f.0);
        // tx_hashes list does not match the blob.
        let mut v: Value = serde_json::from_str(BLOCK_HIGH).unwrap();
        v["result"]["tx_hashes"][0] = json!("00".repeat(32));
        let f = verify_jsonrpc(
            "get_block",
            Some(&json!({"hash": hh})),
            v.to_string().as_bytes(),
            &chain,
        )
        .unwrap_err();
        assert!(f.0.contains("tx_hashes"), "{}", f.0);
    }

    #[test]
    fn daemon_errors_and_unknown_methods_pass_through_unverified() {
        let chain = chain_0_1();
        let err = json!({"jsonrpc":"2.0","id":0,"error":{"code":-1,"message":"Internal error: can't get block by height"}});
        let v = verify_jsonrpc(
            "get_block",
            Some(&json!({"height": 9})),
            err.to_string().as_bytes(),
            &chain,
        )
        .unwrap();
        assert_eq!(v, Verified::none());
        let v = verify_jsonrpc("get_version", None, b"{}", &chain).unwrap();
        assert_eq!(v, Verified::none());
        // Not a JSON-RPC response at all is a fault.
        assert!(
            verify_jsonrpc("get_block", Some(&json!({"height": 1})), b"<html>", &chain).is_err()
        );
    }

    fn header_body(fx: &str) -> String {
        let v: Value = serde_json::from_str(fx).unwrap();
        json!({"jsonrpc":"2.0","id":0,"result":{"block_header": v["result"]["block_header"], "status":"OK","untrusted":true}}).to_string()
    }

    #[test]
    fn headers_by_height_and_hash() {
        let chain = chain_0_1();
        let b1 = header_body(BLOCK1);
        let v = verify_jsonrpc(
            "get_block_header_by_height",
            Some(&json!({"height": 1})),
            b1.as_bytes(),
            &chain,
        )
        .unwrap();
        assert_eq!(v, Verified::at(Verify::Chain, 1));
        let f = verify_jsonrpc(
            "get_block_header_by_height",
            Some(&json!({"height": 0})),
            b1.as_bytes(),
            &chain,
        )
        .unwrap_err();
        assert!(f.0.contains("height mismatch"), "{}", f.0);
        let h1 = fixture_hash(BLOCK1);
        let v = verify_jsonrpc(
            "get_block_header_by_hash",
            Some(&json!({"hash": h1})),
            b1.as_bytes(),
            &chain,
        )
        .unwrap();
        assert_eq!(v.verify, Verify::Chain);
        let f = verify_jsonrpc(
            "get_block_header_by_hash",
            Some(&json!({"hash": fixture_hash(BLOCK0)})),
            b1.as_bytes(),
            &chain,
        )
        .unwrap_err();
        assert!(f.0.contains("answered for hash"), "{}", f.0);
        // Beyond the chain: none, with the height for the caller.
        let bh = header_body(BLOCK_HIGH);
        let v = verify_jsonrpc(
            "get_block_header_by_hash",
            Some(&json!({"hash": fixture_hash(BLOCK_HIGH)})),
            bh.as_bytes(),
            &chain,
        )
        .unwrap();
        assert_eq!(v, Verified::at(Verify::None, 3_754_000));
        // An orphan at a height we hold: honest if declared, a fault if not.
        let mut o: Value = serde_json::from_str(&b1).unwrap();
        o["result"]["block_header"]["hash"] = json!("ab".repeat(32));
        o["result"]["block_header"]["orphan_status"] = json!(true);
        let v = verify_jsonrpc(
            "get_block_header_by_hash",
            Some(&json!({"hash": "ab".repeat(32)})),
            o.to_string().as_bytes(),
            &chain,
        )
        .unwrap();
        assert_eq!(v.verify, Verify::None);
        o["result"]["block_header"]["orphan_status"] = json!(false);
        assert!(verify_jsonrpc(
            "get_block_header_by_hash",
            Some(&json!({"hash": "ab".repeat(32)})),
            o.to_string().as_bytes(),
            &chain
        )
        .is_err());
    }

    #[test]
    fn headers_range_is_all_or_nothing() {
        let chain = chain_0_1();
        let h = |fx: &str| -> Value {
            let v: Value = serde_json::from_str(fx).unwrap();
            v["result"]["block_header"].clone()
        };
        let body = json!({"jsonrpc":"2.0","id":0,"result":{"headers":[h(BLOCK0), h(BLOCK1)],"status":"OK","untrusted":true}}).to_string();
        let p = json!({"start_height": 0, "end_height": 1});
        let v =
            verify_jsonrpc("get_block_headers_range", Some(&p), body.as_bytes(), &chain).unwrap();
        assert_eq!(v, Verified::at(Verify::Chain, 1));
        // A range partly beyond our chain is unverified as a whole.
        let mut far = h(BLOCK1);
        far["height"] = json!(2);
        far["prev_hash"] = h(BLOCK1)["hash"].clone();
        let body = json!({"jsonrpc":"2.0","id":0,"result":{"headers":[h(BLOCK0), h(BLOCK1), far],"status":"OK","untrusted":true}}).to_string();
        let p = json!({"start_height": 0, "end_height": 2});
        let v =
            verify_jsonrpc("get_block_headers_range", Some(&p), body.as_bytes(), &chain).unwrap();
        assert_eq!(v, Verified::at(Verify::None, 2));
        // Wrong count, and a header that does not link, are faults.
        let body = json!({"jsonrpc":"2.0","id":0,"result":{"headers":[h(BLOCK0)],"status":"OK","untrusted":true}}).to_string();
        assert!(
            verify_jsonrpc("get_block_headers_range", Some(&p), body.as_bytes(), &chain).is_err()
        );
        let body = json!({"jsonrpc":"2.0","id":0,"result":{"headers":[h(BLOCK1), h(BLOCK0)],"status":"OK","untrusted":true}}).to_string();
        let p = json!({"start_height": 0, "end_height": 1});
        assert!(
            verify_jsonrpc("get_block_headers_range", Some(&p), body.as_bytes(), &chain).is_err()
        );
    }

    #[test]
    fn on_get_block_hash_matches_the_chain() {
        let chain = chain_0_1();
        let ok = json!({"jsonrpc":"2.0","id":0,"result": fixture_hash(BLOCK1)}).to_string();
        let v = verify_jsonrpc(
            "on_get_block_hash",
            Some(&json!([1])),
            ok.as_bytes(),
            &chain,
        )
        .unwrap();
        assert_eq!(v, Verified::at(Verify::Chain, 1));
        let f = verify_jsonrpc(
            "on_get_block_hash",
            Some(&json!([0])),
            ok.as_bytes(),
            &chain,
        )
        .unwrap_err();
        assert!(f.0.contains("hash mismatch"), "{}", f.0);
        let v = verify_jsonrpc(
            "on_get_block_hash",
            Some(&json!([500])),
            ok.as_bytes(),
            &chain,
        )
        .unwrap();
        assert_eq!(v, Verified::at(Verify::None, 500));
    }

    #[test]
    fn transactions_verify_per_entry_full_and_pruned() {
        for fx in [TXS_FULL, TXS_PRUNED] {
            let r: GetTransactionsResult = serde_json::from_str(fx).unwrap();
            let requested: Vec<String> = r.txs.iter().map(|t| t.tx_hash.clone()).collect();
            let checks = verify_transactions(&requested, &r, Some(3_754_000)).unwrap();
            assert_eq!(checks.len(), r.txs.len());
            assert!(checks.iter().all(|c| matches!(
                c,
                TxCheck::Verified {
                    height: Some(3_754_000)
                }
            )));
            assert_eq!(batch_label(&checks), (Verify::Hash, None));
            // Within the slack the quorum lag allows: honest.
            for lag in 1..=TIP_SLACK {
                assert!(
                    verify_transactions(&requested, &r, Some(3_754_000 - lag)).is_ok(),
                    "tip {lag} behind"
                );
            }
            // Beyond it: a lie.
            assert!(verify_transactions(&requested, &r, Some(3_754_000 - TIP_SLACK - 1)).is_err());
            // Not what was asked for.
            let other = vec!["00".repeat(32)];
            assert!(verify_transactions(&other, &r, Some(3_754_000)).is_err());
        }
    }

    /// A coinbase as monerod serves it: `as_hex` empty, `pruned_as_hex`
    /// set, and `prunable_hash` equal to Keccak("") although the real hash
    /// uses zeros there. Found in the beta: every node was faulted for it.
    #[test]
    fn coinbase_in_pruned_form_verifies() {
        let r: GetTransactionsResult = serde_json::from_str(TXS_COINBASE).unwrap();
        assert!(r.txs[0].as_hex.is_empty());
        assert_eq!(
            r.txs[0].prunable_hash.as_deref(),
            Some("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        );
        let requested = vec![r.txs[0].tx_hash.clone()];
        let checks = verify_transactions(&requested, &r, Some(3_756_163)).unwrap();
        assert_eq!(
            checks,
            vec![TxCheck::Verified {
                height: Some(3_756_163)
            }]
        );
        // Still a lie if the pruned blob itself is wrong.
        let mut bad = r.clone();
        let mut hex_blob = bad.txs[0].pruned_as_hex.clone().unwrap();
        let last = hex_blob.len() - 1;
        hex_blob.replace_range(last.., if &hex_blob[last..] == "0" { "1" } else { "0" });
        bad.txs[0].pruned_as_hex = Some(hex_blob);
        assert!(verify_transactions(&requested, &bad, Some(3_756_163)).is_err());
    }

    #[test]
    fn tampered_tx_is_a_fault_and_pruned_v1_is_partial() {
        let mut r: GetTransactionsResult = serde_json::from_str(TXS_FULL).unwrap();
        let requested: Vec<String> = r.txs.iter().map(|t| t.tx_hash.clone()).collect();
        // A flipped byte in the prefix does not parse; one in the signature
        // parses and hashes to something else. Both are faults.
        // (The parallel array is tampered the same way, or the cross-check
        // fires first.)
        let mut hex_blob = r.txs[0].as_hex.clone();
        hex_blob.replace_range(20..21, if &hex_blob[20..21] == "0" { "1" } else { "0" });
        r.txs[0].as_hex = hex_blob.clone();
        r.txs_as_hex[0] = hex_blob;
        let f = verify_transactions(&requested, &r, Some(3_754_000)).unwrap_err();
        assert!(f.0.contains("malformed"), "{}", f.0);
        let mut hex_blob = r.txs[1].as_hex.clone();
        let last = hex_blob.len() - 1;
        hex_blob.replace_range(last.., if &hex_blob[last..] == "0" { "1" } else { "0" });
        r.txs[1].as_hex = hex_blob.clone();
        r.txs_as_hex[1] = hex_blob;
        let pristine = serde_json::from_str::<GetTransactionsResult>(TXS_FULL).unwrap();
        r.txs[0] = pristine.txs[0].clone();
        r.txs_as_hex[0] = pristine.txs_as_hex[0].clone();
        let f = verify_transactions(&requested, &r, Some(3_754_000)).unwrap_err();
        assert!(f.0.contains("hash mismatch"), "{}", f.0);

        // The parallel array carries other bytes than the hashed entry.
        let mut r: GetTransactionsResult = serde_json::from_str(TXS_FULL).unwrap();
        let mut other = r.txs[0].as_hex.clone();
        other.push_str("00");
        r.txs_as_hex[0] = other;
        let f = verify_transactions(&requested, &r, Some(3_754_000)).unwrap_err();
        assert!(f.0.contains("txs_as_hex"), "{}", f.0);
        let mut r: GetTransactionsResult = serde_json::from_str(TXS_FULL).unwrap();
        r.txs_as_hex.pop();
        assert!(verify_transactions(&requested, &r, Some(3_754_000)).is_err());
        let mut r: GetTransactionsResult = serde_json::from_str(TXS_FULL).unwrap();
        r.txs_as_json = Some(vec![String::from("{}"); r.txs.len()]);
        r.txs[0].as_json = String::from("{\"x\":1}");
        let f = verify_transactions(&requested, &r, Some(3_754_000)).unwrap_err();
        assert!(f.0.contains("txs_as_json"), "{}", f.0);

        let r: GetTransactionsResult = serde_json::from_str(TXS_V1_PRUNED).unwrap();
        let requested: Vec<String> = r.txs.iter().map(|t| t.tx_hash.clone()).collect();
        let checks = verify_transactions(&requested, &r, Some(3_754_000)).unwrap();
        assert!(checks.iter().all(|c| *c == TxCheck::Unverifiable));
        assert_eq!(batch_label(&checks), (Verify::None, None));
        let mixed = [TxCheck::Verified { height: Some(1) }, TxCheck::Unverifiable];
        assert_eq!(batch_label(&mixed), (Verify::Partial, Some((1, 2))));
        assert_eq!(batch_label(&[]), (Verify::None, None));
    }
}
