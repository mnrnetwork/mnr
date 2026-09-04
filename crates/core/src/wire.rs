//! `wire` — JSON-RPC envelope and typed daemon responses for mnr — an RPC
//! network for Monero.
//!
//! The relay forwards monerod's JSON-RPC and legacy responses to clients and
//! verifies what it can. Two rules keep that honest:
//!
//! - **Nothing is dropped.** Every result type carries a `#[serde(flatten)]
//!   extra: BTreeMap<String, Value>` so fields this version of `mnr-core` does
//!   not know about (newer or node-specific fields) round-trip unchanged. The
//!   round-trip tests prove it.
//! - **Newer fields parse everywhere.** Fields monerod added after 0.15 are
//!   `#[serde(default)]`, so a response from an older node still parses.
//!
//! The JSON-RPC error codes mirror `docs/stage1-gateway-development-plan.md`
//! §3.1–3.2: the relay's own `-32001` (subscription expired) and `-32005`
//! (rate limited) alongside the standard `-32700`/`-32600`/`-32601`.
//!
//! Pure data types over serde; no I/O, no `hex` crate (that stays a dev
//! dependency) — hex decoding is [`decode_hex`] / [`decode_hex32`], written
//! with plain `std` so it can be fuzzed alongside everything else.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::verify::{ReportedHeader, TipReport};

/// Standard JSON-RPC: invalid JSON was received.
pub const PARSE_ERROR: i64 = -32700;
/// Standard JSON-RPC: the request object was malformed.
pub const INVALID_REQUEST: i64 = -32600;
/// Standard JSON-RPC: no such method. Used for the wallet-RPC (`NotDaemon`)
/// methods the daemon does not implement (see `crate::policy`).
pub const METHOD_NOT_FOUND: i64 = -32601;
/// mnr-specific: the tenant's subscription has expired (gateway plan §3.1).
pub const MNR_SUBSCRIPTION_EXPIRED: i64 = -32001;
/// mnr-specific: the request exceeded the burst or daily-quota limit
/// (gateway plan §3.2).
pub const MNR_RATE_LIMITED: i64 = -32005;

/// Why a hex string (or a `get_info` tip) could not be interpreted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// The string is not valid hex, or not the expected number of bytes.
    BadHex(String),
    /// `get_info` reported height 0, so there is no tip block to report.
    NoTip,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadHex(s) => write!(f, "not valid {}-byte hex: {s}", s.len() / 2),
            Self::NoTip => f.write_str("get_info reports height 0: no tip block"),
        }
    }
}

impl std::error::Error for WireError {}

/// Decode a hex string into bytes (plain `std`, no `hex` crate). An odd length
/// or a non-hex character is a [`WireError::BadHex`].
pub fn decode_hex(s: &str) -> Result<Vec<u8>, WireError> {
    if s.len() % 2 != 0 {
        return Err(WireError::BadHex(s.to_owned()));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.as_bytes().chunks_exact(2) {
        let hi = hex_nibble(pair[0]).ok_or_else(|| WireError::BadHex(s.to_owned()))?;
        let lo = hex_nibble(pair[1]).ok_or_else(|| WireError::BadHex(s.to_owned()))?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

/// Decode a 32-byte hex hash (block hash, txid, prev hash). Anything that is
/// not exactly 64 hex characters is a [`WireError::BadHex`].
pub fn decode_hex32(s: &str) -> Result<[u8; 32], WireError> {
    let bytes = decode_hex(s)?;
    bytes
        .try_into()
        .map_err(|_| WireError::BadHex(s.to_owned()))
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// A JSON-RPC 2.0 request as monerod receives it (and as the relay receives it
/// from clients before dispatch).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Value,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

/// The `error` object of a JSON-RPC response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// A JSON-RPC 2.0 response. Exactly one of `result` / `error` is present in a
/// well-formed response; `skip_serializing_if` keeps the other key out of the
/// JSON so responses round-trip losslessly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcResponse<T> {
    pub jsonrpc: String,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl<T> JsonRpcResponse<T> {
    /// Build an error response (used by the relay for its own rejections).
    #[must_use]
    pub fn error(id: Value, code: i64, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_owned(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }

    /// Build a `-32601 method not found` response. Used for the wallet-RPC
    /// methods in `crate::policy` that are not daemon methods; `hint` is
    /// carried in `error.data` as `{"hint": ...}`.
    #[must_use]
    pub fn method_not_found(id: Value, method: &str, hint: Option<&str>) -> Self {
        Self {
            jsonrpc: "2.0".to_owned(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code: METHOD_NOT_FOUND,
                message: format!("method not found: {method}"),
                data: hint.map(|h| serde_json::json!({ "hint": h })),
            }),
        }
    }
}

/// The `block_header` object shared by `get_block`, `get_block_header_*`,
/// `get_last_block_header` and `get_block_headers_range`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    pub block_size: u64,
    pub block_weight: u64,
    pub cumulative_difficulty: u64,
    #[serde(default)]
    pub cumulative_difficulty_top64: u64,
    pub depth: u64,
    pub difficulty: u64,
    #[serde(default)]
    pub difficulty_top64: u64,
    pub hash: String,
    pub height: u64,
    #[serde(default)]
    pub long_term_weight: u64,
    pub major_version: u8,
    pub miner_tx_hash: String,
    pub minor_version: u8,
    pub nonce: u32,
    pub num_txes: u64,
    #[serde(default)]
    pub orphan_status: bool,
    #[serde(default)]
    pub pow_hash: String,
    pub prev_hash: String,
    pub reward: u64,
    pub timestamp: u64,
    #[serde(default)]
    pub wide_cumulative_difficulty: String,
    #[serde(default)]
    pub wide_difficulty: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// `get_block` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetBlockResult {
    pub blob: String,
    pub block_header: BlockHeader,
    pub json: String,
    pub miner_tx_hash: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tx_hashes: Vec<String>,
    pub status: String,
    pub untrusted: bool,
    #[serde(default)]
    pub credits: u64,
    #[serde(default)]
    pub top_hash: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// `get_block_header_by_hash` / `get_block_header_by_height` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetBlockHeaderResult {
    pub block_header: BlockHeader,
    pub status: String,
    pub untrusted: bool,
    #[serde(default)]
    pub credits: u64,
    #[serde(default)]
    pub top_hash: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// `get_last_block_header` returns exactly the same shape as a single header.
pub type GetLastBlockHeaderResult = GetBlockHeaderResult;

/// `get_block_headers_range` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetBlockHeadersRangeResult {
    pub headers: Vec<BlockHeader>,
    pub status: String,
    pub untrusted: bool,
    #[serde(default)]
    pub credits: u64,
    #[serde(default)]
    pub top_hash: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// One transaction as returned by `/get_transactions`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxEntry {
    pub as_hex: String,
    pub as_json: String,
    pub block_height: u64,
    #[serde(default)]
    pub block_timestamp: u64,
    #[serde(default)]
    pub confirmations: u64,
    #[serde(default)]
    pub double_spend_seen: bool,
    pub in_pool: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub output_indices: Vec<u64>,
    #[serde(default)]
    pub prunable_as_hex: String,
    #[serde(default)]
    pub prunable_hash: String,
    #[serde(default)]
    pub pruned_as_hex: String,
    pub tx_hash: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// `/get_transactions` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetTransactionsResult {
    pub txs: Vec<TxEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missed_tx: Vec<String>,
    pub txs_as_hex: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub txs_as_json: Vec<String>,
    pub status: String,
    pub untrusted: bool,
    #[serde(default)]
    pub credits: u64,
    #[serde(default)]
    pub top_hash: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// `get_info` result, with every field monerod 0.18 returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetInfoResult {
    #[serde(default)]
    pub adjusted_time: u64,
    pub alt_blocks_count: u64,
    pub block_size_limit: u64,
    pub block_size_median: u64,
    pub block_weight_limit: u64,
    pub block_weight_median: u64,
    #[serde(default)]
    pub bootstrap_daemon_address: String,
    #[serde(default)]
    pub busy_syncing: bool,
    #[serde(default)]
    pub credits: u64,
    pub cumulative_difficulty: u64,
    #[serde(default)]
    pub cumulative_difficulty_top64: u64,
    pub database_size: u64,
    pub difficulty: u64,
    #[serde(default)]
    pub difficulty_top64: u64,
    pub free_space: u64,
    pub grey_peerlist_size: u64,
    pub height: u64,
    #[serde(default)]
    pub height_without_bootstrap: u64,
    pub incoming_connections_count: u64,
    pub mainnet: bool,
    pub nettype: String,
    pub offline: bool,
    pub outgoing_connections_count: u64,
    pub restricted: bool,
    #[serde(default)]
    pub rpc_connections_count: u64,
    pub stagenet: bool,
    pub start_time: u64,
    pub status: String,
    pub synchronized: bool,
    pub target: u64,
    pub target_height: u64,
    pub testnet: bool,
    pub top_block_hash: String,
    #[serde(default)]
    pub top_hash: String,
    pub tx_count: u64,
    pub tx_pool_size: u64,
    pub untrusted: bool,
    pub update_available: bool,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub was_bootstrap_ever_used: bool,
    pub white_peerlist_size: u64,
    #[serde(default)]
    pub wide_cumulative_difficulty: String,
    #[serde(default)]
    pub wide_difficulty: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// The node-specific `get_info` fields that are meaningless across a pool of
/// upstreams; [`GetInfoResult::normalise_get_info`] zeroes them.
pub const NODE_SPECIFIC_FIELDS: &[&str] = &[
    "incoming_connections_count",
    "outgoing_connections_count",
    "rpc_connections_count",
    "white_peerlist_size",
    "grey_peerlist_size",
    "update_available",
    "start_time",
];

impl GetInfoResult {
    /// One upstream's view of the tip, for the quorum check (`verify::quorum_tip`).
    ///
    /// monerod's `get_info.height` is the **number of blocks**: the tip height
    /// plus one, and `top_block_hash` is the hash of the block at
    /// `height - 1`. The reported tip is therefore `(height - 1, top_block_hash)`.
    /// A height of zero, meaning a chain that has not produced genesis, has no
    /// tip.
    pub fn tip_report(&self, upstream: usize) -> Result<TipReport, WireError> {
        let height = self.height.checked_sub(1).ok_or(WireError::NoTip)?;
        Ok(TipReport {
            upstream,
            height,
            hash: decode_hex32(&self.top_block_hash)?,
        })
    }

    /// Replace node-specific fields with neutral values so a response can be
    /// served as if it came from the network as a whole. The relay may
    /// overwrite the zeroed values with network-wide ones before forwarding;
    /// `extra` is cleared of the same names so no stale copy survives a
    /// future re-parse.
    pub fn normalise_get_info(&mut self) {
        self.incoming_connections_count = 0;
        self.outgoing_connections_count = 0;
        self.rpc_connections_count = 0;
        self.white_peerlist_size = 0;
        self.grey_peerlist_size = 0;
        self.update_available = false;
        self.start_time = 0;
        for name in NODE_SPECIFIC_FIELDS {
            self.extra.remove(*name);
        }
    }
}

/// Legacy `/get_height` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetHeightResult {
    pub height: u64,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub untrusted: bool,
    #[serde(default)]
    pub credits: u64,
    #[serde(default)]
    pub top_hash: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// `get_fee_estimate` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetFeeEstimateResult {
    pub fee: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fees: Vec<u64>,
    #[serde(default)]
    pub quantization_mask: u64,
    pub status: String,
    pub untrusted: bool,
    #[serde(default)]
    pub credits: u64,
    #[serde(default)]
    pub top_hash: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Bridge to the verification code: a daemon `block_header` object becomes the
/// [`ReportedHeader`] the header-chain verifier compares against. `hash` and
/// `prev_hash` are hex and must decode.
impl TryFrom<&BlockHeader> for ReportedHeader {
    type Error = WireError;

    fn try_from(h: &BlockHeader) -> Result<Self, Self::Error> {
        Ok(Self {
            height: h.height,
            hash: decode_hex32(&h.hash)?,
            prev_hash: decode_hex32(&h.prev_hash)?,
            timestamp: h.timestamp,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::de::DeserializeOwned;
    use serde::Serialize;

    macro_rules! fixture {
        ($name:literal) => {
            include_str!(concat!("../fixtures/mainnet/", $name))
        };
    }

    const GET_INFO: &str = fixture!("get_info.json");
    const GET_LAST_BLOCK_HEADER: &str = fixture!("get_last_block_header.json");
    const GET_FEE_ESTIMATE: &str = fixture!("get_fee_estimate.json");

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

    fn round_trip<T>(raw: &str)
    where
        T: Serialize + DeserializeOwned + PartialEq + fmt::Debug,
    {
        let v1: Value = serde_json::from_str(raw).unwrap();
        let parsed: T = serde_json::from_str(raw).unwrap();
        let v2: Value = serde_json::from_str(&serde_json::to_string(&parsed).unwrap()).unwrap();
        assert_eq!(v1, v2, "lossy round-trip");
    }

    #[test]
    fn every_block_fixture_parses_as_get_block_result() {
        for (h, raw) in BLOCKS {
            let resp: JsonRpcResponse<GetBlockResult> =
                serde_json::from_str(raw).unwrap_or_else(|e| panic!("block {h}: {e}"));
            let r = resp
                .result
                .unwrap_or_else(|| panic!("block {h} has no result"));
            assert_eq!(r.status, "OK", "block {h} status");
            assert_eq!(r.block_header.height, *h, "block {h} header height");
        }
    }

    #[test]
    fn every_txs_fixture_parses_with_matching_counts() {
        for (h, full, pruned) in TXS {
            for raw in [full, pruned] {
                let r: GetTransactionsResult =
                    serde_json::from_str(raw).unwrap_or_else(|e| panic!("txs @{h}: {e}"));
                assert!(!r.txs.is_empty(), "txs @{h}");
                assert_eq!(r.txs.len(), r.txs_as_hex.len(), "txs @{h} count");
                assert_eq!(r.status, "OK", "txs @{h} status");
            }
        }
    }

    #[test]
    fn every_fixture_round_trips_losslessly() {
        for (_, raw) in BLOCKS {
            round_trip::<JsonRpcResponse<GetBlockResult>>(raw);
        }
        for (_, full, pruned) in TXS {
            round_trip::<GetTransactionsResult>(full);
            round_trip::<GetTransactionsResult>(pruned);
        }
        round_trip::<JsonRpcResponse<GetInfoResult>>(GET_INFO);
        round_trip::<JsonRpcResponse<GetLastBlockHeaderResult>>(GET_LAST_BLOCK_HEADER);
        round_trip::<JsonRpcResponse<GetFeeEstimateResult>>(GET_FEE_ESTIMATE);
    }

    #[test]
    fn unknown_fields_round_trip_through_extra() {
        let mut v: Value = serde_json::from_str(BLOCKS[1].1).unwrap();
        v["result"]["block_header"]["future_field"] = serde_json::json!({ "x": 1 });
        let s = v.to_string();

        let parsed: JsonRpcResponse<GetBlockResult> = serde_json::from_str(&s).unwrap();
        assert!(parsed
            .result
            .as_ref()
            .unwrap()
            .block_header
            .extra
            .contains_key("future_field"));

        let v2: Value = serde_json::from_str(&serde_json::to_string(&parsed).unwrap()).unwrap();
        assert_eq!(v, v2, "unknown field must survive the round-trip");
    }

    #[test]
    fn block_header_converts_to_reported_header() {
        let resp: JsonRpcResponse<GetBlockResult> = serde_json::from_str(BLOCKS[1].1).unwrap();
        let hdr = resp.result.unwrap().block_header;
        let rep = ReportedHeader::try_from(&hdr).unwrap();
        assert_eq!(rep.height, 1);
        assert_eq!(
            rep.hash,
            decode_hex32("771fbcd656ec1464d3a02ead5e18644030007a0fc664c0a964d30922821a8148")
                .unwrap()
        );
        assert_eq!(
            rep.prev_hash,
            decode_hex32("418015bb9ae982a1975da7d79277c2705727a56894ba0fb246adaabb1f4632e3")
                .unwrap()
        );
        assert_eq!(rep.timestamp, 1_397_818_193);

        let mut bad = hdr.clone();
        bad.hash = "zz".to_owned();
        assert!(matches!(
            ReportedHeader::try_from(&bad),
            Err(WireError::BadHex(_))
        ));
    }

    #[test]
    fn get_info_tip_report_uses_height_minus_one() {
        let resp: JsonRpcResponse<GetInfoResult> = serde_json::from_str(GET_INFO).unwrap();
        let info = resp.result.unwrap();
        let report = info.tip_report(3).unwrap();
        assert_eq!(report.upstream, 3);
        // height is block count; the tip is the block at height - 1.
        assert_eq!(report.height, info.height - 1);
        assert_eq!(report.hash, decode_hex32(&info.top_block_hash).unwrap());

        let mut zero = info;
        zero.height = 0;
        assert!(matches!(zero.tip_report(0), Err(WireError::NoTip)));
    }

    #[test]
    fn normalise_get_info_zeroes_node_specific_fields() {
        let resp: JsonRpcResponse<GetInfoResult> = serde_json::from_str(GET_INFO).unwrap();
        let mut info = resp.result.unwrap();
        info.incoming_connections_count = 7;
        info.start_time = 12_345;
        info.update_available = true;
        info.normalise_get_info();

        assert_eq!(info.incoming_connections_count, 0);
        assert_eq!(info.outgoing_connections_count, 0);
        assert_eq!(info.rpc_connections_count, 0);
        assert_eq!(info.white_peerlist_size, 0);
        assert_eq!(info.grey_peerlist_size, 0);
        assert_eq!(info.start_time, 0);
        assert!(!info.update_available);
        for name in NODE_SPECIFIC_FIELDS {
            assert!(!info.extra.contains_key(*name));
        }
    }

    #[test]
    fn method_not_found_carries_the_hint_in_data() {
        let resp = JsonRpcResponse::<GetInfoResult>::method_not_found(
            Value::from("7"),
            "check_tx_key",
            Some("wallet-rpc, not a daemon method"),
        );
        assert_eq!(resp.result, None);
        let v: Value = serde_json::from_str(&serde_json::to_string(&resp).unwrap()).unwrap();
        assert_eq!(v["error"]["code"], METHOD_NOT_FOUND);
        assert_eq!(
            v["error"]["data"]["hint"],
            "wallet-rpc, not a daemon method"
        );

        let e = resp.error.expect("error present");
        assert_eq!(e.code, METHOD_NOT_FOUND);
        assert_eq!(e.message, "method not found: check_tx_key");
        assert_eq!(e.data.unwrap()["hint"], "wallet-rpc, not a daemon method");

        let no_hint =
            JsonRpcResponse::<GetInfoResult>::method_not_found(Value::from("8"), "x", None);
        assert_eq!(no_hint.error.unwrap().data, None);
    }

    #[test]
    fn error_constructor_sets_code_and_message() {
        let resp = JsonRpcResponse::<Value>::error(Value::from(1), PARSE_ERROR, "parse error");
        assert_eq!(resp.id, 1);
        assert_eq!(resp.result, None);
        assert_eq!(resp.jsonrpc, "2.0");
        let e = resp.error.unwrap();
        assert_eq!(e.code, PARSE_ERROR);
        assert_eq!(e.message, "parse error");
        assert_eq!(e.data, None);
    }

    #[test]
    fn hex_helpers_reject_bad_input() {
        assert_eq!(decode_hex("00ff").unwrap(), vec![0x00, 0xff]);
        assert_eq!(decode_hex("").unwrap(), Vec::<u8>::new());
        assert!(matches!(decode_hex("0"), Err(WireError::BadHex(_))));
        assert!(matches!(decode_hex("gg"), Err(WireError::BadHex(_))));
        assert!(matches!(decode_hex32("00ff"), Err(WireError::BadHex(_))));
        assert_eq!(decode_hex32(&"ab".repeat(32)).unwrap().len(), 32);
    }
}
