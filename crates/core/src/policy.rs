//! `policy` — the mnr method policy table (the allow-list).
//!
//! This module is the single source of truth for how the relay dispatches daemon
//! RPC methods: the method class, the cache rule, the quorum rule, the
//! per-upstream timeout and the verification requirement. It started from the
//! prose table in `docs/stage1-gateway-development-plan.md` §3.3 but the code is
//! now canonical and is **verified against monerod's real endpoint registry**,
//! kept as a fixture at `crates/core/fixtures/monerod-core_rpc_server.h`; the
//! tests in this module keep the two in sync so any endpoint monerod adds fails
//! CI until it is classified here.
//!
//! Stage 0 overrides (from `docs/stage0-mvp-plan.md` §4–5):
//! - Response headers are `Mnr-*`, not the gateway plan's `X-Gateway-*`
//!   (`Mnr-Relayed: k/n`, `Mnr-Verify: none`, `Mnr-Upstream: <n>`).
//! - `/get_outs.bin` uses **two-upstream agreement for Pro tokens** and a single
//!   upstream (the owned node preferred) for Free. This is modelled here as a
//!   per-tier [`Verification`] rule ([`Verification::Agreement`]). Decided
//!   2026-09-04 (`stage0-mvp-plan.md` §10 item 3): Free stays single-upstream.
//!
//! This is an **allow-list**: a method not in [`TABLE`] is denied. [`lookup`]
//! returns `None` for it and [`lookup_or_deny`] returns the deny fallback.
//! Denied methods also carry a [`Class::Deny`] row so the rendered table is
//! self-documenting, but the deny-by-default property holds even for methods
//! that are not listed at all.
//!
//! Pure data, no I/O, std only — the rest of `mnr-core` keeps its fuzzability.

/// Distance from the quorum tip inside which data is never cached.
///
/// Blocks/headers/txs within this depth of the tip may be reorged away, so they
/// are served live and only data at height ≤ `quorum_tip − TIP_SAFETY_DEPTH`
/// is treated as immutable and cached (invariant 2 of the plan).
pub const TIP_SAFETY_DEPTH: u64 = 10;

/// How the relay classifies a method (drives dispatch, caching, verification).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// Self-authenticating, immutable data (blocks, headers); cacheable below
    /// the tip safety line, requests above it fall back to SWR.
    Immutable,
    /// Immutable only when below the tip safety line (txs, outputs); young or
    /// mempool data passes through uncached.
    ImmutableConditional,
    /// Consensus state, served with stale-while-revalidate.
    Swr,
    /// Epee binary stream (`get_blocks.bin` family); no cache, streamed through.
    PassthroughStream,
    /// No cache, forwarded to one upstream (mempool, spent status).
    Passthrough,
    /// Writes fanned out to every healthy upstream; success if any accepts.
    Broadcast,
    /// A wallet-RPC method, not a daemon method; rejected with `-32601` + hint.
    NotDaemon,
    /// Denied at the edge (403 / `-32601`).
    Deny,
}

impl Class {
    /// §3.3-style display label for the rendered table.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Immutable => "IMMUTABLE",
            Self::ImmutableConditional => "IMMUTABLE-CONDITIONAL",
            Self::Swr => "SWR",
            Self::PassthroughStream => "PASSTHROUGH-STREAM",
            Self::Passthrough => "PASSTHROUGH",
            Self::Broadcast => "BROADCAST",
            Self::NotDaemon => "NOT-DAEMON",
            Self::Deny => "DENY",
        }
    }
}

/// Which wire form the client uses to reach the method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// JSON-RPC 2.0 method name (e.g. `get_block`).
    JsonRpc,
    /// Legacy HTTP path (epee binary or JSON POST, e.g. `/get_transactions`).
    LegacyPath,
}

impl Transport {
    /// Short label for the rendered table.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::JsonRpc => "json-rpc",
            Self::LegacyPath => "legacy",
        }
    }
}

/// Verification required before an answer is trusted, possibly per client tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verification {
    /// Self-authenticating data: block/tx/header hashes recomputed and matched.
    Authenticated,
    /// Consensus state: majority of ≥3 upstreams must agree.
    Majority,
    /// A fixed number of upstreams must agree, per client tier.
    Agreement { free: u32, pro: u32 },
    /// Not verifiable; response annotated (`Mnr-Verify` / `Mnr-Upstream`),
    /// never silently trusted.
    Annotated,
    /// Wallet-RPC method; reject with `-32601`.
    NotDaemon,
    /// Not dispatched at all (denied).
    NotApplicable,
}

/// The full per-method policy for one entry of the allow-list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// Method name as seen by the client: JSON-RPC name or legacy path.
    pub method: &'static str,
    /// Wire form: JSON-RPC or legacy HTTP path.
    pub transport: Transport,
    /// Dispatch/caching/verification class.
    pub class: Class,
    /// Cache rule, referencing `TIP_SAFETY_DEPTH` where the tip−10 rule applies.
    pub cache: &'static str,
    /// Quorum rule: which upstreams may serve and how many must agree.
    pub quorum: &'static str,
    /// Verification required before trusting the answer.
    pub verification: Verification,
    /// Per-upstream timeout in milliseconds. `0` = never dispatched.
    pub timeout_ms: u32,
    /// Short note; Stage 0 specifics and open decisions live here.
    pub note: &'static str,
}

/// Constructor so the static table stays readable.
#[allow(clippy::too_many_arguments)]
const fn policy(
    method: &'static str,
    transport: Transport,
    class: Class,
    cache: &'static str,
    quorum: &'static str,
    verification: Verification,
    timeout_ms: u32,
    note: &'static str,
) -> Policy {
    Policy {
        method,
        transport,
        class,
        cache,
        quorum,
        verification,
        timeout_ms,
        note,
    }
}

// ── shared rule strings ──────────────────────────────────────────────────────

const IMMUTABLE_CACHE: &str = "Cache 30 d only if requested height <= quorum_tip - TIP_SAFETY_DEPTH; requests above the safety line fall back to SWR. Cache key includes the block hash returned by the node.";
const IMMUTABLE_QUORUM: &str =
    "Height/hash must match the quorum-tip chain (validated against the header chain).";
const SWR_CACHE: &str = "SWR 1/5/15 s (max-age=1, stale-while-revalidate=5, stale-if-error=15) with single-flight coalescing; node-specific fields normalised. Staleness bound <=6 s normal, <=15 s during upstream error.";
const SWR_QUORUM: &str =
    "Majority of >=3 upstreams on quorum tip (each probe height >= quorum_tip - 1).";
const TXS_CACHE: &str = "Cache 30 d per tx hash only for txs with block_height <= quorum_tip - TIP_SAFETY_DEPTH; mempool/young txs pass through. Per-tx-hash, not per request body; batches reassembled at the edge.";
const OUTPUTS_CACHE: &str = "Cache 24 h only if all requested indices belong to blocks <= quorum_tip - TIP_SAFETY_DEPTH; else pass through.";
const STREAM_CACHE: &str = "None - streamed body-through, no buffering.";
const STREAM_QUORUM: &str =
    "Route to the healthiest full node on quorum tip (pruned node only if request has prune=true).";
const POOL_CACHE: &str = "None (mempool is per-node by nature).";
const POOL_QUORUM: &str = "Single node; response annotated Mnr-Upstream (opaque id).";
const SPENT_CACHE: &str = "None (spent status changes with the mempool).";
const NO_CACHE: &str = "None.";
const SINGLE_NODE_QUORUM: &str = "Single node on quorum tip.";
const BROADCAST_QUORUM: &str =
    "Fan out to all healthy upstreams in parallel; success if >=1 returns status OK.";
const NA: &str = "n/a";
const NOT_DAEMON_NOTE: &str =
    "Wallet-RPC method, not a daemon method; return -32601 method not found with a hint.";
const DENY_NOTE: &str =
    "Denied at the edge (403 / -32601); nodes also run --restricted-rpc as defence in depth.";
const MINING_NOTE: &str = "Mining/admin; denied at the edge (403 / -32601).";
const LOGGING_NOTE: &str = "Logging control; denied at the edge (403 / -32601).";

// ── family constructors (const) ──────────────────────────────────────────────

/// SWR consensus state: 1.5 s per-upstream timeout, majority quorum.
const fn swr(method: &'static str, transport: Transport, note: &'static str) -> Policy {
    policy(
        method,
        transport,
        Class::Swr,
        SWR_CACHE,
        SWR_QUORUM,
        Verification::Majority,
        1500,
        note,
    )
}

/// Immutable, hash-verified, JSON-RPC: 3 s per-upstream timeout.
const fn immutable(method: &'static str, note: &'static str) -> Policy {
    policy(
        method,
        Transport::JsonRpc,
        Class::Immutable,
        IMMUTABLE_CACHE,
        IMMUTABLE_QUORUM,
        Verification::Authenticated,
        3000,
        note,
    )
}

/// Transactions: 30 d per-tx-hash cache below the tip safety line, 5 s timeout.
const fn transactions_conditional(
    method: &'static str,
    transport: Transport,
    note: &'static str,
) -> Policy {
    policy(
        method,
        transport,
        Class::ImmutableConditional,
        TXS_CACHE,
        SINGLE_NODE_QUORUM,
        Verification::Authenticated,
        5000,
        note,
    )
}

/// Outputs family: 24 h cache below the tip safety line, per-tier agreement,
/// 10 s timeout.
const fn outputs_conditional(
    method: &'static str,
    transport: Transport,
    note: &'static str,
) -> Policy {
    policy(
        method,
        transport,
        Class::ImmutableConditional,
        OUTPUTS_CACHE,
        SINGLE_NODE_QUORUM,
        Verification::Agreement { free: 1, pro: 2 },
        10000,
        note,
    )
}

/// Epee binary stream: no cache, streamed body-through, 60 s timeout.
const fn stream(method: &'static str, note: &'static str) -> Policy {
    policy(
        method,
        Transport::LegacyPath,
        Class::PassthroughStream,
        STREAM_CACHE,
        STREAM_QUORUM,
        Verification::Annotated,
        60000,
        note,
    )
}

/// No cache, one upstream, 3 s timeout, annotated response.
const fn passthrough(
    method: &'static str,
    transport: Transport,
    cache: &'static str,
    quorum: &'static str,
    note: &'static str,
) -> Policy {
    policy(
        method,
        transport,
        Class::Passthrough,
        cache,
        quorum,
        Verification::Annotated,
        3000,
        note,
    )
}

/// Write fan-out: every healthy upstream in parallel, 5 s each.
const fn broadcast(method: &'static str, transport: Transport, note: &'static str) -> Policy {
    policy(
        method,
        transport,
        Class::Broadcast,
        NO_CACHE,
        BROADCAST_QUORUM,
        Verification::Annotated,
        5000,
        note,
    )
}

/// Denied at the edge; never dispatched.
const fn deny(method: &'static str, transport: Transport, note: &'static str) -> Policy {
    policy(
        method,
        transport,
        Class::Deny,
        NA,
        NA,
        Verification::NotApplicable,
        0,
        note,
    )
}

/// Wallet-RPC method: `-32601` + hint, never dispatched.
const fn not_daemon(method: &'static str) -> Policy {
    policy(
        method,
        Transport::JsonRpc,
        Class::NotDaemon,
        NA,
        NA,
        Verification::NotDaemon,
        0,
        NOT_DAEMON_NOTE,
    )
}

/// A monerod-registered alias of a canonical method: identical policy, with a
/// note naming the canonical form. The canonical argument must be built with the
/// same family constructor as its row in [`TABLE`].
const fn alias_of(method: &'static str, canonical: Policy, note: &'static str) -> Policy {
    Policy {
        method,
        note,
        ..canonical
    }
}

// ── canonical rows that also have monerod-registered aliases ─────────────────
// Named so the alias rows below can reference them instead of duplicating the
// policy. Everything else lives inline in TABLE.

const P_GET_BLOCK: Policy = immutable(
    "get_block",
    "Block hash recomputed from the blob and matched to the requested hash or height.",
);
const P_GET_BLOCK_HEADER_BY_HASH: Policy = immutable(
    "get_block_header_by_hash",
    "Recomputed header hash matched to the requested hash.",
);
const P_GET_BLOCK_HEADER_BY_HEIGHT: Policy = immutable(
    "get_block_header_by_height",
    "Header hash matched to the header chain at that height.",
);
const P_GET_BLOCK_HEADERS_RANGE: Policy = immutable(
    "get_block_headers_range",
    "Range requests are split at the safety line.",
);
const P_ON_GET_BLOCK_HASH: Policy = immutable(
    "on_get_block_hash",
    "Takes a height, returns the block hash; matched to the header chain.",
);
const P_GET_INFO: Policy = swr(
    "/get_info",
    Transport::LegacyPath,
    "Legacy form of get_info; same normalisation.",
);
const P_GET_HEIGHT: Policy = swr(
    "/get_height",
    Transport::LegacyPath,
    "Consensus state; majority of >=3 upstreams.",
);
const P_GET_LAST_BLOCK_HEADER: Policy = swr(
    "get_last_block_header",
    Transport::JsonRpc,
    "Header verified against the header chain.",
);
const P_GET_BLOCK_COUNT: Policy = swr(
    "get_block_count",
    Transport::JsonRpc,
    "Equivalent of get_height by block count; majority of >=3 upstreams.",
);
const P_GET_TRANSACTIONS: Policy = transactions_conditional(
    "/get_transactions",
    Transport::LegacyPath,
    "Tx blob hashed to txid; pruned-tx hash form verified where applicable.",
);
const P_GET_BLOCKS: Policy = stream("/get_blocks.bin", "Wallet sync path; largest bandwidth consumer, metered separately (bytes). Stage 0: not verified - Mnr-Verify: none; owned node preferred; idle timeout 15 s.");
const P_GET_BLOCKS_BY_HEIGHT: Policy = stream(
    "/get_blocks_by_height.bin",
    "Same as get_blocks.bin by height; Mnr-Verify: none in Stage 0; idle timeout 15 s.",
);
const P_GET_HASHES: Policy = stream(
    "/get_hashes.bin",
    "Block hashes for sync; Mnr-Verify: none in Stage 0; idle timeout 15 s.",
);
const P_SEND_RAW_TRANSACTION: Policy = broadcast("/send_raw_transaction", Transport::LegacyPath, "do_not_relay honoured; no retries (tx is idempotent on-chain); overall budget 6 s; result header Mnr-Relayed: k/n. If all reject, return the first error verbatim.");
const P_GET_BLOCK_TEMPLATE: Policy = deny("get_block_template", Transport::JsonRpc, MINING_NOTE);
const P_SUBMIT_BLOCK: Policy = deny("submit_block", Transport::JsonRpc, MINING_NOTE);

/// The method allow-list, one row per endpoint monerod registers (verified
/// against `crates/core/fixtures/monerod-core_rpc_server.h`) plus the
/// wallet-RPC methods that must return `-32601`. Order follows §3.3:
/// immutable, immutable-conditional, SWR, passthrough-stream, passthrough,
/// broadcast, not-daemon, deny.
static TABLE: &[Policy] = &[
    // ── IMMUTABLE (JSON-RPC; hash-verified, cacheable below the tip safety line) ──
    P_GET_BLOCK,
    P_GET_BLOCK_HEADER_BY_HEIGHT,
    P_GET_BLOCK_HEADER_BY_HASH,
    P_GET_BLOCK_HEADERS_RANGE,
    P_ON_GET_BLOCK_HASH,
    // ── IMMUTABLE aliases monerod registers (same policy) ──
    alias_of("getblock", P_GET_BLOCK, "Alias of get_block."),
    alias_of(
        "getblockheaderbyhash",
        P_GET_BLOCK_HEADER_BY_HASH,
        "Alias of get_block_header_by_hash.",
    ),
    alias_of(
        "getblockheaderbyheight",
        P_GET_BLOCK_HEADER_BY_HEIGHT,
        "Alias of get_block_header_by_height.",
    ),
    alias_of(
        "getblockheadersrange",
        P_GET_BLOCK_HEADERS_RANGE,
        "Alias of get_block_headers_range.",
    ),
    alias_of("on_getblockhash", P_ON_GET_BLOCK_HASH, "Alias of on_get_block_hash."),
    // ── SWR (consensus state; majority of >=3 upstreams) ──
    swr(
        "get_info",
        Transport::JsonRpc,
        "Consensus state; node-specific fields (connections, peerlist, update_available, start_time) normalised.",
    ),
    P_GET_INFO,
    P_GET_HEIGHT,
    P_GET_LAST_BLOCK_HEADER,
    swr("get_fee_estimate", Transport::JsonRpc, "Fee estimate = median of upstream estimates."),
    swr("hard_fork_info", Transport::JsonRpc, "Fork/version agreement across upstreams."),
    swr(
        "get_version",
        Transport::JsonRpc,
        "Node version; checked against the directory minimum in Stage 2.",
    ),
    P_GET_BLOCK_COUNT,
    // ── SWR aliases ──
    alias_of("/getheight", P_GET_HEIGHT, "Alias of /get_height."),
    alias_of("/getinfo", P_GET_INFO, "Alias of /get_info."),
    alias_of(
        "getlastblockheader",
        P_GET_LAST_BLOCK_HEADER,
        "Alias of get_last_block_header.",
    ),
    alias_of("getblockcount", P_GET_BLOCK_COUNT, "Alias of get_block_count."),
    // ── IMMUTABLE-CONDITIONAL (txs / outputs; cacheable only below the tip safety line) ──
    P_GET_TRANSACTIONS,
    outputs_conditional(
        "/get_outs.bin",
        Transport::LegacyPath,
        "Ring construction; correctness > hit rate. Stage 0: two-upstream agreement for Pro tokens, single upstream (owned node preferred) for Free (plan §10 item 3, decided).",
    ),
    outputs_conditional("/get_outs", Transport::LegacyPath, "JSON twin of /get_outs.bin; same per-tier agreement."),
    outputs_conditional(
        "/get_o_indexes.bin",
        Transport::LegacyPath,
        "Tx global output indexes; same per-tier agreement.",
    ),
    outputs_conditional(
        "/get_output_distribution.bin",
        Transport::LegacyPath,
        "Binary form of get_output_distribution.",
    ),
    outputs_conditional(
        "get_output_distribution",
        Transport::JsonRpc,
        "Ring-construction data; not self-authenticating from a single response.",
    ),
    outputs_conditional(
        "get_output_histogram",
        Transport::JsonRpc,
        "Ring-construction data; not self-authenticating from a single response.",
    ),
    // ── IMMUTABLE-CONDITIONAL aliases ──
    alias_of("/gettransactions", P_GET_TRANSACTIONS, "Alias of /get_transactions."),
    // ── PASSTHROUGH-STREAM (epee binary; no cache, streamed) ──
    P_GET_BLOCKS,
    P_GET_BLOCKS_BY_HEIGHT,
    P_GET_HASHES,
    // ── stream aliases ──
    alias_of("/getblocks.bin", P_GET_BLOCKS, "Alias of /get_blocks.bin."),
    alias_of(
        "/getblocks_by_height.bin",
        P_GET_BLOCKS_BY_HEIGHT,
        "Alias of /get_blocks_by_height.bin.",
    ),
    alias_of("/gethashes.bin", P_GET_HASHES, "Alias of /get_hashes.bin."),
    // ── PASSTHROUGH (no cache) ──
    passthrough(
        "/get_transaction_pool_hashes.bin",
        Transport::LegacyPath,
        POOL_CACHE,
        POOL_QUORUM,
        "Mempool is per-node by nature; never cached.",
    ),
    passthrough(
        "/get_transaction_pool_hashes",
        Transport::LegacyPath,
        POOL_CACHE,
        POOL_QUORUM,
        "Mempool is per-node by nature; never cached.",
    ),
    passthrough(
        "/get_transaction_pool_stats",
        Transport::LegacyPath,
        POOL_CACHE,
        POOL_QUORUM,
        "Mempool is per-node by nature; never cached.",
    ),
    passthrough(
        "/is_key_image_spent",
        Transport::LegacyPath,
        SPENT_CACHE,
        SINGLE_NODE_QUORUM,
        "Restricted-safe; used by wallets during sync.",
    ),
    passthrough(
        "/get_public_nodes",
        Transport::LegacyPath,
        NO_CACHE,
        SINGLE_NODE_QUORUM,
        "Public node list; we never forward client identity (no client IP, no X-Forwarded-For).",
    ),
    passthrough(
        "/get_limit",
        Transport::LegacyPath,
        NO_CACHE,
        SINGLE_NODE_QUORUM,
        "Daemon bandwidth limits; we never forward client identity.",
    ),
    passthrough(
        "get_txpool_backlog",
        Transport::JsonRpc,
        NO_CACHE,
        SINGLE_NODE_QUORUM,
        "Mempool backlog metrics; per-node by nature.",
    ),
    passthrough(
        "get_txids_loose",
        Transport::JsonRpc,
        NO_CACHE,
        SINGLE_NODE_QUORUM,
        "Mempool txids by prefix; per-node by nature.",
    ),
    // ── BROADCAST (writes fan out) ──
    P_SEND_RAW_TRANSACTION,
    // ── broadcast aliases ──
    alias_of("/sendrawtransaction", P_SEND_RAW_TRANSACTION, "Alias of /send_raw_transaction."),
    // ── NOT-DAEMON (wallet-RPC methods: -32601 + hint) ──
    not_daemon("check_tx_key"),
    not_daemon("check_tx_proof"),
    not_daemon("check_spend_proof"),
    not_daemon("check_reserve_proof"),
    // ── DENY (legacy admin/mining/peer paths) ──
    deny("/get_alt_blocks_hashes", Transport::LegacyPath, DENY_NOTE),
    deny("/start_mining", Transport::LegacyPath, DENY_NOTE),
    deny("/stop_mining", Transport::LegacyPath, DENY_NOTE),
    deny("/mining_status", Transport::LegacyPath, DENY_NOTE),
    deny("/save_bc", Transport::LegacyPath, DENY_NOTE),
    deny("/get_peer_list", Transport::LegacyPath, DENY_NOTE),
    deny("/set_log_hash_rate", Transport::LegacyPath, LOGGING_NOTE),
    deny("/set_log_level", Transport::LegacyPath, LOGGING_NOTE),
    deny("/set_log_categories", Transport::LegacyPath, LOGGING_NOTE),
    deny(
        "/get_transaction_pool",
        Transport::LegacyPath,
        "Restricted-gated (!m_restricted); cannot be served from a public node. Wallets use /get_transaction_pool_hashes(.bin) and /get_transaction_pool_stats instead.",
    ),
    deny("/stop_daemon", Transport::LegacyPath, DENY_NOTE),
    deny("/get_net_stats", Transport::LegacyPath, DENY_NOTE),
    deny("/set_limit", Transport::LegacyPath, DENY_NOTE),
    deny("/out_peers", Transport::LegacyPath, DENY_NOTE),
    deny("/in_peers", Transport::LegacyPath, DENY_NOTE),
    deny("/update", Transport::LegacyPath, DENY_NOTE),
    deny("/pop_blocks", Transport::LegacyPath, DENY_NOTE),
    // ── DENY (json-rpc admin/mining/peer) ──
    deny("get_connections", Transport::JsonRpc, DENY_NOTE),
    deny("get_bans", Transport::JsonRpc, DENY_NOTE),
    deny("set_bans", Transport::JsonRpc, DENY_NOTE),
    deny("banned", Transport::JsonRpc, DENY_NOTE),
    deny("flush_txpool", Transport::JsonRpc, DENY_NOTE),
    deny(
        "relay_tx",
        Transport::JsonRpc,
        "Restricted-gated (!m_restricted); cannot be served from a public node. Broadcast is available via /send_raw_transaction.",
    ),
    deny("sync_info", Transport::JsonRpc, DENY_NOTE),
    deny("prune_blockchain", Transport::JsonRpc, DENY_NOTE),
    deny("get_coinbase_tx_sum", Transport::JsonRpc, DENY_NOTE),
    deny("get_alternate_chains", Transport::JsonRpc, DENY_NOTE),
    deny("flush_cache", Transport::JsonRpc, DENY_NOTE),
    P_GET_BLOCK_TEMPLATE,
    alias_of("getblocktemplate", P_GET_BLOCK_TEMPLATE, "Alias of get_block_template (denied)."),
    deny("get_miner_data", Transport::JsonRpc, MINING_NOTE),
    deny("calc_pow", Transport::JsonRpc, DENY_NOTE),
    deny("add_aux_pow", Transport::JsonRpc, MINING_NOTE),
    P_SUBMIT_BLOCK,
    alias_of("submitblock", P_SUBMIT_BLOCK, "Alias of submit_block (denied)."),
    deny("generateblocks", Transport::JsonRpc, MINING_NOTE),
];

/// Fallback returned by [`lookup_or_deny`] for methods not in the allow-list.
static DENY_FALLBACK: Policy = Policy {
    method: "<unknown>",
    transport: Transport::JsonRpc,
    class: Class::Deny,
    cache: NA,
    quorum: NA,
    verification: Verification::NotApplicable,
    timeout_ms: 0,
    note: "Unknown method; denied (allow-list).",
};

/// The whole allow-list, in table order (aliases included).
#[must_use]
pub fn table() -> &'static [Policy] {
    TABLE
}

/// Look up the policy for a method. `None` means the method is not on the
/// allow-list and must be denied.
#[must_use]
pub fn lookup(method: &str) -> Option<&'static Policy> {
    TABLE.iter().find(|p| p.method == method)
}

/// Look up a method, defaulting to the deny fallback for anything unknown.
#[must_use]
pub fn lookup_or_deny(method: &str) -> &'static Policy {
    lookup(method).unwrap_or(&DENY_FALLBACK)
}

/// Render the policy table as Markdown so docs can be regenerated from code.
#[must_use]
pub fn render_markdown() -> String {
    let mut out = String::new();
    out.push_str("# mnr - method policy table\n\n");
    out.push_str("_Generated from `mnr-core::policy::render_markdown`. The code is canonical; this table is regenerated from it._\n\n");
    out.push_str(&format!(
        "Tip safety depth: {TIP_SAFETY_DEPTH} blocks (`TIP_SAFETY_DEPTH`). Data within that distance of the quorum tip is never cached; requests above the safety line fall back to SWR or pass through. Unknown methods are denied (allow-list).\n\n"
    ));
    out.push_str(&format!(
        "The allow-list is verified against monerod's endpoint registry (`crates/core/fixtures/monerod-core_rpc_server.h`, fetched 2026-09-04). {} rows, {} of them aliases.\n\n",
        TABLE.len(),
        TABLE.iter().filter(|p| p.note.starts_with("Alias of")).count(),
    ));
    out.push_str("| Method | Transport | Class | Cache rule | Quorum rule | Verification | Timeout (ms) | Note |\n");
    out.push_str("|---|---|---|---|---|---|---|---|\n");
    for p in TABLE {
        out.push_str(&format!(
            "| `{}` | {} | {} | {} | {} | {} | {} | {} |\n",
            p.method,
            p.transport.label(),
            p.class.label(),
            p.cache,
            p.quorum,
            verification_label(p.verification),
            p.timeout_ms,
            p.note,
        ));
    }
    out
}

fn verification_label(v: Verification) -> String {
    match v {
        Verification::Authenticated => "authenticated".to_owned(),
        Verification::Majority => "majority (>=3)".to_owned(),
        Verification::Agreement { free, pro } => format!("agreement free={free} pro={pro}"),
        Verification::Annotated => "annotated".to_owned(),
        Verification::NotDaemon => "not-daemon".to_owned(),
        Verification::NotApplicable => "n/a".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every admin/mining/peer method that must be denied: §3.3's deny row plus
    /// the endpoints the registry audit found (`_IF`-gated or admin surface),
    /// as both the legacy paths and the JSON-RPC names monerod registers.
    const DENIED_METHODS: &[&str] = &[
        // legacy paths
        "/get_alt_blocks_hashes",
        "/start_mining",
        "/stop_mining",
        "/mining_status",
        "/save_bc",
        "/get_peer_list",
        "/set_log_hash_rate",
        "/set_log_level",
        "/set_log_categories",
        "/get_transaction_pool",
        "/stop_daemon",
        "/get_net_stats",
        "/set_limit",
        "/out_peers",
        "/in_peers",
        "/update",
        "/pop_blocks",
        // json-rpc
        "get_connections",
        "get_bans",
        "set_bans",
        "banned",
        "flush_txpool",
        "relay_tx",
        "sync_info",
        "prune_blockchain",
        "get_coinbase_tx_sum",
        "get_alternate_chains",
        "flush_cache",
        "get_block_template",
        "getblocktemplate",
        "get_miner_data",
        "calc_pow",
        "add_aux_pow",
        "submit_block",
        "submitblock",
        "generateblocks",
    ];

    /// Extract every endpoint name monerod registers from the fixture: the
    /// first quoted token of every `MAP_URI_AUTO_*` (legacy) and `MAP_JON_RPC_*`
    /// (JSON-RPC) line. Plain std string ops, no regex.
    fn registry_names(src: &str) -> Vec<&str> {
        src.lines()
            .filter(|line| {
                let line = line.trim_start();
                line.starts_with("MAP_URI_AUTO") || line.starts_with("MAP_JON_RPC")
            })
            .filter_map(|line| {
                let name = line.find('"')? + 1;
                let rest = &line[name..];
                let end = rest.find('"')?;
                Some(&rest[..end])
            })
            .collect()
    }

    #[test]
    fn tip_safety_depth_is_10() {
        assert_eq!(TIP_SAFETY_DEPTH, 10);
    }

    #[test]
    fn fixture_exposes_the_expected_registry() {
        let names = registry_names(include_str!("../fixtures/monerod-core_rpc_server.h"));
        assert!(
            names.len() >= 80,
            "expected ~82 endpoints in the monerod registry, found {}",
            names.len()
        );
    }

    #[test]
    fn every_registered_endpoint_has_a_row() {
        let src = include_str!("../fixtures/monerod-core_rpc_server.h");
        for name in registry_names(src) {
            assert!(
                lookup(name).is_some(),
                "monerod registers `{name}` but it has no policy row"
            );
        }
    }

    #[test]
    fn every_policy_row_exists_in_the_registry() {
        let src = include_str!("../fixtures/monerod-core_rpc_server.h");
        let names = registry_names(src);
        for p in TABLE {
            if p.class != Class::NotDaemon {
                assert!(
                    names.contains(&p.method),
                    "policy lists `{}` but monerod does not register it",
                    p.method
                );
            }
        }
    }

    /// Endpoints monerod registers behind `!m_restricted`: unavailable on any
    /// node running `--restricted-rpc`, which is every upstream we use.
    fn restricted_gated_names(src: &str) -> Vec<&str> {
        src.lines()
            .filter(|line| {
                let line = line.trim_start();
                (line.starts_with("MAP_URI_AUTO") || line.starts_with("MAP_JON_RPC"))
                    && line.contains("_IF(")
                    && line.contains("!m_restricted")
            })
            .filter_map(|line| {
                let name = line.find('"')? + 1;
                let rest = &line[name..];
                let end = rest.find('"')?;
                Some(&rest[..end])
            })
            .collect()
    }

    /// Public-node rule 7: we never call a method a restricted node would
    /// refuse. Anything monerod gates on `!m_restricted` must be `Deny`.
    #[test]
    fn every_restricted_gated_endpoint_is_deny() {
        let src = include_str!("../fixtures/monerod-core_rpc_server.h");
        let gated = restricted_gated_names(src);
        assert!(
            gated.len() >= 25,
            "expected the restricted-gated set to be non-trivial, found {}",
            gated.len()
        );
        for name in gated {
            let p = lookup(name).unwrap_or_else(|| panic!("{name} missing from table"));
            assert_eq!(
                p.class,
                Class::Deny,
                "`{name}` is restricted-gated in monerod but not Deny"
            );
        }
    }

    #[test]
    fn every_denied_method_is_class_deny() {
        for name in DENIED_METHODS {
            let p = lookup(name).unwrap_or_else(|| panic!("{name} missing from table"));
            assert_eq!(p.class, Class::Deny, "{name} should be denied");
        }
    }

    #[test]
    fn unknown_method_is_deny() {
        assert!(lookup("get_definitely_not_a_method").is_none());
        assert_eq!(
            lookup_or_deny("get_definitely_not_a_method").class,
            Class::Deny
        );
    }

    #[test]
    fn send_raw_transaction_is_broadcast() {
        for name in ["/send_raw_transaction", "/sendrawtransaction"] {
            let p = lookup(name).unwrap_or_else(|| panic!("{name} missing from table"));
            assert_eq!(p.class, Class::Broadcast, "{name} should broadcast");
        }
        assert_eq!(
            lookup("relay_tx").expect("relay_tx in table").class,
            Class::Deny
        );
    }

    #[test]
    fn get_block_is_immutable() {
        let p = lookup("get_block").expect("get_block in table");
        assert_eq!(p.class, Class::Immutable);
        assert_eq!(p.transport, Transport::JsonRpc);
    }

    #[test]
    fn get_height_is_legacy_only() {
        assert!(
            lookup("get_height").is_none(),
            "monerod registers get_height only as the legacy /get_height path"
        );
        let p = lookup("/get_height").expect("/get_height in table");
        assert_eq!(p.transport, Transport::LegacyPath);
        assert_eq!(p.class, Class::Swr);
    }

    #[test]
    fn send_raw_transaction_is_legacy_only() {
        assert!(
            lookup("send_raw_transaction").is_none(),
            "monerod registers send_raw_transaction only as the legacy /send_raw_transaction path"
        );
        assert_eq!(
            lookup("/send_raw_transaction")
                .expect("legacy path in table")
                .transport,
            Transport::LegacyPath
        );
    }

    #[test]
    fn mempool_methods_are_legacy_paths() {
        for name in [
            "/get_transaction_pool",
            "/get_transaction_pool_hashes",
            "/get_transaction_pool_hashes.bin",
            "/get_transaction_pool_stats",
        ] {
            let p = lookup(name).unwrap_or_else(|| panic!("{name} missing from table"));
            assert_eq!(
                p.transport,
                Transport::LegacyPath,
                "{name} is a legacy path"
            );
        }
        assert_eq!(
            lookup("/get_transaction_pool")
                .expect("/get_transaction_pool in table")
                .class,
            Class::Deny
        );
    }

    #[test]
    fn outputs_family_is_per_tier_agreement() {
        for name in [
            "/get_outs.bin",
            "/get_outs",
            "/get_o_indexes.bin",
            "/get_output_distribution.bin",
            "get_output_distribution",
            "get_output_histogram",
        ] {
            let p = lookup(name).unwrap_or_else(|| panic!("{name} missing from table"));
            assert_eq!(
                p.verification,
                Verification::Agreement { free: 1, pro: 2 },
                "{name} should use per-tier upstream agreement"
            );
        }
    }

    #[test]
    fn aliases_share_canonical_class_and_are_labeled() {
        let pairs = [
            ("getblockcount", "get_block_count"),
            ("/getheight", "/get_height"),
            ("/getinfo", "/get_info"),
            ("getlastblockheader", "get_last_block_header"),
            ("/getblocks.bin", "/get_blocks.bin"),
            ("/getblocks_by_height.bin", "/get_blocks_by_height.bin"),
            ("/gethashes.bin", "/get_hashes.bin"),
            ("/gettransactions", "/get_transactions"),
            ("/sendrawtransaction", "/send_raw_transaction"),
            ("getblock", "get_block"),
            ("getblockheaderbyhash", "get_block_header_by_hash"),
            ("getblockheaderbyheight", "get_block_header_by_height"),
            ("getblockheadersrange", "get_block_headers_range"),
            ("on_getblockhash", "on_get_block_hash"),
            ("getblocktemplate", "get_block_template"),
            ("submitblock", "submit_block"),
        ];
        for (alias, canonical) in pairs {
            let a = lookup(alias).unwrap_or_else(|| panic!("{alias} missing from table"));
            let c = lookup(canonical).unwrap_or_else(|| panic!("{canonical} missing from table"));
            assert_eq!(a.class, c.class, "{alias} should share {canonical}'s class");
            assert!(
                a.note.contains("Alias of"),
                "{alias} should be labelled as an alias"
            );
        }
    }

    #[test]
    fn wallet_rpc_methods_are_not_daemon() {
        for name in [
            "check_tx_key",
            "check_tx_proof",
            "check_spend_proof",
            "check_reserve_proof",
        ] {
            let p = lookup(name).unwrap_or_else(|| panic!("{name} missing from table"));
            assert_eq!(p.class, Class::NotDaemon, "{name} is not a daemon method");
            assert_eq!(p.verification, Verification::NotDaemon);
        }
    }

    #[test]
    fn no_duplicate_method_names() {
        let mut names: Vec<&str> = TABLE.iter().map(|p| p.method).collect();
        names.sort_unstable();
        let dupes: Vec<&str> = names
            .windows(2)
            .filter(|w| w[0] == w[1])
            .map(|w| w[0])
            .collect();
        assert!(dupes.is_empty(), "duplicate method names: {dupes:?}");
    }

    #[test]
    fn render_markdown_covers_every_method() {
        let md = render_markdown();
        for p in TABLE {
            assert!(
                md.contains(&format!("`{}`", p.method)),
                "rendered table missing {}",
                p.method
            );
        }
        assert!(md.contains("TIP_SAFETY_DEPTH"));
    }
}
