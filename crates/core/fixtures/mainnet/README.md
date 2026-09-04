# Mainnet fixtures

Fetched on 2026-09-04 from a public node (`xmr-node.cakewallet.com:18081`) with
`User-Agent: mnr-fixtures/0.1 (+https://mnr.network)`. Raw `get_block`,
`/get_transactions`, `get_info`, `get_last_block_header` and `get_fee_estimate`
responses, unmodified.

- `block-<height>.json`: genesis (0), block 1, the special-cased block 202612,
  every mainnet hard-fork boundary block v2–v16 (1009827, 1141317, 1220516,
  1288616, 1400000, 1546000, 1685555, 1686275, 1788000, 1788720, 1978433,
  2210000, 2210720, 2688888, 2689608), and a recent block (3754000).
- `txs-<height>-prune-{false,true}.json`: up to five transactions from the
  block at that height, in full and pruned form. Covers v1 (202612, 1009827),
  early RingCT (1400000) and current RingCT (2689608, 3754000).
- `get_info.json`, `get_last_block_header.json`, `get_fee_estimate.json`:
  JSON-RPC responses from the same node, for `mnr-core::wire` parsing tests.

Used by `mnr-core::hash` and `mnr-core::wire` tests. Regenerate with the same
RPC calls if a new hard fork lands; add the boundary block.
