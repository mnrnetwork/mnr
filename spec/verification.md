# Verification rules

mnr — an RPC network for Monero. What the relay checks, per method, before an
answer leaves it (`docs/stage0-mvp-plan.md` §4; code in `mnr-core::verify`,
`mnr-relay::verify`, `mnr-relay::consensus`, `mnr-relay::agreement`). The
labels named here are the values of `Mnr-Verify` in `headers.md`.

Licence: CC-BY 4.0. Status: implemented (Stage 0); not yet normative.

## The header chain

The relay keeps its own chain of `(height, hash, prev_hash, timestamp)` records
from genesis. It is built once from the upstreams by *majority*: each batch of
up to 1000 headers is fetched from `min_agree` upstreams at once (the relay's
own node always among them when healthy) and appended only when every copy is
identical and links to the previous record. A copy in the minority is a fault
against its upstream. After that the chain is extended every probe round to the
quorum tip, re-fetching the last 20 records so a reorg is found by the highest
height on which the chains still agree. A reorg truncates the chain, appends
the new branch, and bumps the cache epoch. If no common record is found the
search widens to 1000; beyond that the chain is cut back by 1000 blindly, which
also bumps the epoch. Without a quorum tip (degraded mode) the chain neither
builds nor extends.

Proof-of-work is not verified; linkage and majority are. An upstream that
fabricates a PoW-valid alternate chain is a 51% attacker, outside this model.

## Immutable methods

| Method | Check | Label |
|---|---|---|
| `get_block` by `hash` | Block hash recomputed from `blob`; must equal the requested hash. `block_header` (hash, height, prev_hash, timestamp, versions), `miner_tx_hash`, `tx_hashes` and `num_txes` must describe the blob. | `chain` if the chain holds that hash at that height, else `hash` |
| `get_block` by `height` | As above, and the recomputed hash must equal the chain's at that height; the blob must carry that height. | `chain`; `none` if the chain is shorter |
| `get_block_header_by_height` | Height, hash, prev_hash and timestamp must equal the chain's record. | `chain`; `none` if the chain is shorter |
| `get_block_header_by_hash` | The reported hash must be the requested one; then as by height. A header at a height where the chain holds another block is an orphan: honest only if `orphan_status` is not `false`. | `chain`; `none` if the chain is shorter or the header is a declared orphan |
| `get_block_headers_range` | Exactly `end − start + 1` headers, heights contiguous from `start`, each linking to the previous, each equal to the chain's record. No partial trust: one header beyond the chain makes the whole answer `none`. | `chain` / `none` |
| `on_get_block_hash` | The returned hash must equal the chain's at the requested height. | `chain`; `none` if the chain is shorter |

A request the relay cannot interpret (a malformed `hash` param, for instance)
is passed through with the daemon's own answer as `none`; the fault log counts
wrong *answers* only. A mismatch anywhere is a **fault**: the answer is never
returned, the fault is recorded against the upstream, and the next ranked
upstream is asked, up to three. If every attempt faults the client receives
HTTP 502 with `Mnr-Verify: failed`.

**Ejection.** Three faults within an hour eject an upstream for 24 hours. The
fault log entry that caused it and the upstreams feed both carry
`ejected_until`; when the ejection lapses the upstream re-enters the ranking on
the next probe round and the lapse is logged once. Faults, ejections and the
`verified` count per upstream are public, and they persist across relay
restarts in the relay's database (the fault log keeps its newest thousand
entries), so "node X served a wrong header on Tuesday" stays on the page.

Verified answers whose height is at or below `quorum_tip − 10` are cached under
the current chain epoch; the alias forms (`getblock`, …) share the entry.

## Transactions

`/get_transactions`: every returned entry must have been requested, and the
parallel arrays a wallet may read instead of the entries (`txs_as_hex`,
`txs_as_json`) must have one element per entry carrying the same bytes as
`txs[i].as_hex` / `txs[i].as_json`. For each entry the blob is hashed and must
equal `tx_hash`: the full form from `as_hex`,
or the pruned form from `pruned_as_hex` plus `prunable_hash`. A confirmed entry
must not claim a height more than three blocks above the quorum tip (the
quorum lags a probe round, so a node on the real tip is honestly one or two
blocks ahead of it). An entry with no hashable form
(a pruned v1 transaction) is *unverifiable*, not a fault. A mempool entry
(`in_pool: true`) carries no `block_height`, `confirmations` or
`output_indices` at all (monerod serialises those only for confirmed
transactions, and `relayed` / `received_timestamp` only for pool ones); it is
verified by hash alone, labelled `hash` like any other entry, and never
cached. A confirmed entry that lacks a height is malformed: *unverifiable*,
not a fault; a node that always omits heights therefore shows as permanently
unverifiable on `/get_transactions` (never cached, never `hash`), which is
visible on the upstreams page but is not an ejection signal by design.
`missed_tx` entries must have been requested too.

This is how a client reads the mempool through the relay: pool hashes from
`/get_transaction_pool_hashes(.bin)` or `/get_transaction_pool_stats`
(pass-through, `none`, one upstream), then the transactions themselves from
`/get_transactions`, each proven to hash to its txid.

### The composed pool listing

`/get_transaction_pool` is not forwarded: monerod refuses it on restricted RPC
from commit 57ae55e (2026-07-25, on the 0.18 release branch, not in a shipped
0.18.x yet), so no public node will offer it for long. The relay composes the
same shape itself (plan decision 8). The listing comes from one upstream's
`/get_transaction_pool_hashes`, the relay's own node first because it sees
every broadcast the relay relays; that upstream is the `Mnr-Upstream` of the
whole answer. Every listed transaction is then fetched through the
`/get_transactions` path above, in batches of at most 100, and so proven to
hash to its id; the verifying upstream may differ from the listing one. From
the verified blob the relay recomputes `blob_size`, `weight` (with the
bulletproof clawback), `fee` and the key images, and builds
`spent_key_images` from those, so a key image in two pool transactions shows
as monerod would show it. `tx_json` is the node's rendering of the verified
blob and is passed through as such; `tx_blob` is authoritative.
`receive_time` is the unix time the relay first saw the hash in a listing,
never a node's claim (restricted nodes report zero). The fields a daemon fills
from its own pool state (`max_used_block_*`, `last_failed_*`,
`kept_by_block`, `last_relayed_time`, `do_not_relay`) are zero, false or
empty. A transaction that was mined between the two calls, or that the node
no longer has, is dropped from the listing; one whose blob cannot be parsed
is dropped and counted as unverified.

Label: `hash` when every served entry verified (an empty pool is `hash`),
`partial` with `Mnr-Verified: k/n` when a batch could only partly be
verified, `none` when nothing could. The answer itself is never cached
(`Mnr-Cache: bypass`); verified transactions are held by txid for ten minutes
so a poll costs the listing plus one light call per transaction the relay has
not seen before. That is also the charge: one work unit at admission plus one
per transaction fetched (`extra_wu`), which is one call per new pool
transaction as decision 8 states. Membership is always read from the fresh
listing, never from the tier.

Label: `hash` when every entry verified, `partial` with `Mnr-Verified: k/n`
when some could not be, `none` when none could. Each verified, confirmed entry
at or below the safety line is cached on its own, keyed by hash and the
request's `prune`/`decode_as_json` flags; a later batch is served as cache hits
plus one upstream call for the misses, reassembled in request order.

## Consensus state

`get_info`, `/get_info`, `get_height`, `/get_height`, `get_block_count`,
`get_last_block_header`, `get_fee_estimate`, `hard_fork_info`, `get_version`
and their aliases. On a cache miss the top three ranked on-tip upstreams with
capacity are asked at once and each answer is reduced to an agreement key:

| Method | Key |
|---|---|
| `get_info`, `/get_info` | `(height − 1, top_block_hash)`; excluded from the vote if more than one block from the quorum tip |
| `/get_height` | `(height − 1, hash)`, height only when the node sends no hash; same exclusion |
| `get_block_count` | `count − 1`; same exclusion |
| `get_last_block_header` | `(block_header.height, block_header.hash)`; same exclusion |
| `hard_fork_info` | `(version, enabled, state, earliest_height)` |
| `get_version` | `version` |
| `get_fee_estimate` | not voted: `fee` is the median of the estimates and `fees[i]` the element-wise median when every answer has the same number of tiers |

The largest group of at least two identical keys is served as `majority` with
`Mnr-Agreeing: k/n`; otherwise the best-ranked answer is served as `none`.
Disagreement is never a fault: a node one block ahead or behind is honest.
`get_info` is normalised before it is served (connection counts, peer-list
sizes, `update_available`, `start_time` zeroed).

`get_last_block_header` is additionally checked against the relay's header
chain when the chain already reaches the reported height (the usual case is
that it does not: the chain trails the tip by one probe round). A header the
chain confirms is served as `chain`; one the chain contradicts is served as
`none`, since a majority disagreeing with our chain at a known height is a
reorg in flight that the next chain-sync round settles, and no fault is
recorded. `Mnr-Agreeing` is emitted either way.

## Outputs

`/get_outs`, `/get_outs.bin`, `/get_o_indexes.bin`, `get_output_distribution`,
`/get_output_distribution.bin`, `get_output_histogram`. Per tier: Free is served
by one upstream (the relay's own node preferred) as `none`; Pro by two, whose
answers are parsed (epee portable storage for `.bin`, JSON otherwise), stripped
of `credits`, `top_hash`, `untrusted` and `status`, and compared as trees so a
field one node adds is not a disagreement. Identical answers are `agreement`
with `Mnr-Agreeing: 2/2`. If they differ, a third upstream breaks the tie: the
answers matching it win and the outlier is a fault. No majority, or no third
upstream with capacity, is HTTP 502 `failed`: a wrong ring is worse than no
ring. A tie-breaker that does not answer at all is HTTP 502 `none` (nobody is
proven wrong). An answer
the relay cannot parse is served as `none`, never as agreement.

Only `get_output_distribution` with `to_height` at or below the safety line is
cached, and only when agreed. The rest of the family needs the output
distribution to map indices to heights before it could be cached safely.

## Streams

The `get_blocks.bin` family is not verified in Stage 0 (`none`). A stream is
sent through as it arrives, never buffered: paced to the upstream's published
bandwidth cap, ended after 15 s without a chunk from the upstream (a slow
client does not count), and bounded at 1 GiB per answer. The client pays
20 work units per MB received, settled when the stream ends or the client
disconnects.

## Opt-out (rule 5)

Every upstream host is read at `https://<host>/.well-known/mnr-optout`
(`http://` for plain-HTTP and onion upstreams) at start and once a day, with
the relay's identifying `User-Agent` and no light-call token. Any HTTP 200 means
the operator has opted out: the host leaves rotation at once, the event is in
the public feed, and the relay's operator is told to add the host to the
config's `opt_out` list, which refuses it at load. Anything else (404, no
answer) means "no answer today" and is re-read the next day; removing the file
re-admits the host on the next read.

## Routing of revealing requests

The content of some requests says what a wallet is looking at: the outputs it
builds a ring from (`/get_outs`, `/get_outs.bin`, `/get_o_indexes.bin`,
`get_output_distribution`, `get_output_histogram`), the transactions it looks
up (`/get_transactions`) and the key images it checks (`/is_key_image_spent`).
These go to the relay's **own node first, always**, and to public nodes only
when it is down or at its cap. A public node therefore sees such a request
only as the fallback, and even then without the client's address. The
outputs family for Pro compares the owned node's answer with the best public
node's, so the public node sees that query by design; see `agreement`.

## Not verified

Streams (`/get_blocks.bin` family), mempool methods, `/is_key_image_spent`,
`/get_public_nodes`, `/get_limit`: served from one upstream as `none` with
`Mnr-Upstream`. Broadcasts carry `Mnr-Relayed` instead.
