# Response headers

mnr — an RPC network for Monero. Every answer the relay returns carries a small
set of `Mnr-*` headers that say what was checked and where the answer came from.
A client never needs to send any of them (stock wallets work with nothing but a
daemon address); they exist so that a client *can* know.

Licence: CC-BY 4.0. Status: implemented in `mnr-relay` (Stage 0); not yet
normative for other relays.

## `Mnr-Verify`

What the relay checked before returning the answer. Exactly one value, from the
strongest to the weakest:

| Value | Meaning |
|---|---|
| `chain` | Confirmed against the relay's own header chain: the block or header sits at the height it claims, with the hash and previous hash the chain holds. Implies the hash was recomputed where a blob was present. |
| `hash` | The recomputed hash matched what the client asked for (a block by hash, a transaction by txid), but the relay's chain does not reach that height, so the answer is proven authentic, not proven canonical. |
| `majority` | Consensus state agreed by at least two of the upstreams asked (see `Mnr-Agreeing`). |
| `agreement` | Identical answers from the number of upstreams the client's tier requires (see `Mnr-Agreeing`). |
| `partial` | A batch (`/get_transactions`) in which some entries verified and some could not be (see `Mnr-Verified`). No entry failed. |
| `none` | Not verifiable, or not verified: streams, mempool, degraded mode, a height the chain does not reach yet, a form that cannot be hashed. Served as the upstream sent it and never cached. |
| `failed` | Every upstream asked returned an answer that failed verification, or the upstreams could not agree. The body is an error, never one of the rejected answers. |

Precedence when an answer satisfies more than one rule: `chain` over `hash` for
immutable methods; consensus methods are `majority` or `none` only; the outputs
family is `agreement` or `none` only; transaction batches are `hash`, `partial`
or `none`. `failed` only accompanies an HTTP 502.

A daemon-level error in the answer (unknown hash, height above the tip) is
returned as the daemon sent it, with `none`: it is not a lie.

## `Mnr-Verified: k/n`

With `Mnr-Verify: partial`: `k` of the `n` entries in the answer verified. The
others had no hashable form (a pruned v1 transaction, for instance). Absent
otherwise.

## `Mnr-Agreeing: k/n`

With `majority` or `agreement`: `k` of the `n` upstreams asked gave the same
answer. For the outputs family `n` includes the tie-breaker when one was used.

## `Mnr-Upstream: <n>`

The pool index of the single upstream whose answer this is. An opaque number,
stable for the life of the relay process and never a name or address: a client
can tell that two answers came from different nodes without the relay
advertising which node said what. Absent when an answer was composed from
several upstreams or served from cache.

## `Mnr-Relayed: k/n`

On a broadcast (`send_raw_transaction`): `k` of the `n` healthy upstreams
accepted the transaction. The body is the first accepting upstream's answer, or
the first rejection verbatim when none accepted.

## `Mnr-Cache`

| Value | Meaning |
|---|---|
| `hit` | Served from cache, fresh. |
| `stale` | Served from cache past its `max-age` while a refresh runs, or because the refresh failed (`stale-if-error`). Consensus state only. |
| `miss` | Fetched from an upstream on this request; may have been written to cache. |
| `bypass` | Not a cacheable answer (stream, mempool, write, outputs, error). |

Cache windows: immutable data 30 days but only at or below `quorum_tip − 10`
and only when verified; consensus state `max-age=1, stale-while-revalidate=5,
stale-if-error=15` seconds. A reorg bumps the cache epoch, which is part of
every immutable key, so nothing from the abandoned branch can be served.

## `Mnr-Tier`

`free` or `pro`: the tier of the token the request was accepted under.

## Not headers

The relay never emits a header carrying a token, a token handle, a client
address, or an upstream's name or URL.
