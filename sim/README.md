# sim

Two layers of integration testing for `mnr-relay`.

## In-process load test (exists)

`cargo run -p mnr-relay --release --example load [-- --quick]` builds the real
relay app over four mock upstreams (one owned, three public) and drives 500 rps
of light calls plus 10 concurrent `get_blocks.bin` syncs for 30 s (10 s with
`--quick`, which CI runs on every push). It reports latency percentiles, the
error mix, the cache hit ratio and the work units charged, and fails when any
public-node cap is exceeded: light calls per sliding second, concurrent
streams, bytes over the run (`.claude/rules/public-nodes.md` rule 3), or when
a response lacks `Mnr-Verify` / `Mnr-Cache`.

The owned mock is capped at 50 light rps on purpose so that passthrough
traffic overflows to the public mocks and their caps are exercised; the
overflow the public caps cannot absorb is refused with 503, which is the
designed behaviour.

What it does not prove: a public node's tolerance, verification against real
blocks beyond the fixtures, reorg handling under a real daemon.

## Reorg and ejection drill (exists)

`sim/drill.sh` starts four synthetic nodes (`crates/relay/examples/injector.rs`,
a deterministic header chain with runtime-switchable faults) behind the real
relay binary and drives three scenarios end to end: every node switches to a
branch and back (two reorgs: the header chain is truncated and rebuilt, the
cache epoch bumps, a cached header becomes a miss), one node lies about three
headers (three faults, ejection, the public feed shows it, clients still get
verified answers from the others), and every node cuts its streams (short
reads with HTTP 200; a full stream afterwards proves the slots were released).
Takes about a minute; needs `curl` and `jq`. Exit status 0 only when every
check passes.

What it does not prove: real `monerod` behaviour (fields, timing, a real
reorg). The unit tests carry the fixture-based verification; the drill carries
the state machines around it.

## Stagenet harness (planned)

docker-compose with three `monerod --stagenet` nodes and the relay, for the
same drill against real daemon behaviour. It needs Docker and a stagenet sync
(hours), so it would run nightly, not on push. Not started.
