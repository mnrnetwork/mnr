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

## Stagenet harness (planned, plan §7 weeks 5–6)

docker-compose with three `monerod --stagenet` nodes, the relay, and a fault
injector in front of one node (wrong header, lagging height, dropped stream),
used for the header-chain reorg drill and the ejection drill against real
daemon behaviour. It needs Docker and a stagenet sync (hours), so it runs
nightly, not on push. Not started yet: the unit tests with mock upstreams
cover the injected-fault paths (tampered blob → fault → fall-through →
ejection, lagging tip excluded from the vote, stalled stream cut at the idle
timeout) until it exists.
