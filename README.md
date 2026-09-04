# mnr — an RPC network for Monero

Stage 0: a verified proxy over public Monero nodes plus one node we run.

- Plan: `docs/stage0-mvp-plan.md` (what to build, in order)
- Project context for Claude Code: `CLAUDE.md` (read automatically) and `.claude/rules/public-nodes.md`
- Later stages: `docs/stage1-*` (owned mesh + SLA), `docs/stage2-*` (operator network)
- Website: [`mnrnetwork/mnr.network`](https://github.com/mnrnetwork/mnr.network)

## Layout

```
crates/core    mnr-core   wire · hash · verify · policy · headerchain (no I/O)
crates/relay   mnr-relay  the Stage 0 binary
spec/          protocol notes that become the Stage 2 spec
deploy/        Ansible for the relayer VPS and the owned node
sim/           stagenet harness with fault injector
docs/          the plans
```

## Build

```bash
cargo build --release
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

License: AGPL-3.0-only (see `LICENSE`).
