# mnr — an RPC network for Monero

This repository is **Stage 0**: a verified proxy over public Monero nodes plus one node we run. It is the seed of two larger designs (Stage 1 owned mesh, Stage 2 operator network) and must not foreclose them. Read `@docs/stage0-mvp-plan.md` before doing anything; it is the to-do list. The Stage 1/2 documents in `docs/` are the map, not current scope.

## What we are building right now

One Rust binary, `mnr-relay`, on one VPS, exposing Monero **daemon** RPC at `rpc.mnr.network` (+ a `.onion`). It authenticates a path token, applies a method policy, caches what is safe, verifies what can be verified, fans out writes, and forwards the rest to a pool of upstreams: curated public nodes plus our own full node. Free tier and a $9 Pro tier, no uptime promise.

Explicitly **out of scope** for Stage 0: operator agent, directory, settlement/payouts, affiliate program, stream verification of `get_blocks.bin`, Cloudflare, `monero-wallet-rpc` methods, SLAs.

## Non-negotiable invariants (from the plan; do not "simplify" these away)

1. **Verify, don't trust.** Block/header responses are re-hashed and matched to the requested hash or our header chain; tx blobs are hashed and matched to txids; consensus state (`get_info`, `get_height`, fee) is the majority of ≥3 upstreams. Anything unverifiable is annotated (`Mnr-Verify: none`, `Mnr-Upstream: <n>`), never silently trusted.
2. **Tip safety.** Never cache a block/header/tx within 10 blocks of the quorum tip. Cache keys carry an epoch that is bumped on reorg detection.
3. **Method allow-list.** Only the methods in the policy table are dispatched; admin/mining/peer methods are denied at the edge even though nodes run `--restricted-rpc`.
4. **Writes fan out.** `send_raw_transaction` goes to every healthy upstream in parallel; success if any accepts; `Mnr-Relayed: k/n`.
5. **Public-node rules** (`.claude/rules/public-nodes.md`): per-upstream caps, identifying `User-Agent`, opt-out honoured, no client identity forwarded, restricted methods only. These are ethics, not tuning knobs.
6. **No request logs.** No path, no token, no client IP is ever written. Tokens are stored hashed. Error samples carry only an 8-char token-hash prefix.
7. **Stock wallets must work** with nothing but `--daemon-address rpc.mnr.network:443 --daemon-login <token>:x`. Stock wallets speak HTTP Digest only and keep just host and port of the address, so the token rides in the Digest **username** (the password is ignored; Digest cannot be checked against a stored hash) and the path-token form (`/v1/<token>/…`) is for curl, scripts and URL-taking clients. The relay offers Digest and Basic challenges. Never require a custom header.

## Architecture (Stage 0)

- `crates/core` — `mnr-core`: `wire` (JSON-RPC + epee types), `hash` (Keccak-256, block hashing blob, tx-tree hash, pruned tx hash), `verify` (pure functions over bytes), `policy` (the method table; docs are generated from it), `headerchain`. No I/O. Fuzz targets for every parser.
- `crates/relay` — `mnr-relay`: axum ingress (TLS + onion via local Tor), token auth (SQLite, hashed), in-process token bucket + daily WU quota, policy dispatch, `moka` cache, upstream prober (15 s), ranking, quorum tip, degraded mode, verification, broadcast, invoice watcher against a view-only `monero-wallet-rpc`, Prometheus `/metrics`.
- `spec/` — protocol notes that will become the Stage 2 spec; keep the method table and verification rules here in prose as they land in code.
- `deploy/` — Ansible for the relayer VPS and the owned node (WireGuard, Tor, systemd, monitoring).
- `sim/` — `drill.sh` against a synthetic node with fault injection (wrong header, lagging height, dropped stream); a stagenet compose harness and a nightly CI run are planned, not built.
- Work unit (WU): 1 light request = 1 WU; 1 MB of `get_blocks.bin` = 20 WU. Quotas, invoices and (later) payouts all use WU.

The method policy table is code: `mnr-core::policy` is canonical, checked in tests against monerod's endpoint registry (`crates/core/fixtures/monerod-core_rpc_server.h`), and `docs/method-policy.md` is regenerated from it with `cargo run -p mnr-core --example render_policy > docs/method-policy.md`. `docs/stage1-gateway-development-plan.md` §3.3 is the historical source.

## Conventions

- Licences: AGPL-3.0-only for the workspace, Apache-2.0 for `crates/core` (`mnr-core` must stay embeddable by wallets; keep it free of AGPL dependencies), CC-BY 4.0 for `spec/`, `brand/` all rights reserved. The name is defended by `TRADEMARK.md`, anchored on the domain and the release key, not on a legal entity; there is none.
- Rust 2021, stable toolchain, `cargo fmt` + `cargo clippy -D warnings` clean before commit. tokio + axum + rustls; `moka` for cache; `rusqlite` for state; an in-process token bucket for rate limiting (capacity twice the rate).
- Monero serialization/hashing: the `monero-oxide` crates (the monero-serai fork); wrap them behind `mnr-core::hash` so a crate swap never touches the relay. Every hashing function has fixture tests from real mainnet blocks (every hard-fork boundary block, coinbase-only blocks, pruned and unpruned tx forms, a live mempool entry).
- Tests: `cargo test` for units; `sim/` for integration; differential tests against a real `monerod` for `wire`/`hash`.
- Config is one TOML file; upstreams are a list with `kind = "owned" | "public"`, `transport = "https" | "http" | "onion"`, and per-node caps.
- Headers we emit are `Mnr-*`. Package/crate prefix is `mnr`. The name is written lowercase `mnr`; in prose, "mnr — an RPC network for Monero", never "the Monero network".
- Commit messages: imperative, one line, reference the plan section when implementing it (e.g. `relay: add upstream prober (plan §3)`).

## Repositories

- `mnrnetwork/mnr` (this repo, public) — Cargo workspace, spec, sim, deploy playbooks, engineering docs.
- `mnrnetwork/mnr.network` (public, local `../mnr.network`) — the static site: front page, upstreams page, docs. Design source lives there in `design/`.
- `mnrnetwork/internal` (private, local `../internal`) — business plans, profit model, operator contact and opt-out log, Ansible inventory and secrets, weekly gate numbers. Never copy its contents here.

## Commands

- Build: `cargo build --release`
- Test: `cargo test --workspace`
- Sim: `sim/drill.sh` (needs a release binary; see `sim/README.md`)
- Run locally: `cargo run -p mnr-relay -- --config relay.toml`

## Where decisions came from

`docs/` holds the engineering history; the original aggregator doc, the business plans and the profit model live in the private `mnrnetwork/internal` repo (local: `../internal`). Three independent reviews shaped Stage 1; Stage 2 adds the operator network with mechanisms borrowed from THORChain (probation lane, payout splits, affiliate share, work-weighted votes). When a question is "why is it like this", the answer is in those documents; when a question is "what do I build next", the answer is `docs/stage0-mvp-plan.md` §7.

Decisions are recorded at the end of each plan (the former open-question lists, closed 2026-09-04). A new open question goes there as an item, not into code; do not resolve one silently.
