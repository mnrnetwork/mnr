# Contributing to mnr

Thank you. Before you start, read `CLAUDE.md` for what is being built right
now and `.claude/rules/public-nodes.md` for the rules every upstream code
path must satisfy; they are not negotiable.

## Licences

- `crates/relay` and everything not listed below: **AGPL-3.0-only** (`LICENSE`).
- `crates/core` (`mnr-core`), and `mnr-client` when it exists: **Apache-2.0**
  (`crates/core/LICENSE`), so wallets can embed them. Keep `mnr-core` free of
  AGPL dependencies.
- `spec/` and the verification methodology in `docs/`: **CC-BY 4.0**.
- `brand/`: all rights reserved, see `brand/LICENSE` and `TRADEMARK.md`.

By contributing you license your contribution under the licence of the
directory it lands in. There is no CLA and no copyright assignment; each
contributor keeps their copyright.

## Developer Certificate of Origin

Every commit must carry a `Signed-off-by:` line (`git commit -s`) certifying
the [Developer Certificate of Origin 1.1](https://developercertificate.org/):
that you wrote the change or have the right to submit it under the licence
above. A pseudonym is fine; use the same one consistently.

## Ground rules for code

- `cargo fmt --all` and `cargo clippy --workspace --all-targets -- -D warnings`
  clean, `cargo test --workspace` green.
- Every hashing or parsing function gets a fixture test from real mainnet
  data and a fuzz target.
- No request logs: no path, token or client address may reach a log line.
- Commit messages: imperative, one line, referencing the plan section
  (`relay: add upstream prober (plan §3)`).
