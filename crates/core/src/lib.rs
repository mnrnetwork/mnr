//! `mnr-core` — pure functions for mnr — an RPC network for Monero.
//!
//! This crate has **no I/O**. Everything in it is a function over bytes or
//! plain data so that it can be fuzzed, differential-tested against a real
//! `monerod`, and reused unchanged by the relay, the agent and the client.
//!
//! Modules follow `docs/stage2-network-protocol-architecture.md` §4.1:
//! - [`wire`] — JSON-RPC and epee binary types for the daemon API
//! - [`hash`] — Keccak-256, block hashing blob, tx-tree hash, pruned tx hash
//! - [`verify`] — the verification rules of `docs/stage0-mvp-plan.md` §4
//! - [`policy`] — the method allow-list and per-method class/cache/quorum rules
//! - [`headerchain`] — the `(hash, prev_hash, timestamp, height)` chain store
//! - [`epee`] — read-only parser for monerod's epee binary (`.bin` endpoints), for cross-upstream comparison

#![forbid(unsafe_code)]

pub mod epee;
pub mod hash;
pub mod headerchain;
pub mod policy;
pub mod verify;
pub mod wire;
