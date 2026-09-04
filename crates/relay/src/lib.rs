//! `mnr-relay` — the Stage 0 verified proxy (`docs/stage0-mvp-plan.md` §6).
//!
//! Week 2: config, upstream pool and prober, ingress with token auth and
//! limits, policy dispatch, passthrough and broadcast, and a persistent
//! token store with a work-unit limiter (see [`store`]). Week 3: the header
//! chain ([`chain`]), verification in the request path ([`verify`],
//! [`consensus`], [`agreement`]), the cache ([`cache`]) and Prometheus
//! metrics ([`metrics`]). See `spec/headers.md` for what a client is told.
//!
//! With `[auth] database` set, tokens are managed through the `token`
//! subcommand and requests are authenticated against SQLite; without it,
//! `--dev-token` serves from memory (tests and local runs).

//!
//! The crate is a library plus a thin binary so the load test
//! (`examples/load.rs`) and integration tests can drive the real app.

#![forbid(unsafe_code)]

pub mod agreement;
pub mod auth;
pub mod cache;
pub mod chain;
pub mod config;
pub mod consensus;
pub mod dispatch;
pub mod ingress;
pub mod limits;
pub mod metrics;
pub mod store;
pub mod stream;
pub mod upstream;
pub mod verify;
