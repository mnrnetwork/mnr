# Monero RPC Gateway — Development Plan (v1)

| | |
|---|---|
| **Status** | Canonical engineering plan. Supersedes `Monero RPC Aggregator - Product Documentation.md`. |
| **Date** | 2026-09-03 |
| **Inputs reconciled** | Original product doc; reviews by Grok 4.6, opencode, and Antigravity (all dated 2026-09-03) |
| **Companion document** | `Monero RPC Gateway - Business Operations.md` (tiers, billing ops, SLA, support, finance) |
| **Product name** | **Monero RPC Gateway** (the word "Aggregator" is retired everywhere: file names, code, copy) |

---

## 0. How this plan was derived

The three reviews disagree on tone but agree on substance. Every item below was raised by at least two reviewers and is treated as a **binding decision** for v1:

| Decision | Grok | opencode | Antigravity |
|---|:-:|:-:|:-:|
| Rename to "Gateway"; one canonical doc, one tier table | ✓ | ✓ | ✓ |
| Minimum 3 independently hosted `monerod` nodes; define quorum per method | ✓ | ✓ | ✓ |
| No Cloudflare Cron for health probes (60 s floor) → Durable Object alarm loop | ✓ | — | ✓ |
| Bot Fight Mode permanently off | ✓ | ✓ | ✓ |
| Never cache blocks within N confirmations of tip; reorg invalidation | ✓ | ✓ | ✓ |
| No Durable Object call on cache hits; local token bucket + batched DO sync | ✓ | ✓ | ✓ |
| Daemon RPC only; `monero-wallet-rpc` explicitly out of scope | ✓ | — | ✓ |
| R2 block archive deferred (wallets speak `get_blocks.bin`, not static slices) | ✓ | ✓ | ✓ |
| Routing in the Worker; no Rust hop in v1 | ✓ | — | ✓ (implied) |
| Tor only via a self-hosted bridge, ≥8 s timeout, phase 2 | ✓ | ✓ | ✓ |
| Method-specific timeouts | ✓ | ✓ | ✓ |
| "Zero-log" replaced by a defined logging policy | ✓ | ✓ | ✓ |
| Path tokens: ≥256-bit, rotation mandatory, path never logged, Basic-auth alternative | ✓ | ✓ | ✓ |
| KV eventual consistency (~60 s) must be designed around for auth/billing | — | ✓ | ✓ |
| Cost model from measured per-request cost, not a $77 table | ✓ | ✓ | ✓ |
| 0-conf risk disclosed; "guarantee" language removed | — | ✓ | ✓ |
| Status page / 99.999% SLO / PagerDuty deferred | ✓ | ✓ | ✓ |

Where reviewers offered different specifics (e.g. tip safety margin of 10 vs "10+"), this plan picks one value and states it.

---

## 1. Product definition (one paragraph, one boundary)

**Monero RPC Gateway** is a paid, authenticated HTTPS endpoint that speaks the `monerod` daemon JSON-RPC and binary (`.bin`) API. Behind it sit gateway-owned Monero nodes on separate providers; the edge validates height agreement across them, caches what is safe to cache, broadcasts transactions to all healthy nodes, and fails over automatically. Customers point a stock wallet, a swap backend, or an agent at one URL and stop running `monerod`.

**Scope boundary (state it on the website and in the ToS):**

- **In scope:** `monerod` daemon RPC (`/json_rpc`, legacy `/get_*` endpoints, `/get_blocks.bin`, `/send_raw_transaction`, `/get_transactions`, `/get_outs.bin`, etc.).
- **Out of scope:** `monero-wallet-rpc`. It is stateful, holds view/spend keys, and cannot be multiplexed at an edge. Customers run their own wallet software (CLI/GUI/`monero-wallet-rpc`/`monero-lws`) and point it at the gateway as its daemon.

---

## 2. Target architecture (v1)

```
                      ┌──────────────────────────────────────────────────────────┐
 Wallet / agent /     │  Cloudflare edge (Anycast)                               │
 swap backend  ─────▶ │  Hono Worker "gateway-edge"                              │
 https://rpc.<dom>/   │   1. auth: path token /v1/<tok>/…  or Basic-auth         │
   v1/<tok>/json_rpc  │   2. rate limit: isolate-local token bucket              │
                      │      + batched quota sync to tenant DO (miss path only)  │
                      │   3. classify method → cache / swr / passthrough / bcast │
                      │   4. dispatch to node(s) via Cloudflare Tunnel           │
                      │   5. quorum check on response (per-method rule)          │
                      └───────────────┬──────────────────────────────────────────┘
                                      │ Cloudflare Tunnel (cloudflared on each node)
              ┌───────────────────────┼───────────────────────┐
              ▼                       ▼                       ▼
     ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
     │ node-a (full)   │    │ node-b (full)   │    │ node-c (pruned) │
     │ Hetzner, DE     │    │ OVH, FR/CA      │    │ Vultr/other, NL │
     │ monerod --rpc-  │    │ monerod         │    │ monerod --prune │
     │ restricted-rpc  │    │                 │    │                 │
     └─────────────────┘    └─────────────────┘    └─────────────────┘
              ▲                       ▲                       ▲
              └───────────────────────┼───────────────────────┘
                     ┌────────────────┴─────────────────┐
                     │ Durable Object "HealthProber"    │
                     │  alarm() every 10 s               │
                     │  get_info + get_last_block_header │
                     │  EMA latency, tip agreement       │
                     │  writes snapshot → KV + DO state  │
                     └───────────────────────────────────┘

 Billing (separate box, never on the request path):
   monero-wallet-rpc (view-only) ── watches subaddresses ── "billing" service
   ── XMR402 invoice API ── provisions tenant in TenantDO + KV
```

**What is deliberately absent in v1:** the Rust routing tier, Tor upstreams, the R2 block archive, the public status-page product, PagerDuty, Stripe, Bot Fight Mode, "speculative execution", any 99.99% SLA.

---

## 3. Request path specification

### 3.1 Authentication

| Item | Specification |
|---|---|
| Primary credential | Path token: `https://rpc.<domain>/v1/<token>/json_rpc` where `<token>` = `sub_` + base58(32 random bytes) (256-bit entropy, generated with `crypto.getRandomValues`). |
| Alternative credential | HTTP Basic auth on the bare path (`/v1/json_rpc`) with username = tenant id, password = token. Works with `--daemon-login user:pass` in CLI/GUI wallets. Same token, no second secret. |
| Storage of truth | `TenantDO` (one Durable Object per tenant, keyed by tenant id). Holds `{status, tier, valid_until, token_hash, prev_token_hash, prev_token_grace_until, daily_quota_used, quota_reset_at}`. |
| Edge lookup | KV key `tok:<sha256(token)>` → `{tenant_id, tier, valid_until, status}`. KV is a **read cache**; every provisioning/renewal/rotation writes KV *and* DO. Worker additionally caches the KV result in isolate memory for 30 s. |
| Token comparison | Compare hashes, never raw tokens. Never write raw tokens to KV, DO, logs, or error messages. |
| Consistency window | KV propagation is ≤60 s. Consequence: a revoked/expired tenant may be served for up to 60 s. Accepted for v1 and documented (Ops doc §5). Provisioning latency is hidden by having the billing service write KV first and return the URL only after a read-back succeeds from the same colo. |
| Rotation | `POST /v1/<token>/_gateway/rotate` returns a new token; the old one remains valid for a 24 h grace window (`prev_token_hash`), then is deleted. |
| Rejections | Unknown token → 401. Expired / suspended → 403 with JSON body `{error:{code:-32001,message:"subscription expired"}}` so wallets show a readable reason. |

### 3.2 Rate limiting

Two layers so that the Durable Object is never on the hot path:

1. **Burst (req/s):** isolate-local token bucket keyed by tenant id, refilled at `tier.burst_rps`, capacity `2 × burst_rps`. Because Cloudflare runs many isolates per colo, the effective global burst is somewhat higher than the nominal number; this is acceptable and stated in the tier table as "nominal".
2. **Daily quota:** the Worker increments an in-memory counter and flushes it to `TenantDO.consume(n)` every 100 requests or 1 s, whichever first (`ctx.waitUntil`). DO returns `{remaining, reset_at}`; the Worker caches that and locally refuses once `remaining ≤ 0`. Overshoot is bounded by (isolates × 100) requests, which is far below 1% of any paid quota.
3. **Cache hits** do not touch the DO at all; they only decrement the local counters. Quota counts *all* requests, cached or not (that is what the customer buys).
4. Over-limit responses: HTTP 429, `Retry-After`, JSON-RPC error `-32005`.
5. Sovereign tier: quota bookkeeping is sharded across `N = ceil(burst_rps / 100)` DO shards (`TenantDO:<id>:<shard>`); v1 ships the sharding code path but only Sovereign tenants use it.

### 3.3 Method classification and per-method policy

This table is the single source of truth. It lives in code as `src/methods.ts` and is rendered into the docs from there.

| Method (JSON-RPC unless noted) | Class | Cache rule | Quorum rule | Timeout / node | Notes |
|---|---|---|---|---|---|
| `get_block`, `get_block_header_by_height`, `get_block_header_by_hash`, `get_block_headers_range` | IMMUTABLE | Cache 30 d **only if** requested height ≤ `quorum_tip − 10`. Cache key includes block hash returned by the node; any reorg deeper than 10 is handled by the prober's *invalidate-on-reorg* path (§3.5). Requests above the safety line → SWR class. | Height/hash must match quorum tip chain (validated by hash chain at prober) | 3 s | Range requests are split at the safety line. |
| `/get_transactions` (legacy, POST) | IMMUTABLE-CONDITIONAL | Cache 30 d per tx hash **only** for txs with `block_height ≤ quorum_tip − 10`. Mempool / young txs → PASSTHROUGH. Split batches. | Single node on quorum tip | 5 s | Cache is per-tx-hash, not per request body, so batches are reassembled at the edge. |
| `/get_outs.bin`, `get_output_distribution`, `get_output_histogram` | IMMUTABLE-CONDITIONAL | Cache 24 h if all requested indices belong to blocks ≤ tip − 10 (checked via cached distribution); else PASSTHROUGH | Single node on quorum tip | 10 s | Used in ring construction; correctness > hit rate. |
| `get_info`, `get_height` (JSON-RPC and legacy), `get_last_block_header`, `get_fee_estimate`, `hard_fork_info`, `get_version` | SWR | `Cache-Control: max-age=1, stale-while-revalidate=5, stale-if-error=15` via `caches.default` + in-isolate single-flight (coalesce concurrent misses). Node-specific fields (`incoming_connections_count`, `outgoing_connections_count`, `white_peerlist_size`, `update_available`, `start_time`) are **normalised** (replaced by gateway-wide values or omitted) so responses are node-independent. | Serve only from a node whose last probe height ≥ `quorum_tip − 1` | 1.5 s | Staleness bound: ≤6 s normal, ≤15 s during upstream error. Published as such. |
| `/get_blocks.bin`, `/get_blocks_by_height.bin`, `/get_hashes.bin` (epee binary) | PASSTHROUGH-STREAM | No cache. Response streamed body-through (no buffering in Worker). | Route to the healthiest **full** node on quorum tip (node-c is pruned: allowed only if request has `prune=true`) | 60 s, idle-timeout 15 s | Wallet sync path. Largest bandwidth consumer; metered separately (bytes) for capacity planning. |
| `get_transaction_pool`, `get_transaction_pool_hashes(.bin)`, `get_transaction_pool_stats` | PASSTHROUGH | None | Single node; response is annotated `X-Gateway-Node: <a|b|c>` | 3 s | Mempool is per-node by nature. |
| `/send_raw_transaction`, `send_raw_transaction`, `relay_tx` | BROADCAST | None | Fan out to **all** healthy nodes in parallel. Return success if ≥1 node returns `status: OK`; body includes `X-Gateway-Relayed: k/n`. If all reject, return the first node's error verbatim. | 5 s each, overall 6 s | `do_not_relay` honoured. Retries: none (tx is idempotent on-chain; client may resubmit). |
| `check_tx_key`, `check_tx_proof`, `check_spend_proof`, `check_reserve_proof` | — | — | — | — | **Not daemon methods** (wallet-rpc). Return `-32601 method not found` with a hint. |
| `/is_key_image_spent` | PASSTHROUGH | None (spent status changes with the mempool) | Single node on quorum tip | 3 s | Restricted-safe; used by wallets during sync. |
| `get_alt_blocks_hashes`, `get_bans`, `set_bans`, `flush_txpool`, `set_log_*`, `start_mining`, `stop_mining`, `mining_status`, `sync_info`, `get_peer_list`, `get_connections`, `update`, `pop_blocks`, `prune_blockchain` | ADMIN / DENY | — | — | — | Denied (403 / `-32601`). Nodes also run `--restricted-rpc`, so this is defence in depth. |
| Any unknown method | DENY | — | — | — | Allow-list only. |

**Quorum tip** = the highest height reported by a majority (≥2 of 3) of nodes whose `top_block_hash` agrees at that height, as computed by the prober (§3.5). If no majority exists, the gateway enters **degraded** mode: SWR/IMMUTABLE classes are served from the node with the highest height, cache writes for IMMUTABLE are suspended, and an incident is opened (Ops doc §7).

### 3.4 Dispatch and failover

- Node ranking = healthy nodes sorted by `(on_quorum_tip desc, ema_latency asc)`. The Worker reads the ranking from the in-isolate copy of the health snapshot (refreshed from KV every 10 s; KV lag is acceptable because the prober also writes the snapshot into a `GatewayState` DO that the Worker consults if the KV copy is older than 30 s).
- Read requests go to rank 1. On connection error, 5xx, or timeout, retry once on rank 2. No third attempt (bounded latency).
- Connection to nodes: `fetch()` to `https://node-<x>.<internal-domain>` fronted by Cloudflare Tunnel, with a Cloudflare Access service token in headers so nodes are unreachable without it. `monerod` binds RPC to `127.0.0.1:18081` only; `cloudflared` runs on the same host.
- Requests carry no client IP, no `X-Forwarded-For`, no `CF-Connecting-IP` to nodes (headers stripped by allow-list).

### 3.5 Health prober (Durable Object alarm loop)

```
class HealthProber extends DurableObject {
  alarm():  for each node in parallel:
              t0; get_info (timeout 2 s); get_last_block_header
              record rtt, height, top_block_hash, synchronized, busy_syncing, status
            compute quorum_tip, per-node on_tip, ema_latency (alpha 0.3)
            detect reorg: if quorum top_block_hash at height h != last snapshot hash at h
              → for depth d = 1..20: if hash(h-d) changed, purge cache for heights > h-d
                (cache purge = bump the `epoch` prefix in IMMUTABLE cache keys; cheap)
            write snapshot → this.state.storage, KV "health:snapshot", GatewayState DO
            setAlarm(now + 10 s)
}
```

- Runs in one DO; a Cron Trigger (1 min) exists only to *re-arm* the alarm if it ever dies.
- Snapshot schema is versioned; the Worker refuses snapshots older than 60 s and falls back to "all nodes healthy, round-robin" plus a loud metric.

### 3.6 Logging policy (replaces "zero-log")

| Data | Retained? | Where / how long |
|---|---|---|
| Request path (contains token) | **Never.** Logpush is not enabled; Workers `console.log` never receives the URL. The Worker only logs `sha256(token)[:8]` as a tenant handle in error paths. | — |
| Client IP | Not written by the gateway. Cloudflare's own edge metadata is outside our control and disclosed as such in the privacy page. | — |
| Per-request records | No. | — |
| Aggregate metrics | Yes: counts, latency histograms, cache hit ratio, per-tenant quota usage, per-method counts. Tenant id is included in quota metrics (needed for billing) but never with IP or payload. | Workers Analytics Engine / Prometheus, 90 d |
| Error samples | Sampled (1%) error bodies with token hash prefix, method, upstream status. | 7 d |
| Node-side | `monerod` log level 0; `cloudflared` access logs off. Nodes see only the Cloudflare Tunnel origin, never client IPs. | — |

Marketing phrase to use: **"No application-level request logging, no accounts, no KYC."** Not "zero-log", not "zero-knowledge".

---

## 4. Node infrastructure

| Item | Spec |
|---|---|
| Count | 3 in v1 (2 full + 1 pruned), 3 different providers **and** ASNs. Adding a 4th (second pruned) is the first scale step. |
| Sizing | Full node: 8 vCPU / 32 GB RAM / ≥1 TB NVMe. Pruned: 4–8 vCPU / 16 GB / ≥400 GB NVMe. Chain is ~215–235 GB full, ~75–95 GB pruned as of mid-2026 and grows a few GB/month, so 1 TB leaves ~3 years of headroom. |
| Provider guidance | Hetzner dedicated (auction boxes with NVMe, roughly €45–70/mo) or new AX line (~€97/mo after the June-2026 increase); OVH Eco/Rise; Vultr bare metal or a high-IOPS VPS for the pruned node. Avoid two nodes at one provider even in different DCs. |
| `monerod` flags | `--restricted-rpc --rpc-bind-ip 127.0.0.1 --rpc-bind-port 18081 --confirm-external-bind=0 --rpc-ssl disabled --out-peers 32 --in-peers 64 --db-sync-mode safe --max-concurrency 4 --log-level 0 --enable-dns-blocklist --ban-list <ban list>`; pruned node adds `--prune-blockchain`. Optional: `--zmq-pub tcp://127.0.0.1:18083` for future mempool telemetry. |
| Process supervision | systemd units for `monerod` and `cloudflared`; `Restart=always`; a local `node-agent` (small Go/Python) that exposes `/healthz` (checks `monerod` RPC liveness + disk free + `synchronized`) for the prober and rotates nothing. |
| Access | SSH via key + Cloudflare Access or Tailscale only; no public inbound ports except the Monero P2P port (18080). |
| Provisioning | Ansible playbook `infra/ansible/monero-node.yml`: OS hardening, monerod install (pinned version + GPG verify), cloudflared, node-agent, unattended security upgrades, disk alerts. Initial sync from a **verified snapshot** of our own node-a LMDB (rsync over WireGuard) to bring a new node up in hours rather than days. |
| Backups | Nightly LMDB snapshot of node-a to R2 (`monerod` supports export via `monero-blockchain-export`; alternatively rsync while stopped in a 5-minute maintenance window on the *pruned* node only). Purpose: fast rebuild, not data safety (the chain is public). |

---

## 5. Billing and provisioning service

Runs on a small separate VPS ("billing box"), never on the request path. Ships as `services/billing/` (TypeScript/Node or Rust; pick TypeScript to share types with the Worker).

Components: `monero-wallet-rpc` (view-only wallet, spend key offline), `billing-api` (HTTP), Postgres or SQLite for invoices and tenants, a Cloudflare API client to write KV and call `TenantDO` via an internal Worker route protected by a service token.

Provisioning sequence:

```
Client (web form or XMR402 agent)                Billing API                  wallet-rpc         Edge (KV + TenantDO)
  │  POST /invoices {tier, months}                    │                             │                    │
  │ ────────────────────────────────────────────────▶ │  create_address (subaddr)   │                    │
  │                                                   │ ───────────────────────────▶│                    │
  │ ◀──── {invoice_id, address, amount_xmr,           │ ◀───────────────────────────│                    │
  │        expires_at, xmr402 headers}                │                             │                    │
  │  pays on-chain                                    │  poll get_transfers (10 s)  │                    │
  │                                                   │ ───────────────────────────▶│                    │
  │                                                   │  state: seen(0-conf) → confirmed(10 conf)        │
  │                                                   │  on confirmed: create/extend tenant             │
  │                                                   │  ─────────────── put KV tok:<hash>; DO.provision ─▶
  │  GET /invoices/{id}  (or webhook / XMR402 402→200)│  read-back KV from same colo, then respond       │
  │ ◀──── {status: active, rpc_url, valid_until}      │                             │                    │
```

Rules: price is quoted in XMR at invoice time, locked for 30 min; underpayment by <2% is accepted, otherwise the invoice stays open and shows the remaining amount; renewals reuse the tenant's persistent subaddress and apply `valid_until = max(valid_until, now) + months`; Free tier is provisioned instantly without an invoice; no device fingerprinting or per-person cap is attempted (no KYC means Free-tier abuse is limited by quota, not identity — see Ops doc §3.1 for the trial fallback). XMR402: the billing API implements the 402 challenge/receipt flow for agents, backed by the same invoice table, so "XMR402" is a *payment rail*, not a tier feature. Stripe is out of v1.

0-conf provisioning is **not** done for paid tiers; 10 confirmations (~20 min) is the activation point, with the invoice page showing live confirmation count. This keeps the gateway's own billing consistent with the 0-conf risk guidance we give customers.

---

## 6. Repository layout

```
monero-rpc-gateway/
├── apps/edge/                 Hono Worker (TypeScript, wrangler)
│   ├── src/index.ts           router: /v1/:token/*, /v1/* (basic-auth)
│   ├── src/auth.ts            token parse, hash, KV/DO lookup, isolate cache
│   ├── src/ratelimit.ts       local token bucket + batched DO sync
│   ├── src/methods.ts         THE method policy table (§3.3)
│   ├── src/cache.ts           immutable + SWR helpers, epoch keys, single-flight
│   ├── src/dispatch.ts        ranking, retry-once, header allow-list, streaming
│   ├── src/broadcast.ts       send_raw_transaction fan-out
│   ├── src/do/TenantDO.ts     quota, token hashes, validity
│   ├── src/do/HealthProber.ts alarm loop, quorum, reorg detection
│   ├── src/do/GatewayState.ts latest health snapshot (strongly consistent read)
│   ├── src/metrics.ts         Analytics Engine writes
│   ├── test/                  vitest + miniflare; fixtures of real monerod responses
│   └── wrangler.toml
├── services/billing/          invoice API, wallet-rpc watcher, XMR402 endpoints, provisioning client
├── services/node-agent/       /healthz, disk/sync checks (runs on each node)
├── infra/ansible/             node provisioning, hardening, cloudflared, systemd units
├── infra/cloudflare/          terraform: zone, WAF rules, tunnel, access policies, KV/DO/R2 bindings
├── docs/                      this plan, ops doc, API reference (generated from methods.ts)
└── tools/loadtest/            k6 scripts: wallet-sync replay, get_info storm, tx broadcast
```

---

## 7. Milestones and schedule

Assumes one senior full-stack engineer plus one part-time infra/Monero engineer. Weeks are calendar weeks starting the week of **2026-09-07**.

| # | Milestone | Weeks | Deliverables | Exit criteria |
|---|---|---|---|---|
| M0 | Reset the docs and the repo | 1 | Retire the old doc; commit this plan and the ops doc; repo skeleton; CI (lint, typecheck, vitest); Cloudflare zone + Terraform baseline with **Bot Fight Mode off**, WAF rule set, DDoS defaults. | `wrangler deploy` of a hello-world Worker behind `rpc.<domain>`; Terraform plan clean. |
| M1 | Node mesh | 1–3 | 3 nodes provisioned via Ansible on 3 providers; `monerod` synced (full/full/pruned); cloudflared tunnels; node-agent `/healthz`; Access service tokens. | All 3 nodes reachable from a Worker via tunnel only; direct public RPC refused; `get_info` p50 < 80 ms from edge. |
| M2 | Edge core | 2–4 | Auth (path + Basic), TenantDO, KV cache, rate limiting (local bucket + batched DO), method policy table with DENY/PASSTHROUGH/STREAM, dispatch with retry-once, header stripping, metrics. No caching yet. | monero-wallet-cli syncs a fresh wallet end-to-end through the gateway; Feather + Cake connect; 429 behaviour verified under k6; DO request count on a 10k-request cache-hit run is 0. |
| M3 | Health, quorum, caching | 4–6 | HealthProber DO alarm loop; quorum tip; degraded mode; reorg epoch purge; SWR cache for consensus state with `get_info` normalisation; IMMUTABLE cache with tip − 10 rule; per-tx `get_transactions` cache. | Kill one node → no failed client requests (retry-once path) and ranking updates ≤ 20 s. Simulated reorg (restart node with alt chain fixture) purges cache within one probe interval. Cache hit ratio on a replayed KYC.RIP traffic sample ≥ 60%. |
| M4 | Broadcast + wallet paths | 5–6 | `send_raw_transaction` fan-out with `X-Gateway-Relayed`; `get_blocks.bin` streaming to full nodes; pruned-node routing rule; mempool endpoints with node annotation. | A tx submitted while node-a is partitioned still reaches the network via b/c. A 500-block `get_blocks.bin` completes with Worker CPU < 10 ms (streaming, not buffering). |
| M5 | Billing and self-serve | 6–8 | Billing box; view-only wallet-rpc; invoice API; renewal; token rotation endpoint; XMR402 402-flow; minimal web page (invoice, status, docs). Free tier auto-provision. | Pay a Pro invoice on stagenet → URL live within 60 s of 10th confirmation; renewal extends `valid_until` correctly; rotation grace window works. |
| M6 | Dogfood and hardening | 8–10 | KYC.RIP and Ripley/XMR402 migrated as tenants 1 and 2; load test to 3× their observed peak; chaos tests (node loss, tunnel loss, DO eviction, KV lag); security review of token handling; cost report from real Cloudflare bill. | 14 consecutive days ≥ 99.5% measured availability; cost/1M requests measured and entered in Ops doc §9; go/no-go for public Pro launch. |
| — | **Public launch (Free + Pro + Business)** | 10 | Website, API docs generated from `methods.ts`, ToS/privacy page, support inbox. | — |

**Phase 2 (post-launch, sequenced by customer pull, not by the diagram):**

1. Tor bridge: `tor` + `haproxy` on a fourth box behind a tunnel; Tor upstream pool as Tier 3 failover with 8 s timeouts; optional `.onion` *ingress* for the gateway itself (separate from Cloudflare).
2. Public status page: static site (Cloudflare Pages or GitHub Pages) fed by the prober snapshot; 30/90-day uptime; webhooks for Business tenants. No 99.999% SLO claim.
3. R2 cold-range accelerator for `get_blocks.bin`: only if node bandwidth or IOPS becomes the bottleneck; requires an epee response assembler and a finality rule (export at tip − 720). Treat as its own design doc.
4. Sovereign tier: dedicated node pair per tenant, sharded quota DOs, custom SLA.
5. Stripe / fiat: only when a specific enterprise customer requires an invoice in fiat.
6. Rust or Wasm hot path: only if Worker CPU time becomes a measured cost driver.

---

## 8. Testing and acceptance

| Layer | What | Tooling |
|---|---|---|
| Unit | Method classification, token parsing/hashing, bucket maths, quorum computation, reorg detection, `get_info` normalisation | vitest with recorded `monerod` fixtures (mainnet + stagenet) |
| Integration | Worker against 3 stagenet nodes in Docker (miniflare + `monerod --stagenet`) | GitHub Actions job, nightly |
| Compatibility matrix | monero-wallet-cli, monero-wallet-rpc (as a *client*), Feather, Cake, Monerujo (via `--daemon-address`, path and Basic-auth forms), `monero-lws`, Python `monero` lib, KYC.RIP backend, Ripley agent | Manual checklist per release + scripted where possible |
| Load | k6: get_info storm 2,000 rps; wallet-sync replay 20 concurrent wallets; mixed tenant profile at 3× dogfood peak | Reported as p50/p95/p99, cache hit %, DO req/1k, CPU ms/req |
| Chaos | Stop `monerod`; stop `cloudflared`; introduce 2 s latency on one node; fork one node onto a stale snapshot; evict DO; delay KV writes | Scripted via Ansible + `tc`, run before each release |
| Security | Token never appears in any log sink (grep Logpush-off config, Analytics Engine schema, error samples); header allow-list; admin methods denied; `--restricted-rpc` verified on every node; dependency audit | Checklist + automated grep in CI |

**Definition of done for v1:** all M0–M6 exit criteria met; the tier table in the Ops doc matches `wrangler.toml` tier config byte-for-byte (checked by a CI test); measured cost per 1M requests recorded; two dogfood tenants live for 14 days.

---

## 9. Cost model (line items, not a rounded total)

Prices from Cloudflare's published Workers/DO/KV/R2 rates (September 2026) and current Hetzner pricing after the June-2026 adjustment. Scenario: **100 M edge requests/month**, 60% cache-hit, 3 ms average CPU per request, quota sync every 100 miss-requests, 20 paying tenants.

| Line | Basis | Monthly |
|---|---|---|
| Workers Paid base | flat | $5.00 |
| Workers requests | (100 M − 10 M incl.) × $0.30/M | $27.00 |
| Workers CPU | 300 M ms − 30 M incl. = 270 M × $0.02/M | $5.40 |
| Durable Objects requests | quota syncs 0.4 M + prober 0.26 M + auth misses ~1 M ≈ 1.7 M − 1 M incl. × $0.15/M | ~$0.10 |
| DO duration | prober DO resident ~24/7 at 128 MB ≈ 330 k GB-s (within 400 k incl.) | $0.00 |
| KV reads/writes | auth read-through mostly isolate-cached; ≤ 10 M reads incl.; writes < 1 M incl. | $0.00 |
| R2 | v1: backups only, ~250 GB × $0.015 | $3.75 |
| Analytics Engine / metrics | included on paid plan at this volume | $0.00 |
| **Cloudflare subtotal** | | **≈ $41** |
| node-a full (Hetzner dedicated auction, NVMe) | ~€60 | ~$65 |
| node-b full (OVH / equivalent) | ~€70 | ~$75 |
| node-c pruned (Vultr / high-IOPS VPS) | | ~$45 |
| Billing box + wallet-rpc | small VPS | ~$10 |
| Domain, DNS, misc | | ~$5 |
| **Infrastructure subtotal** | | **≈ $200** |
| **Total v1 run-rate** | | **≈ $240 / month** |

Sensitivity: every additional 100 M edge requests adds ≈ $35 (requests + CPU). A fourth node adds ≈ $50–75. The old "$77 / 98% margin" figure is retired; margin is computed in the Ops doc from these lines against the reconciled tier table.

Capacity ceiling for the 3-node mesh (to be replaced by measured numbers at M6): light JSON-RPC ≈ 300–500 rps sustained per full node before p99 degrades; `get_blocks.bin` ≈ 20–30 concurrent syncing wallets per node before disk IOPS is the limit. That is the input to the quota table in the Ops doc, not the other way round.

---

## 10. Risks and mitigations

| Risk | Mitigation in this plan |
|---|---|
| Cloudflare as single vendor on the request path | Accepted for v1 and disclosed; Business SLA capped at 99.9% (Ops doc §4). Phase 2 adds `.onion` ingress as a Cloudflare-independent path. |
| KV lag serves expired tenants ≤ 60 s | Bounded, documented, and harmless to correctness (only over-serves). |
| Deep reorg (> 10 blocks) poisons immutable cache | Prober checks 20 blocks back and purges by epoch; residual risk documented; Monero deep reorgs are historically extremely rare. |
| Shared upstream fault (all 3 nodes on same bad peer set) | Different providers/ASNs, different seed nodes, ban lists; prober compares against a public reference height (e.g. two well-known explorers) as an *advisory* signal only, never for routing. |
| Wallet sync traffic saturates node disks | Meter bytes per tenant; Business quota includes a bytes/day soft cap; R2 accelerator is the phase-2 answer. |
| Token leakage via customer-side logs | Rotation endpoint, Basic-auth alternative, documentation; not a gateway-side control. |
| Free tier abuse | Quota only; no identity. If abused, Free becomes a 7-day trial provisioned through the invoice flow with amount 0. |
| Billing wallet compromise | View-only wallet on the billing box; spend key offline; sweep schedule in Ops doc §6. |

---

## 11. Decisions (closed 2026-09-04)

1. **Brand and domain:** mnr, at `mnr.network`. "Monero RPC Gateway" is the descriptor of the Stage 1 product, not its name; the offering is sold as mnr's paid tier with an SLA.
2. **Providers for node-b and node-c:** OVH and Vultr, as in the §2 diagram, giving three ASNs with Hetzner for node-a. Revisit only if an NVMe IOPS benchmark on the chosen box fails the LMDB sync test; price alone does not reopen this.
3. **Free tier:** survives launch as a permanent tier, not a trial. It is the Stage 0 product, the funnel to Pro, and the reason the public-node rules exist.
4. **Business SLA:** 99.9%, as this plan proposes. 99.95% is not credible with three nodes and one edge.
5. **Basic-auth tenant id:** derived from the token, the 8-character prefix of its SHA-256 (the same handle used in error samples and the `token` CLI). No second identifier to store or leak; the username field is free-form for wallets that require one.

---

*Sources for pricing facts used in §4 and §9: [Cloudflare Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/), [Monero blockchain size 2026 (Monerica)](https://blog.monerica.com/articles/monero-blockchain-size), [Hetzner price adjustment June 2026](https://docs.hetzner.com/general/infrastructure-and-availability/price-adjustment/).*
