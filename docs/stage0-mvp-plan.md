# mnr — Stage 0 MVP Plan
*a verified proxy over public Monero nodes, plus one of our own*

| | |
|---|---|
| **Status** | The MVP. Sits *under* `Monero RPC Gateway - Development Plan v1.md` (Stage 1) and `mnr - Protocol and Development Architecture.md` (Stage 2); those stay as the map. This is the to-do list. |
| **Date** | 2026-09-03 |
| **Team** | Two people: **A** (Rust, the proxy) and **B** (node, ops, upstream curation, storefront page, outreach). |
| **Duration** | 4 weeks to public beta, weeks of **2026-09-14 → 2026-10-11**; 2 more weeks of hardening before charging. |
| **Budget** | ≈ $90/month (one relayer VPS ≈ $20, one owned node ≈ $60, domain/Tor/misc ≈ $10). |
| **Language** | Rust. The same binary becomes `mnr-relay` in Stage 1 and 2; nothing built here is thrown away. |

---

## 1. What Stage 0 is, in one paragraph

A single Rust binary, `mnr-relay`, on one VPS. It accepts Monero daemon RPC at `rpc.mnr.network` (and a `.onion`), authenticates a path token, applies the method policy from the gateway plan, caches what is safe to cache, fans out writes, and forwards everything else to a pool of upstreams. The pool is **public nodes that already serve the community, plus one node we run and list publicly ourselves**. Every answer that can be checked is checked — block and tx hashes, header linkage, height agreement across upstreams — so the proxy is *more* trustworthy than any single public node a wallet would otherwise pick blindly. It says exactly this on its front page. It is free, with a cheap Pro tier for people who want higher limits, and it makes no availability promise, because we do not run most of the nodes.

What it is **not**: not a gateway (no SLA, no owned mesh), not a network (no operator agent, no settlement), not a way to resell other people's nodes at Business prices. Those are Stages 1 and 2, and the gate to each is in §9.

---

## 2. Rules toward public nodes (non-negotiable; they are the ethics of Stage 0)

1. **Disclose.** The front page, the docs and the `User-Agent` say what this is. Upstream list is public at `mnr.network/upstreams` with each node's current status and our request rate to it.
2. **Contribute.** Our own node is a full node, listed on the public node lists, open to the public with the same restricted RPC everyone else offers, and it carries the heaviest traffic class (wallet-sync streams) by preference so public nodes see light calls from us, not floods.
3. **Cap ourselves.** Per-upstream ceilings: 5 rps light calls, 2 concurrent `get_blocks.bin` streams, 10 MB/s. Above that, requests queue or go to our own node. These caps are config, published, and stricter than what most public nodes would tolerate.
4. **Identify.** `User-Agent: mnr-relay/0.x (+https://mnr.network/upstreams)` on every upstream request so an operator can see who we are and how to reach us.
5. **Honour opt-out.** Any node operator who asks is removed within 24 hours; the opt-out list is public. We also check a `/.well-known/mnr-optout` on each upstream host daily so operators can remove themselves without contacting us.
6. **Never pass client identity.** No client IP, no `X-Forwarded-For`, no token, nothing but the RPC body reaches an upstream.
7. **Use restricted RPC only.** The policy table's allow-list is enforced before dispatch; we never call admin methods on anyone's node.

The disclosure paragraph for the front page, verbatim:

> mnr is a verified proxy. Your wallet's requests are forwarded to public Monero nodes run by community members, and to our own public node. We check every block, transaction and header we return against its hash and against several nodes, so you get a better answer than any single node gives — but the nodes are not ours, and we make no uptime promise. We cap our traffic to each public node, identify ourselves to operators, honour opt-outs, and publish the full upstream list. If you need nodes we run ourselves, with an SLA, that is a separate paid service coming later.

---

## 3. Upstream pool

| Aspect | Rule |
|---|---|
| Sources | Seed list curated by B from the well-known public node lists (monero.fail and wallet-maintained lists), clearnet and `.onion`, mainnet only for now. Target: 8–12 clearnet + 3–5 onion at launch. Nodes run by wallet teams or known community members preferred; anonymous VPS nodes allowed but weighted lower. |
| Consent | Not required by convention (these nodes are public), but B emails or messages every operator we can identify in week 1 to say we are doing it, with the opt-out link. Anyone who says no is never added. |
| Our node | Full node, NVMe, `--restricted-rpc --public-node`, listed publicly, reached by the relayer over a private link (WireGuard) *and* used as a public node by everyone else. It is `tier: owned` in config and preferred for streams and tie-breaks. |
| Probing | Every 15 s: `get_info` + `get_last_block_header`, 2 s timeout clearnet, 8 s onion (via the box's local Tor SOCKS). Records RTT (EMA), height, top hash, `synchronized`, restricted-RPC check. |
| Quorum tip | Highest height reported by ≥3 upstreams that agree on the hash at that height. If fewer than 3 agree, degraded mode (serve highest-height *owned* node; cache writes suspended). |
| Ranking | Healthy, on quorum tip, sorted by EMA latency; owned node gets a small bonus; onion nodes serve light calls only. |
| Ejection | Any upstream that fails verification (§4) three times in an hour is removed from rotation for 24 h and the event logged publicly on the upstreams page. |

---

## 4. Verification at Stage 0

Reused from the network doc §3.4, trimmed to what one box can do:

| Data | Check | Cost |
|---|---|---|
| `get_block`, `get_block_header_*` | Recompute block hash from blob; match requested hash or our header chain | Cheap |
| `/get_transactions` | Keccak(tx blob) = txid; height ≤ tip | Cheap |
| Header chain | Built once by majority from upstreams (≈ 280 MB on disk), extended at the tip by agreement; reorg detection → cache epoch bump | One-time sync ≈ hours |
| `get_info`, `get_height`, fee estimate | Majority of ≥3 upstreams; node-specific fields normalised; SWR cache 1/5/15 s | Cheap |
| `/get_outs.bin` | Two-upstream agreement for **Pro** tokens; single upstream (owned node preferred) for Free | Moderate |
| `/get_blocks.bin` | **Not verified** in Stage 0; routed to the owned node first, public nodes second; response header `Mnr-Verify: none` | — |
| Mempool | Not verifiable; header `Mnr-Upstream: <n>` (an opaque number, not the node's URL, so we do not advertise which node saw what) | — |
| `send_raw_transaction` | Fan out to all healthy upstreams; success if ≥1 OK; `Mnr-Relayed: k/n` | — |

Verified request counts and fault counts per upstream are the numbers on the public upstreams page. This is the feature: "we caught node X serving a wrong header on Tuesday, here's the proof" is what makes people trust the proxy over a raw public node.

---

## 5. Method policy, caching, auth, limits

- **Method policy:** the gateway plan §3.3 table as-is, compiled into `mnr-core::policy`.
- **Cache:** in-memory (`moka`, 1 GB cap) for SWR and immutable-below-tip−10; on-disk store deferred to Stage 1.
- **Auth:** path token `/v1/<token>/…` and Basic auth alternative, 256-bit, hashed at rest in SQLite; rotation endpoint with 24 h grace. Free tokens are issued instantly from the site; no email.
- **Limits:** in-process token bucket per token; daily WU quota in SQLite.

| | Free | Pro |
|---|---|---|
| Price | $0 | **$9/month**, XMR invoice |
| Allowance | 500k WU/month | 10M WU/month |
| Burst | 5 rps | 25 rps |
| `get_outs` | single upstream | two-upstream agreement |
| Streams | owned node when available, else public, 1 concurrent | owned node preferred, 3 concurrent |
| Promise | none | none — "we will tell you what we verified" is the whole promise |

$9 is deliberately a supporter price. It pays the two boxes at ~15 subscribers, and it tests the only question Stage 0 needs to answer: *will anyone pay for verification and convenience over nodes they could use for free?*

- **Payments:** view-only `monero-wallet-rpc` on the relayer box, subaddress per invoice, activation at 10 confirmations, renewals extend `valid_until`. XMR402 flow deferred to Stage 1 unless Ripley wants it in week 4.
- **Logging:** no request logs; aggregate metrics only; token hash prefix in error samples. The gateway plan §3.6 policy applies.

---

## 6. Architecture (one binary, one box)

```
clients ──▶ rpc.mnr.network (TLS, axum) ──┐
clients ──▶ <onion>.onion (local tor)  ───┤
                                          ▼
                     mnr-relay ──── auth (SQLite) ── limits ── policy ── cache ── verify
                                          │
                       ┌──────────────────┼───────────────────────┐
                       ▼                  ▼                       ▼
              owned node (WireGuard)   public clearnet nodes   public .onion nodes (via tor SOCKS)
              full, --public-node      HTTPS/HTTP, capped      light calls only, 8 s timeout

background: prober (15 s) · header-chain sync · cache epoch on reorg · invoice watcher (wallet-rpc) · metrics (/metrics, Prometheus)
```

Crates: `mnr-core` (policy, hash, verify, header chain — the same crate the network doc specifies) and `mnr-relay` (everything else). No agent, no directory, no settlement. Config is one TOML file; upstreams are a list with `kind: owned | public`, `transport: https | http | onion`, and per-node caps.

Relayer box: 4 vCPU / 8 GB / 80 GB NVMe (header chain + SQLite + cache). Owned node: 8 vCPU / 32 GB / 1 TB NVMe on a different provider, in the sizing of the gateway plan §4.

---

## 7. Four-week build

| Week | A — Rust | B — node, ops, product |
|---|---|---|
| **1** (Sep 14) | Repo, CI, `mnr-core`: policy table, block/tx hashing with mainnet fixtures, header-chain store, verify functions with tests. | Order owned node and relayer VPS; start `monerod` sync from a trusted snapshot; WireGuard; Tor on relayer box; curate upstream list; write to identifiable operators; register domain + `.onion`; **reserve** `mnr`, `mnr-core`, `mnr-relay`, `mnr-client`, `mnr-agent` on crates.io and the `mnr` handle on npm and PyPI (the name is defended by use, see `TRADEMARK.md`). |
| **2** | `mnr-relay`: axum ingress, token auth, limits, policy dispatch, prober, ranking, quorum tip, degraded mode, passthrough and broadcast. First end-to-end: CLI wallet syncs through the proxy against public nodes. | Owned node public and listed; monitoring (disk, sync, RTT); upstreams page (static, fed by relayer JSON); front page with the disclosure text; opt-out mechanism and `.well-known` check. |
| **3** | Verification wired into the request path (block/tx/header, majority for consensus state, `get_outs` agreement for Pro); SWR + immutable cache with epoch bump on reorg; `Mnr-*` headers; metrics. | Invoice flow: view-only wallet-rpc, subaddress per invoice, activation, renewals; Free-token issuance page; docs: connect CLI/GUI/Feather/Cake/Monerujo; run compatibility checks. |
| **4** | Hardening: per-upstream caps and queues, ejection logic, onion upstream path, fuzz smoke on parsers, load test (500 rps light, 10 concurrent syncs). | **Public beta** (Free only): announce in community channels with the disclosure; dogfood KYC.RIP and Ripley on Pro tokens; watch upstream operators' reactions and honour any opt-outs same day. |
| **5–6** | Fix what the beta finds; header-chain reorg drill; token rotation endpoint. | Turn on Pro ($9); publish first weekly "what we verified / what we caught" post; collect the three numbers in §9. |

**Status (2026-09-05).** Column A is shipped through week 4 and the weeks 5–6 drill: weeks 1–2 in `3907de6..6f5234c`, week 3 (verification, cache, majority, agreement, metrics) in `bf5625f..5a8a131`, week 4 (streamed bodies with caps, queueing, opt-out check, ejection lifecycle, load test) in `db7b11d..7551b07`, the storefront, deploy playbook, release workflow and the reorg/ejection drill after that. Column B code (storefront, token page, wallet docs, Ansible) is shipped; the human items remain: operator notices, the relayer VPS, the `.onion`, the wallet compatibility matrix, the announcement. The owned node is `node.kyc.rip` (see §10 item 7).

Exit criteria for "MVP shipped": a stock CLI wallet and Feather sync from scratch through `rpc.mnr.network`; injected wrong-header test from a fake upstream produces an ejection and a public log entry; owned node listed on public node lists and serving outsiders; no request logs anywhere; upstream caps demonstrably enforced under load; at least 10 identified upstream operators informed, zero unresolved opt-outs.

---

## 8. Risks specific to Stage 0

| Risk | Response |
|---|---|
| A public-node operator objects publicly ("they're reselling our node") | The disclosure, the caps, the identification header, the opt-out, and our own public node are the answer; respond within the day, remove on request, link the upstreams page. This is the scenario the reviews warned about, and the rules in §2 exist so the answer is already true when it is asked. |
| Public nodes are inconsistent (pruned vs full, old versions, odd `get_info`) | Verification and normalisation handle data; the prober's restricted-RPC and version checks handle capability; anything weird is ejected and logged rather than papered over. |
| Public nodes rate-limit or ban us | Caps keep us under typical limits; the owned node absorbs overflow; ejection is automatic. If it becomes common, that is the signal to move to Stage 1. |
| Owned node becomes the real workhorse and public nodes decorative | Acceptable — it means demand exists and Stage 1 (two more nodes) is justified. Track the share of WU served by the owned node; above 60% for 4 weeks is a Stage 1 trigger. |
| Nobody pays $9 | Then the verification layer is a public good and the business is Stage 1 with owned nodes and SLAs sold to backends — the code is unchanged. |
| Header-chain sync from public nodes is poisoned | Built by majority of ≥5 upstreams including our own node; spot-checked against two block explorers as an advisory signal; any disagreement halts the build and alerts. |

---

## 9. Gates to the next stages

Collect three numbers weekly from week 6: **paying Pro tokens**, **WU served per day** (split owned/public), and **backends asking for an SLA** (any client who asks "what uptime do you guarantee?" is a tally mark).

- **Go to Stage 1 (gateway: two more owned nodes, Business tier, SLA credits)** when *either* five backends have asked for an SLA, *or* the owned node serves > 60% of WU for four consecutive weeks, *or* Pro revenue covers two more boxes. The gateway plan is the spec; its M1 starts the day the boxes are ordered.
- **Go to Stage 2 (mnr network: operator agent, settlement, directory)** when *either* three public-node operators ask to be paid or to plug in formally, *or* a partner (wallet, hosting business) wants to run their own relayer on our binary. The network architecture doc is the spec; P1 starts from a working relayer rather than from zero, which removes roughly a quarter of its schedule.
- **Stay at Stage 0** if none of the above within 12 weeks of public beta — in which case the proxy remains a maintained public good at $90/month, and the business question is answered honestly.

---

## 10. Decisions (closed 2026-09-04)

Recorded here so nothing in the code resolves them silently. Changing one is a plan edit, not a code edit.

1. **Pricing:** Pro is $9/month, Free is 500k WU/month. Confirmed; the tier table in §5 is the contract and `mnr-relay` enforces it.
2. **Owned node provider:** a Hetzner dedicated box with NVMe (auction line), per the gateway plan's provider guidance. The relayer VPS goes to a different provider and ASN (Vultr or OVH), so the two boxes never share a failure domain.
3. **`get_outs` for Free:** single upstream, owned node preferred. Two-upstream agreement stays a Pro feature; Free capacity is the reason. Encoded as `Agreement { free: 1, pro: 2 }` in `mnr-core::policy`.
4. **Operator notices:** signed in the project's name, "mnr (mnr.network)", with B's name as the human contact and the opt-out link. Operators should know who to answer to, and the project name is what they will see in the `User-Agent`.
5. **`.onion` upstreams:** week 5, after the public beta. Launch is clearnet upstreams only; the relay already accepts `transport = "onion"` and `tor_socks`, so adding them is a config change once Tor is on the box.
6. **Identity without an entity:** no legal entity for now, possibly ever. The project's identity is `mnr.network` plus the release signing key (`TRADEMARK.md`); licences are AGPL-3.0 (relay, agent), Apache-2.0 (`mnr-core`, `mnr-client`), CC-BY 4.0 (spec), all rights reserved (brand). B reserves the crate and package names in week 1; the domain gets auto-renew, registrar lock, 2FA and a second recovery contact.
7. **Owned node:** `https://node.kyc.rip` (monerod 0.18.5, mainnet, behind Cloudflare) is the owned node, listed as `own-1`. On 2026-09-05 it answered admin methods (`get_connections`, `sync_info`, `/get_transaction_pool`) on its public endpoint, so it runs without `--restricted-rpc`; §3 requires the restricted RPC on the public port and the unrestricted one on loopback only (`deploy/roles/node` sets it up that way). The relay never calls those methods, but anyone else can until it is fixed. Ops item for B, tracked here so it is not forgotten. Also for B: back up `/var/lib/mnr/invoice-secret` into the vault after the relay's first start (purchase tokens are derived from it; see `deploy/README.md`).
