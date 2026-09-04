# deploy

Ansible for the relayer VPS and the owned node (`docs/stage0-mvp-plan.md`
§6, §7 column B). Inventory and secrets live in the private `internal` repo
(`internal/deploy/inventory.yml`, vault), never here; `inventory.example.yml`
shows the shape.

```bash
pip install ansible-core && ansible-galaxy collection install community.general
ansible-playbook -i ../../internal/deploy/inventory.yml site.yml --ask-vault-pass
```

## What it sets up

**Every box** (`common`): unattended security upgrades, ufw default-deny with
rate-limited SSH, journald capped at 500 MB / 14 days.

**Owned node** (`node`): `monerod` from the official release, `--public-node`,
the **restricted** RPC on the public port and the unrestricted RPC on loopback
only (rule 2 and plan §3; `confirm-external-bind` so it is explicit), P2P and
the restricted port opened.

**Relayer** (`relay`):
- `mnr-relay` from the GitHub release named by `mnr_release`, SHA-256 checked
  against the release's `SHA256SUMS`, running as a system user on loopback
  with a hardened unit (`ProtectSystem=strict`, private tmp, no new privileges).
- `/etc/mnr/relay.toml` rendered from `relay.toml.j2`; the upstream list, caps,
  opt-outs and price come from the inventory.
- Caddy on 443 for `mnr_domain`, ACME by e-mail, access log discarded,
  `CF-Connecting-IP` forwarded as `X-Forwarded-For` only from Cloudflare's
  ranges (`trusted_proxies cloudflare`). If the domain is not behind
  Cloudflare, set `mnr_client_ip_header` to `X-Forwarded-For` and drop the
  `header_up` line so Caddy's own client address is used.
- Tor with a v3 hidden service on the same relay; the address is printed at
  the end of the play and lives in `/var/lib/tor/mnr/hostname`.
- `monero-wallet-rpc` **view-only** on loopback for invoices. The wallet is
  restored on first run from `mnr_wallet_address` and the vaulted view key;
  the spend key never touches this box.
- Prometheus and node_exporter scraping the relay's private `/metrics`.

## First run and checks

After the play: `curl -s https://<domain>/healthz` (200 once three upstreams
agree, 503 while degraded), `curl -s -X POST https://<domain>/v1/tokens/free`
for a token, then one call through it with a wallet from
`mnr.network/docs/connect-wallets/`. The header chain takes about an hour to
build on mainnet; `mnr_chain_height` in `/metrics` shows progress.

This playbook is syntax-checked in CI; it has not yet run against the real
boxes, which is the ops step that follows (column B, week 1–2).
