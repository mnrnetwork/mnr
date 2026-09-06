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
- Caddy on 443 for `mnr_domain`, ACME by e-mail, access log discarded. With
  `mnr_behind_cloudflare` (default) 443 is firewalled to Cloudflare's ranges
  (`group_vars/all.yml`, refresh them when Cloudflare does), Caddy trusts
  `CF-Connecting-IP` only from those ranges and passes the result to the relay
  as `X-Forwarded-For`; a direct connection forging the header is throttled by
  its own address. Set `mnr_behind_cloudflare: false` for a bare origin: 443
  opens to everyone and the socket peer is the client.
- Tor with a v3 hidden service on the same relay; the address is printed at
  the end of the play and lives in `/var/lib/tor/mnr/hostname`.
- `monero-wallet-rpc` **view-only** on loopback for invoices, only when
  `mnr_wallet_viewkey` is set. The wallet is restored on first run from
  `mnr_wallet_address` and the vaulted view key; the spend key never touches
  this box. Without it the relay runs Free-only and Pro invoices answer 503;
  add the wallet vars and re-run the play to turn Pro on.
- Prometheus and node_exporter scraping the relay's private `/metrics`.

## Re-admitting an opted-out host

An opt-out is deliberately sticky: it survives restarts (it is in the
database's `opt_out_log`) and the daily check only re-marks on a 200, never
un-marks. To re-admit a host whose operator has changed their mind, remove it
from `opt_out` in the config if it is there, delete its rows with
`sqlite3 /var/lib/mnr/relay.db "DELETE FROM opt_out_log WHERE upstream='<name>'"`,
and restart the relay.

## Back up the invoice secret

`/var/lib/mnr/invoice-secret` (32 bytes, created on the first start) is what
purchase tokens are derived from. Copy it into the vault after the first run.
If it is lost, tokens already issued keep working, but an invoice can no
longer show its token to a customer who did not save it.

## First run and checks

After the play: `curl -s https://<domain>/healthz` (200 once three upstreams
agree, 503 while degraded), `curl -s -X POST https://<domain>/v1/tokens/free`
for a token, then one call through it with a wallet from
`mnr.network/docs/connect-wallets/`. The header chain takes about an hour to
build on mainnet; `mnr_chain_height` in `/metrics` shows progress.

This playbook is syntax-checked in CI; it has not yet run against the real
boxes, which is the ops step that follows (column B, week 1–2).

## Updating the relay by hand

On the relay box, `deploy/update.sh` does what the playbook's binary step
does, without Ansible:

```
sudo ./update.sh            # latest GitHub release
sudo ./update.sh v0.1.12    # a named release
sudo ./update.sh --dry-run  # fetch and verify only
sudo ./update.sh --rollback # previous binary back, restart
```

It verifies the tarball against the release's `SHA256SUMS`, keeps the
running binary as `/usr/local/bin/mnr-relay.prev`, restarts `mnr-relay`
and prints the version the relay reports on its own feed. Copy the script
to the box once (`scp deploy/update.sh <box>:/usr/local/sbin/`); it needs
`curl` and `jq`, both installed by the `common` role. `mnr-relay faults clear`
still needs its own restart afterwards, as before.
