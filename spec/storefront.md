# Storefront API

mnr — an RPC network for Monero. How a client gets a token and how a Pro token
is paid for. Three endpoints on the same host as the RPC, no account, no email,
no request log. Licence: CC-BY 4.0. Status: implemented in `mnr-relay`
(Stage 0); not yet normative.

All answers are JSON with `Cache-Control: no-store` and, for browsers, CORS
limited to the site's origin. Errors are `{"error": "<reason>"}` with 400
(bad request), 404 (unknown invoice or token), 429 (too many requests from
this client), 503 (the relay has no token database, or no wallet for invoices).

## `POST /v1/tokens/free`

Issues a Free token immediately.

```json
{
  "token": "sub_…",
  "tier": "free",
  "allowance_wu": 500000,
  "burst_rps": 5,
  "daemon_address": "https://rpc.mnr.network/v1/<token>",
  "wallet_login": "rpc.mnr.network:443 with username <token>, any password, SSL on",
  "docs": "https://mnr.network/docs/connect-wallets/"
}
```

The token is shown once. Nothing links it to whoever asked: issuance is
throttled per client (three per hour) through a key that is a hash of the
client address with a random key that lives only in the relay process, so it
cannot be reversed later and is never written anywhere. Behind a proxy, the
address is read from a header only when the relay listens on loopback and
the proxy sets that header from a trusted source alone (the deploy playbook
firewalls the origin to Cloudflare's ranges and takes the address from
`CF-Connecting-IP` only on connections from them). A relay-wide daily
ceiling bounds the total.

## `POST /v1/invoices`

Creates a Pro invoice. Body, all optional: `{"months": 1, "renew": "<token>"}`.

```json
{
  "invoice_id": "3f9c…",
  "status": "pending",
  "address": "8…",
  "amount_atomic": 60000000000,
  "amount_xmr": "0.06",
  "months": 1,
  "renewal": false,
  "received_atomic": 0,
  "confirmations": 0,
  "created_at": 1788600000,
  "expires_at": 1788686400,
  "uri": "monero:8…?tx_amount=0.06"
}
```

The address is a fresh subaddress on the relay's **view-only** wallet, one per
invoice; a renewal reuses the token's previous one, which is why only one
invoice per token may be open at a time (a second one would be paid by the
same transfer). Only a current, active **Pro** token can be renewed: a Free
token has nothing to extend and a suspended one stays suspended; an expired
Pro token is exactly what renewal is for, and its new validity runs from the
payment. The price is $9 per month (plan decision 1), billed in XMR at the
rate when the invoice is created, and fixed for that invoice: the amount is
$9 × months ÷ rate, rounded **up** to the next 0.0001 XMR. The rate is the
median of independent public sources (Kraken, CoinGecko, KuCoin, and the
hourly feeds of explorer.xmr.club and monerospace.org), refreshed every ten
minutes; a source more than 15% from the median is dropped and at least two
must remain; a new rate more than 30% from the last accepted one is held
until three consecutive rounds agree; the last accepted rate is persisted and
one older than 24 hours is not used, in which case invoice creation answers
503 `price unavailable` rather than mispricing. The invoice reports
`price_usd`, `rate_usd_per_xmr`, `rate_at` and `rate_sources` so the payer
sees how the amount came about. An operator may instead set a fixed XMR
price (`pro_price_atomic`), in which case no lookups run and those fields
are absent. An invoice is open for 24 hours. Creation is throttled like free
tokens.

## `GET /v1/invoices/{invoice_id}`

The invoice as above, with `status` moving `pending → paid` or `pending →
expired`, `received_atomic` and `confirmations` updated from the wallet, and
after payment, for a purchase, `token`: the Pro token. For a renewal there is
no token to show; the renewed one simply runs longer.

The invoice id is the only secret. Keep it until the token is in the wallet:
the token is shown for seven days after payment, then a leaked id recovers
nothing. Status reads are throttled per client (a few hundred an hour).

### Payment rule

Every 30 seconds the relay reads the wallet's incoming transfers to the
invoice's subaddress. Transfers with at least 10 confirmations, received after
the invoice was created, are summed; when the sum reaches the amount the
invoice is paid. Underpayment stays pending until the rest arrives or the
invoice expires; overpayment is a tip, recorded as an amount only. If the
wallet is unreachable nothing changes: an invoice is never marked paid on an
error.

### The token is derived, not stored

A purchased Pro token is `sub_` + base58 of
`SHA-256(secret ‖ "mnr-invoice-token-v1" ‖ invoice_id)`, where `secret` is
32 random bytes the relay keeps in a file only it can read. The token database
holds the token's hash, as for every token; the raw token exists only in the
answer to the status call, recomputed from the id on demand. Payment activates
it for 30 days × months from the moment of payment.

While an invoice is pending, its status carries `seen_atomic` (what the
wallet has seen for that subaddress at any confirmation depth, pool included),
`received_atomic` (what has the required confirmations) and
`remaining_atomic` / `remaining_xmr` (what is still due), with `confirmations`
being those of the payment that completes the amount: a single transfer that
covers it on its own, else the youngest part of a split payment. A payer who sent too little sees the shortfall
rather than a count that never turns into a token.

## `POST /v1/{token}/rotate`

Answers `{"token": "sub_…", "previous_valid_secs": 86400}`. The new token is
current from now; the old one keeps working for 24 hours so a wallet can be
switched without a gap. A rotated purchase token can no longer be recovered
from its invoice. A renewal invoice that was open when the token was rotated
is still the token's: paying it extends the rotated token, and a second
renewal request from the new token is refused while it is pending. Rotating
twice while an invoice is open drops the link (only one previous hash is
kept); such an invoice expires unpaid after 24 hours and the relay logs the
handle each time the watcher tries it.

## What the relay never has

A client's address (only a per-process hash of it, for throttling), an email,
a name, a payment source (the wallet is view-only and sees only incoming
transfers to its own subaddresses), a raw token at rest, a request log.
