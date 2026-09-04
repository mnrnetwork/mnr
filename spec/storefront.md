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
  "docs": "https://mnr.network/docs/connect-wallets/"
}
```

The token is shown once. Nothing links it to whoever asked: issuance is
throttled per client (three per hour) through a key that is a hash of the
client address with a random key that lives only in the relay process, so it
cannot be reversed later and is never written anywhere. A relay-wide daily
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
invoice; a renewal reuses the token's previous one. The price is per month and
set by the operator in XMR (the promise is about nine dollars; there is no
exchange-rate lookup in the relay). An invoice is open for 24 hours. Creation
is throttled like free tokens.

## `GET /v1/invoices/{invoice_id}`

The invoice as above, with `status` moving `pending → paid` or `pending →
expired`, `received_atomic` and `confirmations` updated from the wallet, and
after payment, for a purchase, `token`: the Pro token. For a renewal there is
no token to show; the renewed one simply runs longer.

The invoice id is the only secret. Keep it until the token is in the wallet.

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

## `POST /v1/{token}/rotate`

Answers `{"token": "sub_…", "previous_valid_secs": 86400}`. The new token is
current from now; the old one keeps working for 24 hours so a wallet can be
switched without a gap. A rotated purchase token can no longer be recovered
from its invoice.

## What the relay never has

A client's address (only a per-process hash of it, for throttling), an email,
a name, a payment source (the wallet is view-only and sees only incoming
transfers to its own subaddresses), a raw token at rest, a request log.
