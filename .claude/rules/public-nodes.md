# Rules toward public nodes

These are the ethics of Stage 0, copied from `docs/stage0-mvp-plan.md` §2. They are
not tuning knobs. Any code path that talks to an upstream must satisfy all seven.

1. **Disclose.** The front page, the docs and the `User-Agent` say what this is. The
   upstream list is public at `mnr.network/upstreams` with each node's current status
   and our request rate to it.
2. **Contribute.** Our own node is a full node, listed on the public node lists, open
   to the public with the same restricted RPC everyone else offers, and it carries the
   heaviest traffic class (wallet-sync streams) by preference.
3. **Cap ourselves.** Per-upstream ceilings: 5 rps light calls, 2 concurrent
   `get_blocks.bin` streams, 10 MB/s. Above that, requests queue or go to our own node.
   These caps are config, published, and stricter than most public nodes would tolerate.
4. **Identify.** `User-Agent: mnr-relay/0.x (+https://mnr.network/upstreams)` on every
   upstream request.
5. **Honour opt-out.** Any operator who asks is removed within 24 hours; the opt-out
   list is public. Check `/.well-known/mnr-optout` on each upstream host daily.
6. **Never pass client identity.** No client IP, no `X-Forwarded-For`, no token,
   nothing but the RPC body reaches an upstream.
7. **Use restricted RPC only.** The policy allow-list is enforced before dispatch; we
   never call admin methods on anyone's node.

## How this applies to code

- Every upstream HTTP client is constructed in one place and sets the `User-Agent`;
  there is no second client.
- Caps are per-upstream config fields with the defaults above; a missing field means
  the default, never "unlimited".
- Header forwarding to upstreams is an allow-list (`Content-Type`, `Content-Length`,
  `Accept`), not a deny-list.
- Opt-out is a config list plus the daily `.well-known` probe; an opted-out host is
  refused at config load, not just deprioritised.
- When in doubt, prefer the owned node.
