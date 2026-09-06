#!/usr/bin/env bash
# Update mnr-relay on this box from a GitHub release, checksum verified.
#
#   sudo ./update.sh            # latest release
#   sudo ./update.sh v0.1.12    # that release (with or without the v)
#   sudo ./update.sh --rollback # put the previous binary back and restart
#   sudo ./update.sh --dry-run  # download and verify only, install nothing
#
# What it does: fetch the tarball and SHA256SUMS for the target, verify,
# unpack, ask the new binary for its version, keep the current binary as
# mnr-relay.prev, install, restart the service, and print the version the
# running relay reports on its own feed. Same paths as deploy/roles/relay.
set -euo pipefail

REPO="${MNR_REPO:-mnrnetwork/mnr}"
BIN="${MNR_BIN:-/usr/local/bin/mnr-relay}"
SERVICE="${MNR_SERVICE:-mnr-relay}"
LISTEN="${MNR_LISTEN:-127.0.0.1:18089}"
TARGET="${MNR_TARGET:-$(uname -m)-unknown-linux-gnu}"
WORK="${MNR_WORK:-/var/lib/mnr/releases}"

say() { printf '%s\n' "$*"; }
die() { printf 'update: %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"

mode=install
want=""
for arg in "$@"; do
  case "$arg" in
    --rollback) mode=rollback ;;
    --dry-run) mode=dry ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    -*) die "unknown option $arg" ;;
    *) want="$arg" ;;
  esac
done

restart_and_report() {
  systemctl restart "$SERVICE"
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    sleep 1
    if v=$(curl -sf --max-time 3 "http://$LISTEN/upstreams.json" | jq -r '.relay.version // empty' 2>/dev/null) && [ -n "$v" ]; then
      say "running: mnr-relay $v ($(systemctl is-active "$SERVICE"))"
      return 0
    fi
  done
  say "service is $(systemctl is-active "$SERVICE") but the feed did not answer within 10 s:" >&2
  journalctl -u "$SERVICE" -n 20 --no-pager >&2
  return 1
}

if [ "$mode" = rollback ]; then
  [ -x "$BIN.prev" ] || die "no $BIN.prev to roll back to"
  say "rolling back to: $("$BIN.prev" --version)"
  cp -f "$BIN" "$BIN.rolledback"
  install -m 0755 "$BIN.prev" "$BIN"
  restart_and_report
  exit 0
fi

command -v jq >/dev/null || die "jq is required (apt install jq)"

if [ -z "$want" ]; then
  want=$(curl -sf --max-time 15 "https://api.github.com/repos/$REPO/releases/latest" | jq -r .tag_name)
  [ -n "$want" ] && [ "$want" != null ] || die "cannot read the latest release tag from GitHub"
fi
case "$want" in v*) tag="$want" ;; *) tag="v$want" ;; esac

current="unknown"
[ -x "$BIN" ] && current=$("$BIN" --version 2>/dev/null | awk '{print $2}' | cut -d+ -f1 || true)
if [ "$current" = "${tag#v}" ] && [ "$mode" != dry ]; then
  say "already on mnr-relay $current; nothing to do (use --rollback or name another version)"
  exit 0
fi

base="https://github.com/$REPO/releases/download/$tag"
file="mnr-relay-$tag-$TARGET.tar.gz"
mkdir -p "$WORK"
cd "$WORK"
say "fetching $tag for $TARGET"
curl -sfL --max-time 120 -o "$file" "$base/$file" || die "no asset $file in release $tag"
curl -sfL --max-time 30 -o "SHA256SUMS.$tag" "$base/SHA256SUMS" || die "no SHA256SUMS in release $tag"
grep " $file\$" "SHA256SUMS.$tag" | sha256sum -c --quiet - || die "checksum mismatch for $file"
say "checksum ok"

dir="mnr-relay-$tag-$TARGET"
rm -rf "$dir"
tar xzf "$file"
new="$dir/mnr-relay"
[ -x "$new" ] || new=$(find "$dir" -type f -name mnr-relay | head -1)
[ -n "$new" ] && [ -x "$new" ] || die "tarball has no mnr-relay binary"
say "new: $("$new" --version)"
say "current: ${current}"

if [ "$mode" = dry ]; then
  say "dry run: verified, nothing installed"
  exit 0
fi

[ -x "$BIN" ] && cp -f "$BIN" "$BIN.prev"
install -m 0755 "$new" "$BIN"
say "installed $BIN (previous kept as $BIN.prev)"
restart_and_report
# Keep the last three downloads.
ls -1t "$WORK"/mnr-relay-*.tar.gz 2>/dev/null | tail -n +4 | xargs -r rm -f
