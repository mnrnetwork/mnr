#!/usr/bin/env bash
# The reorg and ejection drill (docs/stage0-mvp-plan.md §7 weeks 5–6).
#
# Four synthetic nodes (examples/injector.rs) behind the real relay binary:
#   1. a cached header, then every node switches to a branch → the relay
#      detects the reorg, bumps the cache epoch, the cached answer is a miss;
#      switching back is a second reorg;
#   2. one node lies about three headers → three faults, ejection, the
#      public feed shows it, clients still get verified answers;
#   3. every node cuts its streams → short reads; honest again → a full
#      stream, so the slots were released.
# Exit status 0 only if every check passed. Needs curl and jq.
set -euo pipefail
cd "$(dirname "$0")/.."

TOK=sub_4k9ZQ2pQ7wq1sDhBfT8zPxT5Y3v7g9jN2mR6cLbVwXyU
RELAY=127.0.0.1:18095
METRICS=127.0.0.1:18096
INJ=(18191 18192 18193 18194)
TMP=$(mktemp -d)
PIDS=()
FAIL=0

cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; rm -rf "$TMP"; }
trap cleanup EXIT

check() { if [ "$2" = "$3" ]; then echo "  ok   $1"; else echo "  FAIL $1: got '$2', want '$3'"; FAIL=1; fi; }
check_ge() { if [ "$2" -ge "$3" ]; then echo "  ok   $1 ($2)"; else echo "  FAIL $1: got $2, want >= $3"; FAIL=1; fi; }
metric() { curl -s "http://$METRICS/metrics" | awk -v n="$1" '$1==n {print $2}'; }
inject() { curl -s -o /dev/null -X POST "http://127.0.0.1:$1/_inject" -H 'content-type: application/json' -d "$2"; }
inject_all() { for p in "${INJ[@]}"; do inject "$p" "$1"; done; }
hdr() { grep -i "^$2:" "$1" | tr -d '\r' | awk '{print $2}'; }
# header_by_height H → writes headers to $TMP/h, prints the Mnr-Verify and Mnr-Cache values
header_by_height() {
  curl -s -D "$TMP/h" -o "$TMP/b" -X POST "http://$RELAY/v1/$TOK/json_rpc" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"get_block_header_by_height\",\"params\":{\"height\":$1}}"
  echo "$(hdr "$TMP/h" mnr-verify) $(hdr "$TMP/h" mnr-cache) $(hdr "$TMP/h" mnr-upstream)"
}
wait_for() { # wait_for "<desc>" <secs> <cmd...> ; passes when cmd prints "1"
  local desc=$1 secs=$2; shift 2
  for _ in $(seq 1 "$secs"); do
    if [ "$("$@" 2>/dev/null)" = "1" ]; then echo "  ok   $desc"; return 0; fi
    sleep 1
  done
  echo "  FAIL $desc (timeout ${secs}s)"; FAIL=1; return 1
}

echo "building…"
cargo build -q --release -p mnr-relay --example injector
cargo build -q --release -p mnr-relay

echo "starting four synthetic nodes and the relay…"
for p in "${INJ[@]}"; do
  ./target/release/examples/injector "127.0.0.1:$p" >"$TMP/inj-$p.log" 2>&1 &
  PIDS+=($!)
done
cat >"$TMP/relay.toml" <<TOML
listen = "$RELAY"
[probe]
interval_secs = 2
min_agree = 3
[chain]
path = "$TMP/headers.mnrh"
[metrics]
listen = "$METRICS"
[[upstreams]]
name = "inj-owned"
url = "http://127.0.0.1:${INJ[0]}"
kind = "owned"
transport = "http"
caps = { rps_light = 500, max_streams = 32, mbps = 200 }
[[upstreams]]
name = "inj-1"
url = "http://127.0.0.1:${INJ[1]}"
kind = "public"
transport = "http"
caps = { rps_light = 100, max_streams = 2, mbps = 50 }
[[upstreams]]
name = "inj-2"
url = "http://127.0.0.1:${INJ[2]}"
kind = "public"
transport = "http"
caps = { rps_light = 100, max_streams = 2, mbps = 50 }
[[upstreams]]
name = "inj-3"
url = "http://127.0.0.1:${INJ[3]}"
kind = "public"
transport = "http"
caps = { rps_light = 100, max_streams = 2, mbps = 50 }
TOML
sleep 1
./target/release/mnr-relay --config "$TMP/relay.toml" --dev-token "$TOK:pro" >"$TMP/relay.log" 2>&1 &
PIDS+=($!)

wait_for "relay healthy (quorum of 3)" 20 sh -c "curl -s -o /dev/null -w '%{http_code}' http://$RELAY/healthz | grep -q 200 && echo 1"
wait_for "header chain built to 300" 30 sh -c "[ \"\$(curl -s http://$METRICS/metrics | awk '\$1==\"mnr_chain_height\"{print \$2}')\" = 300 ] && echo 1"

echo
echo "phase 1: reorg"
read -r v c u <<<"$(header_by_height 250)"
check "header 250 verified against the chain" "$v $c" "chain miss"
read -r v c u <<<"$(header_by_height 250)"
check "header 250 served from cache" "$c" "hit"
EPOCH0=$(metric mnr_chain_epoch)
inject_all '{"mode":"branch","from":280,"id":1}'
wait_for "reorg detected (branch from 280)" 30 sh -c "[ \"\$(curl -s http://$METRICS/metrics | awk '\$1==\"mnr_reorgs_total\"{print \$2}')\" -ge 1 ] && echo 1"
EPOCH1=$(metric mnr_chain_epoch)
check_ge "epoch bumped" "$EPOCH1" "$((EPOCH0 + 1))"
read -r v c u <<<"$(header_by_height 250)"
check "cached header is a miss after the epoch bump" "$c" "miss"
read -r v c u <<<"$(header_by_height 295)"
check "a header on the new branch verifies against the rebuilt chain" "$v" "chain"
inject_all '{"mode":"honest"}'
wait_for "second reorg (back to the canonical chain)" 30 sh -c "[ \"\$(curl -s http://$METRICS/metrics | awk '\$1==\"mnr_reorgs_total\"{print \$2}')\" -ge 2 ] && echo 1"
read -r v c u <<<"$(header_by_height 295)"
check "header 295 verified again after the switch back" "$v $c" "chain miss"

echo
echo "phase 2: ejection"
for h in 200 201 202; do
  inject "${INJ[0]}" "{\"mode\":\"lie_header\",\"height\":$h}"
  read -r v c u <<<"$(header_by_height "$h")"
  check "header $h: liar skipped, verified answer from another node" "$v" "chain"
  if [ "$u" = "0" ]; then echo "  FAIL header $h came from the liar"; FAIL=1; fi
done
inject "${INJ[0]}" '{"mode":"honest"}'
S=$(curl -s "http://$RELAY/upstreams.json")
check "liar ejected" "$(echo "$S" | jq -r '.upstreams[0].ejected')" "true"
check_ge "faults in the public log" "$(echo "$S" | jq -r '.faults | length')" 3
check "faults name the liar" "$(echo "$S" | jq -r '.faults[0].upstream')" "inj-owned"
check "quorum survives with three honest nodes" "$(echo "$S" | jq -r '.degraded')" "false"

echo
echo "phase 3: dropped streams"
inject_all '{"mode":"drop_streams"}'
CURLS=()
for i in 1 2 3; do
  ( curl -s -m 30 -D "$TMP/sh$i" -o "$TMP/s$i" -X POST "http://$RELAY/v1/$TOK/get_blocks.bin" -d '{}' || true ) &
  CURLS+=($!)
done
wait "${CURLS[@]}"
for i in 1 2 3; do
  n=$(stat -f %z "$TMP/s$i" 2>/dev/null || stat -c %s "$TMP/s$i")
  code=$(head -1 "$TMP/sh$i" | awk '{print $2}')
  if [ "$code" = 200 ] && [ "$n" -ge 65536 ] && [ "$n" -lt 2097152 ]; then
    echo "  ok   stream $i started (HTTP 200) and was cut short ($n of 2097152 bytes)"
  else
    echo "  FAIL stream $i: HTTP $code, $n bytes: $(head -c 200 "$TMP/s$i")"; FAIL=1
  fi
done
inject_all '{"mode":"honest"}'
sleep 1
curl -s -m 30 -o "$TMP/full" -D "$TMP/fh" -X POST "http://$RELAY/v1/$TOK/get_blocks.bin" -d '{}' || true
n=$(stat -f %z "$TMP/full" 2>/dev/null || stat -c %s "$TMP/full")
check "a full stream after the slots were released" "$n" "2097152"
check "stream annotated" "$(hdr "$TMP/fh" mnr-verify) $(hdr "$TMP/fh" mnr-cache)" "none bypass"

echo
if [ "$FAIL" = 0 ]; then echo "DRILL PASSED"; else echo "DRILL FAILED (relay log: $TMP/relay.log)"; trap - EXIT; for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done; exit 1; fi
