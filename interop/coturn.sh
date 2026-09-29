#!/usr/bin/env bash
# coturn's own test client (turnutils_uclient) against the built node: its -y mode puts both
# ends' allocations on one server and relays between them, which is exactly this node's model.
# Needs coturn installed (apt-get install coturn / brew install coturn). Fails on any loss
# outside -R (which corrupts messages on purpose).
#   cargo build --release && interop/coturn.sh
set -euo pipefail
cd "$(dirname "$0")/.."
KEY=fiahLYMg85YkiFJQ0Xp3Bl0x3pXkUhI4nMU8jj6QRio
PORT=${PORT:-34790}
TURN_SECRET=$KEY TURN_PUBLIC_IP=127.0.0.1 TURN_PORT=$PORT ./target/release/resonance-node 2>/tmp/resonance-coturn.log &
NODE=$!
trap 'kill $NODE 2>/dev/null || true' EXIT
sleep 0.5
fail=0
run() {
  local name=$1; shift
  local out
  out=$(timeout 90 turnutils_uclient -y -c -W "$KEY" -u "ins:$name:p" -m 2 -n 200 -l 170 -z 5 -p "$PORT" "$@" 127.0.0.1 2>&1 || true)
  local total
  total=$(grep -E 'Total lost packets' <<<"$out" | tail -1 || true)
  echo "$name: ${total:-no result}"
  # -R corrupts coturn's own messages, some of them its allocations: all that's asked of the
  # node there is that it survives (checked below).
  [[ "$name" == corrupt ]] && return
  if [[ "$total" != *"Total lost packets 0 "* ]]; then fail=1; fi
}
run channels
run send-indications -s
run padded-channel-data -D
run random-channels -N
run permissions-to-random-ips -G
run corrupt -R
# Still answering after all that.
timeout 10 turnutils_stunclient -p "$PORT" 127.0.0.1 >/dev/null || { echo "the node stopped answering"; fail=1; }
kill -0 $NODE || { echo "the node died"; cat /tmp/resonance-coturn.log; exit 1; }
exit $fail
