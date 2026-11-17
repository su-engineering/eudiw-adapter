#!/bin/sh
# Runs each example backend against the Compose demo (deploy/compose/demo.sh must have started it): the backend
# starts a session, the eudi-dev wallet answers the launch URI, the status URL reaches "verified" and the backend
# retrieves only the requested claim, and the adapter's signed webhook reaches the backend. Also checks that the page
# and the component are served.
set -eu
cd "$(dirname "$0")"
command -v jq >/dev/null || { echo "jq is required"; exit 1; }
# The demo client sends webhooks to http://host.docker.internal:3000, so each backend takes port 3000 in turn.
# HOST=0.0.0.0 because on Linux the adapter container reaches the host only on a non-loopback address.
WEBHOOK_SECRET=$(cd ../deploy/compose && docker compose run --rm --no-deps -T --entrypoint cat keygen /keys/webhook-secret)
export WEBHOOK_SECRET HOST=0.0.0.0

check() {
  name=$1 port=$2
  shift 2
  PORT=$port "$@" > "/tmp/eudiw-example-$name.log" 2>&1 &
  pid=$!
  trap 'kill $pid 2>/dev/null || true' EXIT
  for _ in $(seq 1 30); do
    curl -sf -o /dev/null "http://localhost:$port/" && break
    sleep 1
  done
  curl -sf "http://localhost:$port/" | grep -q '<eudiw-request\|eudiw-request.js'
  curl -sf "http://localhost:$port/eudiw/eudiw-request.js" | grep -q "customElements.define('eudiw-request'"
  curl -sf "http://localhost:$port/eudiw/vendor/qrcode.mjs" | grep -q 'export const qrcode'
  curl -sf -o /dev/null "http://localhost:$port/eudiw/fonts/jetbrains-mono-latin-wght-normal.woff2"

  started=$(curl -sf -X POST "http://localhost:$port/verifications")
  launch=$(echo "$started" | jq -r .launch_uri)
  status_url=$(echo "$started" | jq -r .status_url)
  result_url=$(echo "$started" | jq -r .result_url)
  case "$launch" in openid4vp://*) ;; *) echo "$name: unexpected launch URI"; exit 1 ;; esac
  # The browser sees neither the adapter's session id nor its credentials.
  echo "$started" | grep -q 'vrs_' && { echo "$name: adapter session id leaked to the browser"; exit 1; }
  test "$(curl -sf "http://localhost:$port$status_url" | jq -r .status)" = pending

  (cd ../deploy/compose && docker compose run --rm wallet "$launch" > /dev/null 2>&1)

  status=""
  for _ in $(seq 1 20); do
    status=$(curl -sf "http://localhost:$port$status_url" | jq -r .status)
    [ "$status" = verified ] && break
    sleep 1
  done
  test "$status" = verified || { echo "$name: status is $status"; exit 1; }
  # The adapter's signed webhook reaches the backend, which checks the signature and records it.
  webhook=""
  for _ in $(seq 1 30); do
    webhook=$(curl -sf "http://localhost:$port$status_url" \
      | jq -r '[.trace[] | select(.event == "POST /webhooks/eudiw")][0].detail // empty')
    [ -n "$webhook" ] && break
    sleep 1
  done
  test "$webhook" = "verified · signature valid" || { echo "$name: no valid webhook (got '$webhook')"; exit 1; }
  result=$(curl -sf -X POST "http://localhost:$port$result_url")
  echo "$result" | jq -e '.claims == {"age_over_18": true}' > /dev/null
  # The trace shows what the backend did, never claim values.
  echo "$result" | jq -e '[.trace[] | .detail] | all(test("age_over_18|true") | not)' > /dev/null
  # The result can be retrieved once.
  test "$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://localhost:$port$result_url")" = 404
  kill $pid
  wait $pid 2>/dev/null || true
  trap - EXIT
  echo "$name example: verified, webhook signature valid, only age_over_18 returned"
}

check node 3000 node node/server.mjs
check python 3000 python3 python/server.py
