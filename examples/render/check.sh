#!/bin/sh
# Renders the example page in a real browser against the Compose demo (deploy/compose/demo.sh must be running):
# decodes the QR code as drawn on screen, checks the vendored font is in use and that the page reaches its verified
# state when the test wallet answers. Screenshots land in $OUT_DIR (default: a temporary directory).
set -eu
cd "$(dirname "$0")"
command -v zbarimg >/dev/null || { echo "zbarimg (zbar-tools) is required"; exit 1; }
PLAYWRIGHT_IMAGE=mcr.microsoft.com/playwright:v1.56.1-noble
OUT_DIR=${OUT_DIR:-$(mktemp -d)}
mkdir -p "$OUT_DIR"
OUT_DIR=$(cd "$OUT_DIR" && pwd)
rm -f "$OUT_DIR/launch.txt"

PORT=3002 node ../node/server.mjs > "$OUT_DIR/backend.log" 2>&1 &
backend=$!
trap 'kill $backend 2>/dev/null || true; docker rm -f eudiw-render >/dev/null 2>&1 || true' EXIT
for _ in $(seq 1 30); do curl -sf -o /dev/null http://localhost:3002/ && break; sleep 1; done

# Linux runners share the host network; Docker Desktop reaches the host by name.
if [ "$(uname)" = Linux ]; then network="--network host"; base=http://localhost:3002/
else network=""; base=http://host.docker.internal:3002/; fi
# shellcheck disable=SC2086
docker run -d --name eudiw-render $network -e BASE_URL=$base -e OUT_DIR=/out -v "$OUT_DIR:/out" \
  -v "$PWD/check.mjs:/work/check.mjs:ro" -w /work "$PLAYWRIGHT_IMAGE" \
  sh -c 'npm init -y >/dev/null && npm i -s playwright@1.56.1 >/dev/null 2>&1 && node check.mjs' > /dev/null

for _ in $(seq 1 120); do [ -s "$OUT_DIR/launch.txt" ] && break; sleep 1; done
[ -s "$OUT_DIR/launch.txt" ] || { docker logs eudiw-render; echo "the page did not show a request"; exit 1; }
decoded=$(zbarimg --quiet --raw "$OUT_DIR/qr.png")
[ "$decoded" = "$(cat "$OUT_DIR/launch.txt")" ] || { echo "the QR code on screen does not decode to the launch URI"; exit 1; }
echo "QR code on screen decodes to the launch URI"

(cd ../../deploy/compose && docker compose run --rm wallet "$(cat "$OUT_DIR/launch.txt")" > /dev/null 2>&1)
status=$(docker wait eudiw-render)
docker logs eudiw-render 2>&1 | tail -5
[ "$status" = 0 ] || exit 1
echo "screenshots in $OUT_DIR"
