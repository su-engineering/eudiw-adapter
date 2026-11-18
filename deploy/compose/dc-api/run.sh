#!/bin/sh
# The W3C Digital Credentials API in a real browser, against the Compose demo (./demo.sh must have started it):
# Chromium with eudi-dev's DC API extension, answered by an eudi-dev wallet server, on a relying-party page at
# http://localhost:3005 (dc-api/check.mjs). Fails unless:
#   1. an SD-JWT VC presented through navigator.credentials.get() verifies, bound to the page's origin;
#   2. an mdoc PID verifies, its device signature over the OpenID4VPDCAPIHandover session transcript;
#   3. a session created for another registered origin (http://localhost:3006) rejects the presentation the page at
#      :3005 gets (key_binding_audience_mismatch). eudi-dev in debug mode only warns that the page's origin is not
#      in expected_origins, so this checks the adapter's own binding;
#   4. the integration kit works over the API: the Node and Python example pages offer "use a wallet on this
#      device", the <eudiw-request> component calls the API, and the backend relays the response (dc-api/kit.mjs).
set -eu
cd "$(dirname "$0")/.."

docker compose --profile dc-api up -d --wait dc-wallet
browser() { docker compose --profile dc-api run --rm -T "$@" dc-browser < /dev/null; }

echo "1. SD-JWT VC through the Digital Credentials API"
browser
echo "2. ISO mdoc PID through the Digital Credentials API"
browser -e POLICY=age-over-18-mdoc
echo "3. A session for another origin rejects what the page gets"
browser -e ORIGIN=http://localhost:3006 -e EXPECT=rejected -e EXPECT_REASON=key_binding_audience_mismatch

echo "4. The example page and <eudiw-request> over the Digital Credentials API, Node and Python backends"
browser -e SCRIPT=kit.mjs
browser -e SCRIPT=kit.mjs -e BACKEND=python

echo "Digital Credentials API: SD-JWT VC and mdoc verified in Chromium, a presentation for another origin rejected,"
echo "and the example page with <eudiw-request> works over it"
