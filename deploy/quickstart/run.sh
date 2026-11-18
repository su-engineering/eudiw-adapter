#!/bin/sh
# The eudiw-adapter demo in one command, without cloning or building anything:
#
#   curl -fsSL https://raw.githubusercontent.com/su-engineering/eudiw-adapter/main/deploy/quickstart/run.sh | sh
#
# Needs Docker (with Compose), curl and jq. Downloads the Compose file and its configuration into
# ./eudiw-adapter-quickstart, starts PostgreSQL, Keycloak and the released adapter image, then plays both sides with
# the eudi-dev test wallet. Synthetic keys and credentials only. EUDIW_REF picks another branch or tag;
# EUDIW_BASE_URL another source (CI uses a file:// URL of the checkout).
set -eu
for tool in docker curl jq; do
  command -v "$tool" > /dev/null || { echo "$tool is required"; exit 1; }
done
docker compose version > /dev/null 2>&1 || { echo "Docker Compose v2 is required"; exit 1; }
BASE=${EUDIW_BASE_URL:-https://raw.githubusercontent.com/su-engineering/eudiw-adapter/${EUDIW_REF:-main}}
DIR=${EUDIW_QUICKSTART_DIR:-eudiw-adapter-quickstart}

mkdir -p "$DIR"
cd "$DIR"
echo "Downloading the demo files into $(pwd)"
fetch() { curl -fsSL "$BASE/$1" -o "$2"; }
fetch deploy/quickstart/docker-compose.yml docker-compose.yml
fetch deploy/quickstart/tenants.json tenants.json
fetch deploy/compose/generate-keys.sh generate-keys.sh
fetch deploy/compose/wallet.sh wallet.sh
fetch deploy/compose/config/keycloak-realm.json keycloak-realm.json

echo "Starting PostgreSQL, Keycloak and the adapter (the first start pulls the images)"
docker compose up -d --quiet-pull keygen postgres keycloak adapter
ready=""
for _ in $(seq 1 120); do
  kc=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:8081/realms/demo/.well-known/openid-configuration || true)
  ad=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:9000/health/ready || true)
  if [ "$kc" = "200" ] && [ "$ad" = "200" ]; then ready=yes; break; fi
  sleep 2
done
[ -n "$ready" ] || { echo "services did not become ready; see: cd $DIR && docker compose logs"; exit 1; }

TOKEN=$(curl -sf -d grant_type=client_credentials -d client_id=demo-portal -d client_secret=demo-only-secret \
  http://localhost:8081/realms/demo/protocol/openid-connect/token | jq -r .access_token)
session() {
  curl -sf -H "Authorization: Bearer $TOKEN" -H "Idempotency-Key: quickstart-$1-$(date +%s)" \
    -H 'Content-Type: application/json' -d "{\"policy_id\":\"$2\",\"mode\":\"cross_device\"}" \
    http://localhost:8080/v1/verification-sessions
}

echo
echo "1. Your backend asks the adapter to check 'over 18' and gets a link for the wallet:"
SESSION=$(session sdjwt age-over-18)
echo "$SESSION" | jq '{id, status, launch_uri: .wallet_launch.launch_uri}'
ID=$(echo "$SESSION" | jq -r .id)

echo "2. The wallet (eudi-dev, HAIP mode) fetches the signed request and presents an SD-JWT VC"
docker compose run --rm wallet "$(echo "$SESSION" | jq -r .wallet_launch.launch_uri)" > /dev/null 2>&1

echo "3. The backend fetches the result once. The credential also holds a name; only the requested claim comes back:"
RESULT=$(curl -sf -H "Authorization: Bearer $TOKEN" "http://localhost:8080/v1/verification-sessions/$ID/result")
echo "$RESULT" | jq '{status, claims, credential_evidence}'
echo "$RESULT" | jq -e '.claims == {"age_over_18": true}' > /dev/null || { echo "unexpected result"; exit 1; }

echo "4. A credential from an issuer the policy does not trust is rejected:"
SESSION=$(session untrusted age-over-18)
ID=$(echo "$SESSION" | jq -r .id)
docker compose run --rm wallet "$(echo "$SESSION" | jq -r .wallet_launch.launch_uri)" untrusted > /dev/null 2>&1 || true
STATUS=$(curl -sf -H "Authorization: Bearer $TOKEN" "http://localhost:8080/v1/verification-sessions/$ID")
echo "$STATUS" | jq '{status, reason}'
echo "$STATUS" | jq -e '.status == "rejected"' > /dev/null || { echo "expected a rejection"; exit 1; }

echo "5. The same check with an ISO mdoc PID:"
SESSION=$(session mdoc age-over-18-mdoc)
ID=$(echo "$SESSION" | jq -r .id)
docker compose run --rm wallet "$(echo "$SESSION" | jq -r .wallet_launch.launch_uri)" mdoc > /dev/null 2>&1
RESULT=$(curl -sf -H "Authorization: Bearer $TOKEN" "http://localhost:8080/v1/verification-sessions/$ID/result")
echo "$RESULT" | jq '{status, claims}'
echo "$RESULT" | jq -e '.claims == {"age_over_18": true}' > /dev/null || { echo "unexpected mdoc result"; exit 1; }

echo
echo "Done. The adapter's management API is on http://localhost:8080, Keycloak on http://localhost:8081."
echo "To stop it and delete its data: cd $DIR && docker compose down --volumes"
