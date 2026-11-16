#!/bin/sh
# End-to-end demo: a backend asks the adapter to verify "over 18", a test wallet answers,
# and the backend receives only the age_over_18 claim.
set -eu
cd "$(dirname "$0")"
command -v curl >/dev/null || { echo "curl is required"; exit 1; }
command -v jq >/dev/null || { echo "jq is required"; exit 1; }

if [ ! -d ../../adapter-verifier-service/target/quarkus-app ]; then
  echo "Building the service..."
  (cd ../.. && ./mvnw -q -B -pl adapter-verifier-service -am package -DskipTests)
fi

docker compose up -d --build keygen postgres keycloak adapter

echo "Waiting for Keycloak and the adapter..."
ready=""
for _ in $(seq 1 120); do
  kc=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:8081/realms/demo/.well-known/openid-configuration || true)
  ad=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:9000/health/ready || true)
  if [ "$kc" = "200" ] && [ "$ad" = "200" ]; then ready=yes; break; fi
  sleep 2
done
[ -n "$ready" ] || { echo "services did not become ready; see: docker compose logs"; exit 1; }

echo "1. The portal backend gets an access token (OAuth client credentials)"
TOKEN=$(curl -sf -d grant_type=client_credentials -d client_id=demo-portal -d client_secret=demo-only-secret \
  http://localhost:8081/realms/demo/protocol/openid-connect/token | jq -r .access_token)

echo "2. It starts a verification session for policy age-over-18"
SESSION=$(curl -sf -H "Authorization: Bearer $TOKEN" -H "Idempotency-Key: demo-$(date +%s)" \
  -H 'Content-Type: application/json' -d '{"policy_id":"age-over-18","mode":"cross_device"}' \
  http://localhost:8080/v1/verification-sessions)
echo "$SESSION" | jq .
ID=$(echo "$SESSION" | jq -r .id)
LAUNCH=$(echo "$SESSION" | jq -r .wallet_launch.launch_uri)

echo "3. The wallet scans the QR code and presents its credential"
docker compose run --rm wallet "$LAUNCH"

echo "4. The backend polls the session"
curl -sf -H "Authorization: Bearer $TOKEN" "http://localhost:8080/v1/verification-sessions/$ID" | jq .

echo "5. The backend fetches the result once. Only the requested claim is present:"
RESULT=$(curl -sf -H "Authorization: Bearer $TOKEN" "http://localhost:8080/v1/verification-sessions/$ID/result")
echo "$RESULT" | jq .
echo "$RESULT" | jq -e '.claims == {"age_over_18": true}' > /dev/null || { echo "unexpected result"; exit 1; }

echo "6. A credential from an issuer the policy does not trust is rejected"
SESSION=$(curl -sf -H "Authorization: Bearer $TOKEN" -H "Idempotency-Key: demo-untrusted-$(date +%s)" \
  -H 'Content-Type: application/json' -d '{"policy_id":"age-over-18","mode":"cross_device"}' \
  http://localhost:8080/v1/verification-sessions)
ID=$(echo "$SESSION" | jq -r .id)
docker compose run --rm wallet "$(echo "$SESSION" | jq -r .wallet_launch.launch_uri)" untrusted || true
STATUS=$(curl -sf -H "Authorization: Bearer $TOKEN" "http://localhost:8080/v1/verification-sessions/$ID")
echo "$STATUS" | jq .
echo "$STATUS" | jq -e '.status == "rejected" and .result_available == false' > /dev/null \
  || { echo "expected the untrusted credential to be rejected"; exit 1; }

echo "Done. To stop and delete the demo data: docker compose down --volumes"
