#!/bin/sh
# Runs walt.id Wallet API 2, a wallet independent of eudi-dev, against the Compose demo (./demo.sh must have
# started it), and fails unless:
#   1. it presents an SD-JWT VC for age-over-18 and the backend receives only age_over_18;
#   2. it presents an ISO mdoc PID, signing the OpenID4VP session transcript with its device key, with the same
#      result;
#   3. a credential signed under a certificate chain the trusted list does not name is rejected
#      (certificate_untrusted);
#   4. a walt.id wallet that does not trust the demo relying-party root refuses the request, so the session stays
#      pending;
#   5. with transaction_data (a payment_card entry), walt.id hashes it into its Key Binding JWT and the result
#      returns it; the eudi-dev wallet, which ignores transaction_data, is rejected (transaction_data_mismatch).
set -eu
cd "$(dirname "$0")/.."
command -v jq >/dev/null || { echo "jq is required"; exit 1; }

docker compose --profile waltid up -d --wait waltid-wallet

TOKEN=$(curl -sf -d grant_type=client_credentials -d client_id=demo-portal -d client_secret=demo-only-secret \
  http://localhost:8081/realms/demo/protocol/openid-connect/token | jq -r .access_token)

session() {
  curl -sf -H "Authorization: Bearer $TOKEN" -H "Idempotency-Key: waltid-$1-$(date +%s)" \
    -H 'Content-Type: application/json' \
    -d "{\"policy_id\":\"${2:-age-over-18}\",\"mode\":\"cross_device\"${3:+,\"transaction_data\":$3}}" \
    http://localhost:8080/v1/verification-sessions
}
status() {
  curl -sf -H "Authorization: Bearer $TOKEN" "http://localhost:8080/v1/verification-sessions/$1"
}

echo "1. walt.id presents an SD-JWT VC"
SESSION=$(session verified)
ID=$(echo "$SESSION" | jq -r .id)
docker compose run --rm waltid-holder "$(echo "$SESSION" | jq -r .wallet_launch.launch_uri)"
RESULT=$(curl -sf -H "Authorization: Bearer $TOKEN" "http://localhost:8080/v1/verification-sessions/$ID/result")
echo "$RESULT" | jq -e '.status == "verified" and .claims == {"age_over_18": true}' > /dev/null \
  || { echo "unexpected result: $RESULT"; exit 1; }

echo "2. walt.id presents an ISO mdoc"
SESSION=$(session mdoc age-over-18-mdoc)
ID=$(echo "$SESSION" | jq -r .id)
docker compose run --rm waltid-holder "$(echo "$SESSION" | jq -r .wallet_launch.launch_uri)" mdoc
RESULT=$(curl -sf -H "Authorization: Bearer $TOKEN" "http://localhost:8080/v1/verification-sessions/$ID/result")
echo "$RESULT" | jq -e '.status == "verified" and .claims == {"age_over_18": true}' > /dev/null \
  || { echo "unexpected mdoc result: $RESULT"; exit 1; }

echo "3. A credential from an untrusted issuer is rejected"
SESSION=$(session untrusted)
ID=$(echo "$SESSION" | jq -r .id)
if docker compose run --rm waltid-holder "$(echo "$SESSION" | jq -r .wallet_launch.launch_uri)" untrusted; then
  echo "the adapter accepted a credential from an untrusted issuer"; exit 1
fi
status "$ID" | jq -e '.status == "rejected" and .reason == "certificate_untrusted" and .result_available == false' > /dev/null \
  || { echo "expected rejected: $(status "$ID")"; exit 1; }

echo "4. A wallet that does not trust the relying-party root refuses the request"
docker compose --profile waltid run -d --rm --name eudiw-waltid-other-root -e TRUST_ANCHOR_FILE=/keys/issuer-root.pem \
  waltid-wallet > /dev/null
trap 'docker rm -f eudiw-waltid-other-root > /dev/null 2>&1 || true' EXIT
ready=""
for _ in $(seq 1 60); do
  if docker exec eudiw-waltid-other-root curl -sf -o /dev/null http://localhost:7006/wallet; then ready=yes; break; fi
  sleep 2
done
[ -n "$ready" ] || { echo "the second walt.id wallet did not start"; exit 1; }
SESSION=$(session other-root)
ID=$(echo "$SESSION" | jq -r .id)
if docker compose run --rm -e WALTID_URL=http://eudiw-waltid-other-root:7006 waltid-holder \
    "$(echo "$SESSION" | jq -r .wallet_launch.launch_uri)" > /dev/null 2>&1; then
  echo "the wallet answered a request from a relying party it does not trust"; exit 1
fi
docker logs eudiw-waltid-other-root 2>&1 | grep -q X509TrustAnchorMismatch \
  || { echo "the wallet failed for another reason than the trust anchor"; docker logs eudiw-waltid-other-root | tail -20; exit 1; }
status "$ID" | jq -e '.status == "pending"' > /dev/null || { echo "expected pending: $(status "$ID")"; exit 1; }

echo "5. Transaction data: walt.id binds it, eudi-dev (which ignores it) is rejected"
PAYMENT='[{"type":"payment_card","credential_ids":["age"],"merchant_name":"Demo Shop","amount":"42.00 EUR"}]'
SESSION=$(session payment age-over-18-payment "$PAYMENT")
ID=$(echo "$SESSION" | jq -r .id)
docker compose run --rm waltid-holder "$(echo "$SESSION" | jq -r .wallet_launch.launch_uri)"
RESULT=$(curl -sf -H "Authorization: Bearer $TOKEN" "http://localhost:8080/v1/verification-sessions/$ID/result")
echo "$RESULT" | jq -e --argjson tx "$PAYMENT" '.status == "verified" and .transaction_data == $tx' > /dev/null \
  || { echo "unexpected transaction data result: $RESULT"; exit 1; }
SESSION=$(session payment-eudi-dev age-over-18-payment "$PAYMENT")
ID=$(echo "$SESSION" | jq -r .id)
docker compose --profile wallet run --rm wallet "$(echo "$SESSION" | jq -r .wallet_launch.launch_uri)" > /dev/null 2>&1 || true
status "$ID" | jq -e '.status == "rejected" and .reason == "transaction_data_mismatch"' > /dev/null \
  || { echo "expected transaction_data_mismatch: $(status "$ID")"; exit 1; }

echo "walt.id Wallet API 2: SD-JWT VC and mdoc verified, untrusted issuer rejected, unknown relying-party root refused by the wallet, transaction data bound"
echo "To stop everything, the walt.id wallet included: docker compose --profile waltid down --volumes"
