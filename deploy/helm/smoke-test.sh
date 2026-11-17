#!/bin/sh
# Installs the chart into a local kind cluster with the restricted Pod Security Standard enforced, then starts a
# verification session through the API. Synthetic keys only. Requires docker, kind, kubectl, helm, openssl, curl, jq.
set -eu
cd "$(dirname "$0")/../.."
CLUSTER=${CLUSTER:-eudiw-smoke}
NS=eudiw
IMAGE=eudiw-adapter:smoke
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"; [ -n "${PF:-}" ] && kill "$PF" 2>/dev/null || true' EXIT

[ -d adapter-verifier-service/target/quarkus-app ] || ./mvnw -q -B -ntp -pl adapter-verifier-service -am package -DskipTests
docker build -q -t "$IMAGE" -f adapter-verifier-service/src/main/docker/Dockerfile . > /dev/null
kind get clusters | grep -qx "$CLUSTER" || kind create cluster --name "$CLUSTER" --wait 120s
kind load docker-image "$IMAGE" --name "$CLUSTER"
kubectl config use-context "kind-$CLUSTER" > /dev/null

echo "== PostgreSQL (separate namespace, not under the restricted policy)"
kubectl create namespace eudiw-db --dry-run=client -o yaml | kubectl apply -f - > /dev/null
kubectl -n eudiw-db apply -f - > /dev/null <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata: {name: postgres}
spec:
  selector: {matchLabels: {app: postgres}}
  template:
    metadata: {labels: {app: postgres}}
    spec:
      containers:
        - name: postgres
          image: postgres:16.10-alpine
          env:
            - {name: POSTGRES_DB, value: eudiw}
            - {name: POSTGRES_USER, value: eudiw}
            - {name: POSTGRES_PASSWORD, value: smoke-only-password}
          ports: [{containerPort: 5432}]
          readinessProbe: {exec: {command: [pg_isready, -U, eudiw]}, periodSeconds: 2}
---
apiVersion: v1
kind: Service
metadata: {name: postgres}
spec:
  selector: {app: postgres}
  ports: [{port: 5432}]
YAML
kubectl -n eudiw-db rollout status deploy/postgres --timeout=120s

echo "== Synthetic keys and configuration"
cd "$WORK"
ca() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1-key.pem" 2>/dev/null
  openssl req -x509 -new -key "$1-key.pem" -subj "$2" -days 30 -out "$1.pem" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"; }
ca issuer-root "/CN=Smoke Issuer Root (synthetic)"
ca verifier-root "/CN=Smoke RP Root (synthetic)"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out verifier-key.pem 2>/dev/null
openssl req -new -key verifier-key.pem -subj "/CN=Smoke Verifier (synthetic)" -out verifier.csr
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n' > verifier.ext
openssl x509 -req -in verifier.csr -CA verifier-root.pem -CAkey verifier-root-key.pem -CAcreateserial -days 30 \
  -out verifier.pem -extfile verifier.ext 2>/dev/null
cat > tenants.json <<'JSON'
{"tenants":[{"id":"smoke","verifier":{"private_key_file":"verifier-key.pem","certificate_chain_file":"verifier.pem"},
 "clients":[{"client_id":"smoke-portal","policies":["age-over-18"]}],
 "policies":[{"id":"age-over-18",
  "dcql":{"credentials":[{"id":"age","format":"dc+sd-jwt","meta":{"vct_values":["https://credentials.example/age"]},
          "claims":[{"path":["age_over_18"]}]}]},
  "output":{"age_over_18":{"credential":"age","path":["age_over_18"]}},
  "trust_anchors_file":"issuer-root.pem","status_policy":"reject_known_invalid"}]}]}
JSON
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out token-key.pem 2>/dev/null
PUBLIC=$(openssl pkey -in token-key.pem -pubout -outform DER | base64 | tr -d '\n')

kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f - > /dev/null
kubectl label namespace "$NS" --overwrite pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=latest > /dev/null
kubectl -n "$NS" delete secret eudiw-config eudiw-db eudiw-data-key --ignore-not-found > /dev/null
kubectl -n "$NS" create secret generic eudiw-config --from-file=tenants.json --from-file=verifier-key.pem \
  --from-file=verifier.pem --from-file=issuer-root.pem > /dev/null
kubectl -n "$NS" create secret generic eudiw-db --from-literal=username=eudiw \
  --from-literal=password=smoke-only-password > /dev/null
kubectl -n "$NS" create secret generic eudiw-data-key --from-literal=data-key="$(openssl rand -base64 32)" > /dev/null
cd - > /dev/null

echo "== Install the chart (two replicas, egress restricted to DNS, PostgreSQL and public addresses)"
helm upgrade --install eudiw deploy/helm/eudiw-adapter -n "$NS" --wait --timeout 5m \
  --set networkPolicy.egress.enabled=true \
  --set-json 'networkPolicy.egress.cluster=[{"to":[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"eudiw-db"}}}],"ports":[{"port":5432,"protocol":"TCP"}]}]' \
  --set image.repository=eudiw-adapter --set image.tag=smoke --set image.pullPolicy=Never \
  --set publicBaseUrl=http://localhost:18080 --set production=false \
  --set oidc.audience=eudiw-adapter \
  --set database.url=jdbc:postgresql://postgres.eudiw-db:5432/eudiw --set database.existingSecret=eudiw-db \
  --set dataKey.existingSecret=eudiw-data-key --set config.existingSecret=eudiw-config \
  --set "extraEnv[0].name=QUARKUS_OIDC_PUBLIC_KEY" --set "extraEnv[0].value=$PUBLIC" \
  --set "extraEnv[1].name=QUARKUS_OIDC_DISCOVERY_ENABLED" --set-string "extraEnv[1].value=false" \
  --set "extraEnv[2].name=QUARKUS_OIDC_TOKEN_ISSUER" --set "extraEnv[2].value=https://smoke.example"
kubectl -n "$NS" get pods

echo "== Start a session through the API"
kubectl -n "$NS" port-forward svc/eudiw-eudiw-adapter 18080:8080 > /dev/null 2>&1 &
PF=$!
sleep 3
b64url() { base64 | tr -d '\n=' | tr '/+' '_-'; }
NOW=$(date +%s)
HEADER=$(printf '{"alg":"RS256","typ":"JWT"}' | b64url)
CLAIMS=$(printf '{"iss":"https://smoke.example","aud":"eudiw-adapter","azp":"smoke-portal","scope":"verification:create verification:read","iat":%s,"exp":%s}' "$NOW" "$((NOW + 300))" | b64url)
SIG=$(printf '%s.%s' "$HEADER" "$CLAIMS" | openssl dgst -sha256 -sign "$WORK/token-key.pem" | b64url)
TOKEN="$HEADER.$CLAIMS.$SIG"
SESSION=$(curl -sf -H "Authorization: Bearer $TOKEN" -H "Idempotency-Key: smoke-$NOW" -H 'Content-Type: application/json' \
  -d '{"policy_id":"age-over-18","mode":"cross_device"}' http://localhost:18080/v1/verification-sessions)
echo "$SESSION" | jq -e '.status == "pending" and (.wallet_launch.launch_uri | startswith("openid4vp://"))' > /dev/null
HANDLE=$(echo "$SESSION" | jq -r .wallet_launch.request_uri | sed 's|.*/oid4vp/requests/||')
curl -sf -X POST http://localhost:18080/oid4vp/requests/"$HANDLE" | grep -q '\.'

echo "== Metrics on the management port only"
kubectl -n "$NS" port-forward deploy/eudiw-eudiw-adapter 19000:9000 > /dev/null 2>&1 &
PF2=$!
sleep 3
curl -sf http://localhost:19000/metrics | grep -q 'eudiw_events_total{action="session_created"'
test "$(curl -s -o /dev/null -w '%{http_code}' http://localhost:18080/metrics)" = 404
kill "$PF2" 2>/dev/null || true
echo "Smoke test passed: chart installed under the restricted policy, session created, request object served, metrics scraped."
