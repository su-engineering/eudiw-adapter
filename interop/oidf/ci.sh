#!/bin/sh
# Runs the OpenID Foundation OID4VP 1.0 Final + HAIP verifier test plan against a locally built eudiw-adapter,
# end to end, and fails if any module ends differently from expected.json. Used by CI and runnable on a laptop.
#
# Needs: docker, java 21 (JAVA_HOME), openssl, python3, curl, and the service built
# (./mvnw -pl adapter-verifier-service -am package -DskipTests). Synthetic keys only.
# Output (suite logs, adapter log, results.json) goes to $OUT_DIR, default interop/oidf/out.
set -eu
cd "$(dirname "$0")"
HERE=$(pwd)
OUT_DIR=${OUT_DIR:-$HERE/out}
APP=../../adapter-verifier-service/target/quarkus-app/quarkus-run.jar
PG_PORT=${PG_PORT:-55432}
: "${JAVA_HOME:?set JAVA_HOME to a Java 21 JDK}"
[ -f "$APP" ] || { echo "build the service first: ./mvnw -pl adapter-verifier-service -am package -DskipTests"; exit 1; }
mkdir -p "$OUT_DIR"

cleanup() {
  [ -n "${ADAPTER_PID:-}" ] && kill "$ADAPTER_PID" 2>/dev/null || true
  docker compose -f suite-compose.yml logs --no-color server > "$OUT_DIR/suite-server.log" 2>&1 || true
  docker compose -f suite-compose.yml down -v > /dev/null 2>&1 || true
  docker rm -f eudiw-oidf-postgres > /dev/null 2>&1 || true
}
trap cleanup EXIT

echo "Starting the conformance suite and PostgreSQL"
docker compose -f suite-compose.yml up -d --quiet-pull
docker run -d --rm --name eudiw-oidf-postgres -e POSTGRES_DB=eudiw -e POSTGRES_USER=eudiw \
  -e POSTGRES_PASSWORD=oidf-run-only -p "127.0.0.1:$PG_PORT:5432" postgres:16.10-alpine > /dev/null
ready=""
for _ in $(seq 1 120); do
  if curl -sfk -o /dev/null https://localhost.emobix.co.uk:8443/api/runner/available; then ready=yes; break; fi
  sleep 2
done
[ -n "$ready" ] || { echo "the suite did not start"; exit 1; }

./setup.sh

# The adapter's own TLS certificate. The suite reaches it as host.docker.internal.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -keyout tls-key.pem -out tls.pem \
  -subj "/CN=host.docker.internal" -addext "subjectAltName=DNS:host.docker.internal,DNS:localhost" 2>/dev/null

echo "Starting the adapter on https://localhost:8453"
EUDIW_CONFIG_FILE=$HERE/tenants.json \
EUDIW_PUBLIC_BASE_URL=https://host.docker.internal:8453 \
EUDIW_DATA_KEY=$(cat data-key) \
EUDIW_DB_URL=jdbc:postgresql://127.0.0.1:$PG_PORT/eudiw EUDIW_DB_USER=eudiw EUDIW_DB_PASSWORD=oidf-run-only \
EUDIW_OIDC_AUDIENCE=eudiw-adapter \
EUDIW_PRODUCTION=false EUDIW_EGRESS_ALLOW_PRIVATE_ADDRESSES=true \
EUDIW_MANAGEMENT_HOST=127.0.0.1 \
"$JAVA_HOME/bin/java" \
  -Djavax.net.ssl.trustStore="$HERE/truststore.jks" -Djavax.net.ssl.trustStorePassword=changeit \
  -Djdk.internal.httpclient.disableHostnameVerification=true \
  -Dquarkus.http.port=8452 -Dquarkus.http.ssl-port=8453 -Dquarkus.http.insecure-requests=disabled \
  -Dquarkus.http.ssl.certificate.files="$HERE/tls.pem" -Dquarkus.http.ssl.certificate.key-files="$HERE/tls-key.pem" \
  -Dquarkus.oidc.discovery-enabled=false -Dquarkus.oidc.public-key="$(cat token-public.b64)" \
  -Dquarkus.oidc.token.issuer=https://oidf.local \
  -jar "$APP" > "$OUT_DIR/adapter.log" 2>&1 &
ADAPTER_PID=$!
ready=""
for _ in $(seq 1 90); do
  if curl -sf -o /dev/null http://127.0.0.1:9000/health/ready; then ready=yes; break; fi
  kill -0 "$ADAPTER_PID" 2>/dev/null || break
  sleep 2
done
[ -n "$ready" ] || { echo "the adapter did not start"; tail -50 "$OUT_DIR/adapter.log"; exit 1; }

python3 run.py --check "${EXPECTED:-expected.json}" --logs "$OUT_DIR"
