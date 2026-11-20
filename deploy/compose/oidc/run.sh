#!/bin/sh
# Wallet login through the adapter's OpenID Connect provider (ADR-018), against the Compose demo (./demo.sh must have
# started it). The adapter's tenant demo-city is the provider (config/tenants.json), with two clients:
#   - keycloak-broker: Keycloak's "shop" realm has the adapter as an identity provider
#     (config/keycloak-shop-realm.json);
#   - nextcloud: Nextcloud's stock user_oidc app has the adapter as its provider, set up below with occ.
# Chromium logs in twice through each (oidc/check.mjs); the eudi-dev wallet presents a synthetic PID every time, from
# a fresh wallet with a new holder key. Fails unless:
#   1. the first Keycloak login creates an account through Keycloak's first-login flow;
#   2. the second Keycloak login lands on that account without asking for anything;
#   3. Keycloak holds exactly one user, linked to the eudi-wallet identity provider, with the given and family name
#      from the ID token;
#   4. both Nextcloud logins reach the same Nextcloud user, created by user_oidc on the first one.
set -eu
cd "$(dirname "$0")/.."
rm -rf oidc/out && mkdir -p oidc/out

echo "Nextcloud with the adapter as its OpenID Connect provider"
docker compose --profile oidc up -d --wait nextcloud
occ() { docker compose --profile oidc exec -T -u www-data nextcloud php occ "$@" < /dev/null; }
# user_oidc pinned by version and checksum, from Nextcloud's release repository.
USER_OIDC=8.13.0
USER_OIDC_SHA256=6f13fa0477144a6812d8648626c64cee91807d1d0b60ca41424543086b9e2775
docker compose --profile oidc exec -T nextcloud sh -ec "
  [ -d /var/www/html/custom_apps/user_oidc ] && exit 0
  curl -fsSL --retry 5 -o /tmp/user_oidc.tar.gz \
    https://github.com/nextcloud-releases/user_oidc/releases/download/v$USER_OIDC/user_oidc-v$USER_OIDC.tar.gz
  echo '$USER_OIDC_SHA256  /tmp/user_oidc.tar.gz' | sha256sum -c - > /dev/null
  tar -xzf /tmp/user_oidc.tar.gz -C /var/www/html/custom_apps
  chown -R www-data:www-data /var/www/html/custom_apps/user_oidc" < /dev/null
occ app:enable user_oidc > /dev/null
echo "user_oidc $(occ app:getpath user_oidc > /dev/null && occ config:app:get user_oidc installed_version)"
# Nextcloud refuses to fetch from private addresses by default; the adapter is one in this demo.
occ config:system:set allow_local_remote_servers --value true --type boolean > /dev/null
# user_oidc refuses OpenID Connect over plain http unless told otherwise; this demo has no TLS. Never in production.
occ config:app:set user_oidc allow_insecure_http --value=1 --type=boolean --lazy > /dev/null
occ user_oidc:provider eudi-wallet --clientid=nextcloud \
  --clientsecret='demo-only+nextcloud/secret=0123456789abcdef' \
  --discoveryuri=http://adapter:8080/oidc/demo-city/.well-known/openid-configuration > /dev/null

docker compose --profile oidc run --rm -T oidc-browser < /dev/null > oidc/out/result.json &
browser=$!
for n in 1 2 3 4; do
  for _ in $(seq 1 180); do
    [ -s "oidc/out/launch-$n" ] && break
    kill -0 "$browser" 2> /dev/null || { echo "the browser stopped before login $n:"; cat oidc/out/result.json; exit 1; }
    sleep 1
  done
  [ -s "oidc/out/launch-$n" ] || { echo "no launch URI for login $n"; exit 1; }
  echo "$n. The wallet presents a PID for login $n"
  docker compose run --rm -T wallet "$(cat "oidc/out/launch-$n")" pid < /dev/null > "oidc/out/wallet-$n.log" 2>&1 \
    || { echo "the wallet failed:"; cat "oidc/out/wallet-$n.log"; exit 1; }
done
wait "$browser" || { echo "the browser failed:"; cat oidc/out/result.json; exit 1; }
cat oidc/out/result.json

ADMIN=$(curl -fsS http://localhost:8081/realms/master/protocol/openid-connect/token \
  -d grant_type=password -d client_id=admin-cli -d username=admin -d password=demo-only-admin | jq -r .access_token)
USERS=$(curl -fsS -H "Authorization: Bearer $ADMIN" "http://localhost:8081/admin/realms/shop/users?briefRepresentation=false")
echo "$USERS" | jq -e 'length == 1' > /dev/null || { echo "expected one user in the shop realm"; echo "$USERS" | jq '[.[] | .username]'; exit 1; }
USER_ID=$(echo "$USERS" | jq -r '.[0].id')
LINKS=$(curl -fsS -H "Authorization: Bearer $ADMIN" "http://localhost:8081/admin/realms/shop/users/$USER_ID/federated-identity")
echo "$LINKS" | jq -e 'length == 1 and .[0].identityProvider == "eudi-wallet"' > /dev/null \
  || { echo "the user is not linked to the eudi-wallet provider: $LINKS"; exit 1; }
echo "$USERS" | jq -e '.[0].email == "erika@shop.example" and .[0].firstName == "Erika" and .[0].lastName == "Mustermann"' > /dev/null \
  || { echo "the account does not hold the first-login profile: $(echo "$USERS" | jq -c '.[0] | {username, email, firstName, lastName}')"; exit 1; }
jq -e '.logins | length == 4 and .[2].user != null and .[2].user != "admin" and .[2].user == .[3].user' oidc/out/result.json > /dev/null \
  || { echo "the two Nextcloud logins did not reach the same user"; exit 1; }
echo "Wallet login: Keycloak (two logins, one account, linked to the provider) and Nextcloud (two logins, one user)"
