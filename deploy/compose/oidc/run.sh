#!/bin/sh
# Wallet login through Keycloak, against the Compose demo (./demo.sh must have started it). Keycloak's "shop" realm
# has the adapter as an OpenID Connect identity provider (config/keycloak-shop-realm.json); the adapter's tenant
# demo-city is the provider and keycloak-broker its client (config/tenants.json). Fails unless:
#   1. a login from Keycloak's account console reaches the adapter's login page, the eudi-dev wallet presents a
#      synthetic PID, and Keycloak's first-login flow creates an account;
#   2. a second login with the same PID lands on that account without asking for anything;
#   3. Keycloak holds exactly one user linked to the eudi-wallet identity provider, with no email from the wallet.
set -eu
cd "$(dirname "$0")/.."
rm -rf oidc/out && mkdir -p oidc/out

docker compose --profile oidc run --rm -T oidc-browser < /dev/null > oidc/out/result.json &
browser=$!
for n in 1 2; do
  for _ in $(seq 1 120); do
    [ -s "oidc/out/launch-$n" ] && break
    kill -0 "$browser" 2> /dev/null || { echo "the browser stopped before login $n"; cat oidc/out/result.json; exit 1; }
    sleep 1
  done
  [ -s "oidc/out/launch-$n" ] || { echo "no launch URI for login $n"; exit 1; }
  echo "$n. The wallet presents a PID for the login Keycloak started"
  docker compose run --rm -T wallet "$(cat "oidc/out/launch-$n")" pid < /dev/null > "oidc/out/wallet-$n.log" 2>&1 \
    || { echo "the wallet failed:"; cat "oidc/out/wallet-$n.log"; exit 1; }
done
wait "$browser"
cat oidc/out/result.json

ADMIN=$(curl -fsS http://localhost:8081/realms/master/protocol/openid-connect/token \
  -d grant_type=password -d client_id=admin-cli -d username=admin -d password=demo-only-admin | jq -r .access_token)
USERS=$(curl -fsS -H "Authorization: Bearer $ADMIN" "http://localhost:8081/admin/realms/shop/users?briefRepresentation=false")
echo "$USERS" | jq -e 'length == 1' > /dev/null || { echo "expected one user in the shop realm"; echo "$USERS" | jq '[.[] | .username]'; exit 1; }
USER_ID=$(echo "$USERS" | jq -r '.[0].id')
LINKS=$(curl -fsS -H "Authorization: Bearer $ADMIN" "http://localhost:8081/admin/realms/shop/users/$USER_ID/federated-identity")
echo "$LINKS" | jq -e 'length == 1 and .[0].identityProvider == "eudi-wallet"' > /dev/null \
  || { echo "the user is not linked to the eudi-wallet provider: $LINKS"; exit 1; }
jq -e '.logins | length == 2' oidc/out/result.json > /dev/null || { echo "the browser did not finish both logins"; exit 1; }
echo "$USERS" | jq -e '.[0].email == "erika@shop.example" and .[0].firstName == "Erika"' > /dev/null \
  || { echo "the account does not hold the first-login profile: $(echo "$USERS" | jq -c '.[0] | {username, email, firstName}')"; exit 1; }
echo "Wallet login through Keycloak: two logins, one account, linked to the adapter's OpenID Connect provider"
