#!/bin/sh
# Generates synthetic demo key material. Every key and certificate here is for the local demo only.
set -eu
OUT=${1:-/keys}
mkdir -p "$OUT"
cd "$OUT"
# The demo client's webhook secret (Standard Webhooks whsec_ form).
[ -f webhook-secret ] || { echo "whsec_$(openssl rand -base64 32)" > webhook-secret && chmod 644 webhook-secret; }
# Wallet login (ADR-018): the ID token key, the subject key and Keycloak's client secret at the provider (the
# same synthetic secret is in keycloak-shop-realm.json). Created here, before the early exit, so older demo volumes
# get them too.
[ -f oidc-id-token-key.pem ] || { openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out oidc-id-token-key.pem 2> /dev/null && chmod 644 oidc-id-token-key.pem; }
[ -f oidc-subject-key ] || { openssl rand -base64 32 > oidc-subject-key && chmod 644 oidc-subject-key; }
[ -f oidc-broker-secret ] || { echo "demo-only-broker-secret-0123456789abcdef" > oidc-broker-secret && chmod 644 oidc-broker-secret; }
if [ -f done ]; then
  echo "demo keys already present"
  exit 0
fi

ca() { # name subject
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1-key.pem"
  openssl req -x509 -new -key "$1-key.pem" -subj "$2" -days 3650 -out "$1.pem" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
}
leaf() { # name subject ca san
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1-key.pem"
  openssl req -new -key "$1-key.pem" -subj "$2" -out "$1.csr"
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n%s\n' "$4" > "$1.ext"
  openssl x509 -req -in "$1.csr" -CA "$3.pem" -CAkey "$3-key.pem" -CAcreateserial -days 825 -out "$1.pem" -extfile "$1.ext"
  rm -f "$1.csr" "$1.ext"
}

ca issuer-root "/CN=Demo Issuer Root (synthetic)"
leaf issuer "/CN=Demo Issuer (synthetic)" issuer-root "subjectAltName=DNS:issuer.demo.example"
ca verifier-root "/CN=Demo Relying Party Root (synthetic)"
leaf verifier "/CN=Demo Verifier (synthetic)" verifier-root ""

# A synthetic ETSI TS 119 602 PID providers list (JSON, compact JAdES with RS256) that names the issuer root.
# The adapter trusts the demo issuer only through this signed list.
b64url() { base64 | tr -d '\n=' | tr '/+' '_-'; }
der64() { openssl x509 -in "$1" -outform DER | base64 | tr -d '\n'; }
openssl req -x509 -newkey rsa:2048 -nodes -keyout list-signer-key.pem -out list-signer.pem -days 825 \
  -subj "/CN=Demo List Signer (synthetic)/O=Demo Operator/C=EU" -addext "keyUsage=critical,digitalSignature"
ISSUED=$(date -u +%Y-%m-%dT%H:%M:%SZ)
NEXT=$(date -u -d "@$(( $(date +%s) + 90 * 86400 ))" +%Y-%m-%dT%H:%M:%SZ)
HEADER=$(printf '{"alg":"RS256","x5c":["%s"]}' "$(der64 list-signer.pem)" | b64url)
PAYLOAD=$(printf '{"LoTE":{"ListAndSchemeInformation":{"LoTEVersionIdentifier":1,"LoTESequenceNumber":1,"LoTEType":"http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList","SchemeOperatorName":[{"lang":"en","value":"Demo Operator"}],"SchemeTerritory":"EU","ListIssueDateTime":"%s","NextUpdate":"%s"},"TrustedEntitiesList":[{"TrustedEntityInformation":{"TEName":[{"lang":"en","value":"Demo Issuer"}],"TEAddress":{},"TEInformationURI":[{"lang":"en","uriValue":"https://issuer.demo.example"}]},"TrustedEntityServices":[{"ServiceInformation":{"ServiceName":[{"lang":"en","value":"PID issuance"}],"ServiceTypeIdentifier":"http://uri.etsi.org/19602/SvcType/PID/Issuance","ServiceDigitalIdentity":{"X509Certificates":[{"val":"%s"}]}}}]}]}}' \
  "$ISSUED" "$NEXT" "$(der64 issuer-root.pem)" | b64url)
SIGNATURE=$(printf '%s.%s' "$HEADER" "$PAYLOAD" | openssl dgst -sha256 -sign list-signer-key.pem | b64url)
printf '%s.%s.%s' "$HEADER" "$PAYLOAD" "$SIGNATURE" > pid-list.jwt

openssl rand -base64 32 > data-key
chmod 644 ./*.pem data-key pid-list.jwt
touch done
echo "demo keys generated in $OUT"
