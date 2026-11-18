#!/bin/sh
# Synthetic PKI, adapter configuration and suite configuration for running the OIDF OID4VP 1.0 Final + HAIP
# verifier plan against eudiw-adapter on this machine.
set -eu
cd "$(dirname "$0")"
ca() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1-key.pem" 2>/dev/null
  openssl req -x509 -new -key "$1-key.pem" -subj "$2" -days 30 -out "$1.pem" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"; }
leaf() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1-key.pem" 2>/dev/null
  openssl req -new -key "$1-key.pem" -subj "$2" -out "$1.csr"
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n%s\n' "$4" > "$1.ext"
  openssl x509 -req -in "$1.csr" -CA "$3.pem" -CAkey "$3-key.pem" -set_serial "$(date +%s%N | cut -c1-15)" -days 30 -out "$1.pem" -extfile "$1.ext" 2>/dev/null
  rm -f "$1.csr" "$1.ext"; }
ca issuer-root "/CN=OIDF run issuer root (synthetic)"
leaf issuer "/CN=OIDF suite emulated issuer (synthetic)" issuer-root "subjectAltName=DNS:localhost.emobix.co.uk"
ca rp-root "/CN=OIDF run RP root (synthetic)"
leaf rp "/CN=eudiw-adapter under test (synthetic)" rp-root ""
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out token-key.pem 2>/dev/null
openssl pkey -in token-key.pem -pubout -outform DER | base64 | tr -d '\n' > token-public.b64
openssl rand -base64 32 > data-key
cat > tenants.json <<'JSON'
{"tenants":[{"id":"oidf","verifier":{"private_key_file":"rp-key.pem","certificate_chain_file":"rp.pem"},
 "wallet_invocation":"openid4vp://",
 "clients":[{"client_id":"oidf-portal","policies":["pid"],"completion_uri":"https://portal.example/verification-complete"}],
 "policies":[{"id":"pid",
  "dcql":{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},
          "claims":[{"path":["given_name"]}]}]},
  "output":{"given_name":{"credential":"pid","path":["given_name"]}},
  "trust_anchors_file":"issuer-root.pem","status_policy":"require_valid"}]}]}
JSON
python3 - <<'PY'
import subprocess, base64, json, re
def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b'=').decode()
text = subprocess.run(['openssl','ec','-in','issuer-key.pem','-text','-noout'],capture_output=True,text=True).stdout
def hexblock(name):
    m = re.search(name + r':\s*\n((?:\s+[0-9a-f:]+\n)+)', text)
    return bytes.fromhex(re.sub(r'[\s:]', '', m.group(1)))
priv = hexblock('priv'); pub = hexblock('pub')
priv = priv[-32:].rjust(32, b'\0'); assert pub[0] == 4
der = subprocess.run(['openssl','x509','-in','issuer.pem','-outform','DER'],capture_output=True).stdout
jwk = {"kty":"EC","crv":"P-256","alg":"ES256","d":b64u(priv),"x":b64u(pub[1:33]),"y":b64u(pub[33:65]),
       "x5c":[base64.b64encode(der).decode()]}
rp_root = open('rp-root.pem').read()
json.dump({"alias":"eudiw-adapter","description":"eudiw-adapter local run",
           "credential":{"signing_jwk":jwk},
           "client":{"request_object_trust_anchor_pem":rp_root}}, open('suite-config.json','w'), indent=1)
PY
echo | openssl s_client -connect localhost.emobix.co.uk:8443 -servername localhost.emobix.co.uk 2>/dev/null \
  | openssl x509 > suite-tls.pem
rm -f truststore.jks
"$JAVA_HOME/bin/keytool" -importcert -noprompt -alias suite -file suite-tls.pem -keystore truststore.jks -storepass changeit > /dev/null
echo "setup done"
