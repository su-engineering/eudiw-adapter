#!/bin/sh
# Generates synthetic demo key material. Every key and certificate here is for the local demo only.
set -eu
OUT=${1:-/keys}
mkdir -p "$OUT"
cd "$OUT"
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

openssl rand -base64 32 > data-key
chmod 644 ./*.pem data-key
touch done
echo "demo keys generated in $OUT"
