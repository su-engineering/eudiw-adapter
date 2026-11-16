#!/bin/sh
# Creates a SoftHSM token for the demo and generates the verifier's request-signing key inside it. The key never
# leaves the token; only its public key is read to issue the certificate. Synthetic, for the local demo only.
set -eu
HSM=/hsm
MODULE=/usr/lib/softhsm/libsofthsm2.so
if [ -f "$HSM/done" ]; then
  echo "demo HSM token already present"
  exit 0
fi
mkdir -p "$HSM/tokens"
printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\n' "$HSM" > "$HSM/softhsm2.conf"
export SOFTHSM2_CONF="$HSM/softhsm2.conf"
softhsm2-util --init-token --free --label demo --pin 1234 --so-pin 5678 > /dev/null
pkcs11-tool --module "$MODULE" --login --pin 1234 --keypairgen --key-type EC:prime256v1 \
  --label verifier --id 01 > /dev/null
pkcs11-tool --module "$MODULE" --read-object --type pubkey --label verifier -o "$HSM/verifier-pub.der" > /dev/null
cd "$HSM"
openssl pkey -pubin -inform DER -in verifier-pub.der -out verifier-pub.pem
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > verifier.ext
openssl x509 -new -subj "/CN=Demo Verifier in SoftHSM (synthetic)" -force_pubkey verifier-pub.pem \
  -CA /keys/verifier-root.pem -CAkey /keys/verifier-root-key.pem -set_serial "$(date +%s)" -days 825 -extfile verifier.ext -out verifier-hsm.pem
openssl x509 -in verifier-hsm.pem -outform DER -out verifier-hsm.der
pkcs11-tool --module "$MODULE" --login --pin 1234 --write-object verifier-hsm.der --type cert \
  --label verifier --id 01 > /dev/null
printf '1234' > pin
rm -f verifier.ext verifier-pub.der verifier-hsm.der
chown -R 10001:10001 "$HSM"
touch done
echo "demo HSM token created; the verifier key is non-extractable"
