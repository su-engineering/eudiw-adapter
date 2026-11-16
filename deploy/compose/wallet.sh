#!/bin/sh
# Plays the holder with the eudi-dev test wallet: issue a synthetic credential, then answer the request.
# With "untrusted" as the second argument, the credential is signed by a random key the adapter does not trust.
set -eu
LAUNCH_URI=$1
MODE=${2:-trusted}
mkdir -p /tmp/w
if [ "$MODE" = "untrusted" ]; then
  SIGNER=""
else
  SIGNER="--key /keys/issuer-key.pem --cert /keys/issuer.pem"
fi
# shellcheck disable=SC2086
eudi issue sdjwt --wallet --storage file --wallet-dir /tmp/w $SIGNER \
  --iss https://issuer.demo.example --vct https://credentials.demo.example/age \
  --claims '{"age_over_18": true, "given_name": "Erika", "family_name": "Mustermann"}' > /dev/null
eudi wallet accept --storage file --wallet-dir /tmp/w --haip --auto-accept --no-open "$LAUNCH_URI"
