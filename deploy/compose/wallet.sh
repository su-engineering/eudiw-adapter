#!/bin/sh
# Plays the holder with the eudi-dev test wallet: issue a synthetic credential, then answer the request.
# With "untrusted" as the second argument, the credential is signed by a random key the adapter does not trust.
# With "mdoc" it is an ISO mdoc PID (eu.europa.ec.eudi.pid.1) instead of an SD-JWT VC; with "mdoc-iso" the wallet
# signs the ISO/IEC 18013-7 session transcript instead of the OpenID4VP one, which the adapter must reject.
set -eu
LAUNCH_URI=$1
MODE=${2:-trusted}
mkdir -p /tmp/w
if [ "$MODE" = "untrusted" ]; then
  SIGNER=""
else
  SIGNER="--key /keys/issuer-key.pem --cert /keys/issuer.pem"
fi
if [ "$MODE" = "mdoc" ] || [ "$MODE" = "mdoc-iso" ]; then
  [ "$MODE" = "mdoc-iso" ] && TRANSCRIPT="--session-transcript iso"
  eudi issue mdoc --wallet --storage file --wallet-dir /tmp/w --key /keys/issuer-key.pem \
    --cert /keys/issuer.pem \
    --claims '{"age_over_18": true, "given_name": "Erika", "family_name": "Mustermann"}' > /dev/null
  # shellcheck disable=SC2086
  exec eudi wallet accept --storage file --wallet-dir /tmp/w --haip --auto-accept --no-open ${TRANSCRIPT:-} "$LAUNCH_URI"
fi
# shellcheck disable=SC2086
eudi issue sdjwt --wallet --storage file --wallet-dir /tmp/w $SIGNER \
  --iss https://issuer.demo.example --vct https://credentials.demo.example/age \
  --claims '{"age_over_18": true, "given_name": "Erika", "family_name": "Mustermann"}' > /dev/null
eudi wallet accept --storage file --wallet-dir /tmp/w --haip --auto-accept --no-open "$LAUNCH_URI"
