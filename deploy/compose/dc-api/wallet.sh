#!/bin/sh
# The eudi-dev wallet server that answers Digital Credentials API requests through eudi-dev's browser extension:
# write the extension (pointed at this server) into /ext for the browser, start the server, which approves every
# presentation without asking. Synthetic credentials signed with the demo issuer key: an SD-JWT VC issued into the
# store before the start, and an mdoc PID issued into the running server, because the server generates its own
# default PID at startup, which replaces an mdoc of the same doctype issued before.
set -eu
CLAIMS='{"age_over_18": true, "given_name": "Erika", "family_name": "Mustermann"}'
mkdir -p /tmp/w
eudi issue sdjwt --wallet --storage file --wallet-dir /tmp/w --key /keys/issuer-key.pem --cert /keys/issuer.pem \
  --iss https://issuer.demo.example --vct https://credentials.demo.example/age --claims "$CLAIMS" > /dev/null
eudi wallet extension /ext --wallet-url http://dc-wallet:8085 > /dev/null
eudi wallet serve --storage file --wallet-dir /tmp/w --listen 0.0.0.0 --port 8085 \
  --base-url http://dc-wallet:8085 --auto-accept --allow-private-networks --haip &
server=$!
for _ in $(seq 1 60); do
  wget -q -O /dev/null http://127.0.0.1:8085/ && break
  sleep 1
done
eudi issue mdoc --wallet --remote http://127.0.0.1:8085 --key /keys/issuer-key.pem --cert /keys/issuer.pem \
  --claims "$CLAIMS" > /dev/null
touch /ext/ready
wait "$server"
