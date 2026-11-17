# Status list fixtures

Synthetic only. `eudi-dev-statuslist.cwt` is a Status List Token in CWT form served by the independent eudi-dev
wallet v3.8.0 (`eudi wallet serve --storage memory`) at `https://localhost:8086/api/statuslist`, after an mdoc
issued into that wallet at index 122 was revoked. `eudi-dev-wallet-ca.crt` (PEM) is the wallet's in-memory test CA that
signs the status list signer's certificate; its key was never stored.
