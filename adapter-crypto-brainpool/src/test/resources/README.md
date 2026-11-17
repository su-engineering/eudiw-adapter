# Brainpool fixtures

Synthetic only. Made with OpenSSL, so neither the certificates nor the signatures come from BouncyCastle:

- `brainpool-iaca.crt` (PEM): a test IACA on brainpoolP256r1 (`CN=BP Test IACA (synthetic), C=DE`). Its key was not kept.
- `brainpool-device-response.b64`: a base64url DeviceResponse holding one mDL (`age_over_18` true, `issuing_country` `DE`).
  The document signer certificate (brainpoolP256r1, mDL document signer extended key usage, 400 days) and the device
  key are on brainpoolP256r1. OpenSSL signed the MSO and the device authentication; ES256 is in both protected headers.
  Session transcript: client_id `x509_hash:brainpool-fixture`, nonce `nonce-brainpool`, response URI
  `https://verifier.example/response`, no encryption key. The MSO is valid from 2026-11-17T16:00:00Z for a year.
