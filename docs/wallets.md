# Wallets

Which wallets have presented credentials to eudiw-adapter, what each run covered, and how often it runs. A wallet is listed as working only when a run is automated or recorded with its version and date. "Not tested" means exactly that: not that it fails.

## Tested

| Wallet | Version | Formats | Flow | What the run covers | How often | Last run |
| --- | --- | --- | --- | --- | --- | --- |
| [eudi-dev](https://github.com/eudi-dev/eudi-dev), an independent open-source test wallet (command line) | v3.8.0 | SD-JWT VC, ISO mdoc (PID) | cross-device; Digital Credentials API (browser extension) | Signed request by `request_uri` under `x509_hash` and an encrypted `direct_post.jwt` response, in every run. In `--haip --arf --mode strict` (`verify` job): the wallet presents an SD-JWT VC to a policy that sends a registration certificate in `verifier_info`, fetching that certificate's status list, and refuses our request under an untrusted relying-party CA. In `--haip` (`demo` job): an SD-JWT VC from an issuer the policy does not trust is rejected, a presentation that ignores `transaction_data` is rejected (`transaction_data_mismatch`; this version does not support it), an mdoc device signature over the OpenID4VP session transcript verifies, and one over the ISO/IEC 18013-7 transcript is rejected. Over the Digital Credentials API (`demo` job, [script](../deploy/compose/dc-api/run.sh)): headless Chromium calls `navigator.credentials.get()` on a relying-party page, eudi-dev's extension hands the signed request and the page's Origin to an eudi-dev wallet server, and an SD-JWT VC and an mdoc PID verify (`dc_api.jwt`); a session for another origin rejects what the page gets | every change: `verify` job (Testcontainers) and `demo` job (Compose) | every CI run |
| [walt.id Wallet API 2](https://github.com/walt-id/waltid-identity/tree/main/waltid-services/waltid-wallet-api2), an independent open-source wallet service, driven over its HTTP API | 1.2.1 | SD-JWT VC, ISO mdoc (PID) | cross-device | Signed request by `request_uri` (POST) under `x509_hash`, with the demo relying-party root as the wallet's only trust anchor, and an encrypted `direct_post.jwt` response. The wallet presents an SD-JWT VC and the backend receives only `age_over_18`; it presents an mdoc PID and its device signature over the OpenID4VP session transcript verifies; a credential signed under a certificate chain the trusted list does not name is rejected (`certificate_untrusted`); a second walt.id wallet that trusts another root refuses our request; it binds a `payment_card` `transaction_data` entry in its Key Binding JWT, and the result returns it. The wallet generates the holder key; the run script signs each credential with the demo issuer key and imports it, so walt.id's issuance (OpenID4VCI) is not exercised ([script](../deploy/compose/waltid/run.sh)) | every change: `demo` job (Compose) | every CI run |
| [OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite), acting as wallet and issuer | release v5.3.4 | SD-JWT VC | same-device | `oid4vp-1final-verifier-haip-test-plan`: 14 modules, five of which must verify and nine must be rejected (bad signatures, `sd_hash`, key binding nonce, audience and time, revoked credential, wrong `vct`). Every module ends in REVIEW; not certified ([details](../interop/oidf/README.md)) | every change: `oidf` job | every CI run |

Outside the wallets, the SD-JWT checks are also compared with a second implementation (Authlete `sd-jwt` 1.11, and `cbor` 1.21 for mdoc structures) in the unit tests. See the [feature matrix](standards-matrix.md) for each feature's evidence.

## Not tested yet

| Wallet | Status |
| --- | --- |
| EU reference wallet (Android, iOS) | Planned: first on emulators and simulators, then on phones ([roadmap](../ROADMAP.md) item 3) |
| A phone wallet over a platform's Digital Credentials API | Not run yet. CI runs the API in Chromium with eudi-dev's extension (above) |

Not covered by any run: ISO mdoc in the same-device flow, mdoc with `deviceMac` (not supported), and real registrars or real trusted lists.

## Adding a wallet

If you have run a wallet against the adapter, open an issue with the wallet's name and version, the format and flow, the session status and reason the adapter returned, and the adapter log of the run with personal data removed. A wallet goes into the table above once the run can be repeated: in CI, or with steps and logs kept in this repository.
