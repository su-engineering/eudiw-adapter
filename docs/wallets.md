# Wallets

Which wallets have presented credentials to eudiw-adapter, what each run covered, and how often it runs. A wallet is listed as working only when a run is automated or recorded with its version and date. "Not tested" means exactly that: not that it fails.

## Tested

| Wallet | Version | Formats | Flow | What the run covers | How often | Last run |
| --- | --- | --- | --- | --- | --- | --- |
| [eudi-dev](https://github.com/eudi-dev/eudi-dev), an independent open-source test wallet (command line) | v3.8.0 | SD-JWT VC, ISO mdoc (PID) | cross-device | Signed request by `request_uri` under `x509_hash` and an encrypted `direct_post.jwt` response, in every run. In `--haip --arf --mode strict` (`verify` job): the wallet presents an SD-JWT VC to a policy that sends a registration certificate in `verifier_info`, fetching that certificate's status list, and refuses our request under an untrusted relying-party CA. In `--haip` (`demo` job): an SD-JWT VC from an issuer the policy does not trust is rejected, an mdoc device signature over the OpenID4VP session transcript verifies, and one over the ISO/IEC 18013-7 transcript is rejected | every change: `verify` job (Testcontainers) and `demo` job (Compose) | every CI run |
| [OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite), acting as wallet and issuer | release v5.3.4 | SD-JWT VC | same-device | `oid4vp-1final-verifier-haip-test-plan`: 14 modules, five of which must verify and nine must be rejected (bad signatures, `sd_hash`, key binding nonce, audience and time, revoked credential, wrong `vct`). Every module ends in REVIEW; not certified ([details](../interop/oidf/README.md)) | every change: `oidf` job | every CI run |

Outside the wallets, the SD-JWT checks are also compared with a second implementation (Authlete `sd-jwt` 1.11, and `cbor` 1.21 for mdoc structures) in the unit tests. See the [feature matrix](standards-matrix.md) for each feature's evidence.

## Not tested yet

| Wallet | Status |
| --- | --- |
| EU reference wallet (Android, iOS) | Planned: first on emulators and simulators, then on phones ([roadmap](../ROADMAP.md) item 3) |
| A second independent wallet in CI | Planned ([roadmap](../ROADMAP.md) item 4). Candidates must run without a person, speak OpenID4VP 1.0 Final with DCQL, and accept `x509_hash` and encrypted responses |
| Any wallet over the Digital Credentials API | The adapter does not support the browser API yet ([roadmap](../ROADMAP.md) item 2) |

Not covered by any run: ISO mdoc in the same-device flow, mdoc with `deviceMac` (not supported), and real registrars or real trusted lists.

## Adding a wallet

If you have run a wallet against the adapter, open an issue with the wallet's name and version, the format and flow, the session status and reason the adapter returned, and the adapter log of the run with personal data removed. A wallet goes into the table above once the run can be repeated: in CI, or with steps and logs kept in this repository.
