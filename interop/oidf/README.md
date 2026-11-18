# OpenID Foundation conformance suite

Runs the OpenID Foundation's `oid4vp-1final-verifier-haip-test-plan` (OpenID4VP 1.0 Final + HAIP 1.0, SD-JWT VC, `direct_post.jwt`, `x509_hash`) against a local eudiw-adapter. The suite acts as the wallet and also as the credential issuer.

## Run

CI runs the plan on every change (the `oidf` job in [ci.yaml](../../.github/workflows/ci.yaml)) and keeps the suite logs as the `oidf-conformance-logs` artifact. To run it on your machine, build the service and run the same script:

```sh
./mvnw -pl adapter-verifier-service -am package -DskipTests
JAVA_HOME=/path/to/jdk-21 ./interop/oidf/ci.sh
```

It needs Docker, Java 21, OpenSSL, Python 3 and curl. [ci.sh](ci.sh):

1. Starts the suite, pinned to a release in [suite-compose.yml](suite-compose.yml), at `https://localhost.emobix.co.uk:8443`, and PostgreSQL.
2. Runs [setup.sh](setup.sh), which creates synthetic issuer and relying-party PKIs, the adapter's `tenants.json`, the suite configuration and a truststore for the suite's TLS certificate.
3. Starts the adapter over HTTPS on port 8453 with a self-signed certificate. The suite reaches it as `https://host.docker.internal:8453`. Access tokens are signed by a key `setup.sh` creates.
4. Runs [run.py](run.py) with `--check expected.json`. It creates one plan, runs every module, and fails unless all modules in [expected.json](expected.json) ran, nothing else ran, each ended in the adapter with the expected status and reason, and the suite logged no failure or warning.

Results, the suite log of each module and the adapter's log go to `interop/oidf/out`, or to `OUT_DIR` if set. `python3 run.py -v <module>` runs one module against a suite and adapter you started yourself.

To move to a newer suite release, change both image tags and digests in [suite-compose.yml](suite-compose.yml) (the tags are listed in the suite's GitLab container registry), run `ci.sh`, and update [expected.json](expected.json) and the results below in the same change if the plan changed.

## Notes

- **TLS hostname.** The suite's local TLS certificate is `CN=localhost` with no subject alternative name. The JDK refuses it for `localhost.emobix.co.uk`, so the adapter fetched the suite's status lists only with `-Djdk.internal.httpclient.disableHostnameVerification=true`. This applies to the local run only. Production keeps hostname verification.
- **Same-device flow.** The suite is a same-device web wallet, and HAIP 1.0 section 5.1 requires `redirect_uri` in that flow, so sessions are created with `"mode": "same_device"`.
- **Development settings.** The adapter runs with `EUDIW_PRODUCTION=false` and the egress development settings, because the suite's status lists are on a loopback address.

## Results, 2026-11-18

Suite: `registry.gitlab.com/openid/conformance-suite:release-v5.3.4`, pinned by digest in [suite-compose.yml](suite-compose.yml). CI repeats this run on every change; its logs are the current record. The first local run, on 2026-11-17 with the suite at repository commit `e8bd0c0`, gave the same outcomes.

| Module | Suite log | Adapter outcome |
| --- | --- | --- |
| happy-flow | no failures or warnings | verified |
| minimal-cnf-jwk | no failures or warnings | verified |
| request-uri-method-post | no failures or warnings | verified |
| request-uri-fetched-twice | no failures or warnings | verified |
| present-credential-without-status | no failures or warnings | verified |
| invalid-kb-jwt-signature | no failures or warnings | rejected `invalid_key_binding` |
| invalid-credential-signature | no failures or warnings | rejected `invalid_signature` |
| invalid-sd-hash | no failures or warnings | rejected `sd_hash_mismatch` |
| invalid-kb-jwt-nonce | no failures or warnings | rejected `key_binding_nonce_mismatch` |
| invalid-kb-jwt-aud | no failures or warnings | rejected `key_binding_audience_mismatch` |
| kb-jwt-iat-in-past | no failures or warnings | rejected `key_binding_stale` |
| kb-jwt-iat-in-future | no failures or warnings | rejected `key_binding_stale` |
| present-revoked-credential | no failures or warnings | rejected `credential_revoked` |
| wrong-vct | no failures or warnings | rejected `credential_type_not_allowed` |

`invalid-session-transcript` applies to mdoc only and did not run.

**What this result is not.**
- **Not passed.** Every module ends in REVIEW. The suite asks for a screenshot of the verifier's own result page, and in same-device flows the adapter answers the wallet with `200` and `redirect_uri` even for a rejected presentation. A headless API service has no such page; the outcome is in the session resource shown above.
- **Not certification.** Certification needs the hosted suite, a publicly reachable verifier, and the screenshots.

**Earlier attempts.** They found nothing wrong in the adapter. The first attempts ran over plain HTTP, and the suite requires HTTPS `request_uri` and `response_uri`; production requires HTTPS anyway. They also used cross-device mode, where the suite expects HAIP's same-device `redirect_uri`.
