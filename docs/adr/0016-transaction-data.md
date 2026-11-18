# ADR-016: Transaction data (`transaction_data`)

Status: accepted, implemented for SD-JWT VC.

## Context

OpenID4VP 1.0 lets a verifier send `transaction_data` (section 5.1): typed JSON objects, such as a payment, that the holder authorizes with the same presentation. For SD-JWT VC the wallet puts a hash of each entry into the Key Binding JWT (`transaction_data_hashes`, appendix B.3.3.1), so the holder's key signs the transaction together with the nonce. Payment and signing flows (for example EUDI SCA) build on it.

## Decision

1. **The client sends objects; the adapter encodes them.** `POST /v1/verification-sessions` takes `transaction_data` as JSON objects. Each is serialized once and base64url-encoded, and that exact string is what the wallet hashes, the request object carries and the check uses. The policy allows types by name (`transaction_data_types`); other types are refused with 400 before a session exists.
2. **One credential per entry.** OpenID4VP lets an entry name several credentials, of which the wallet uses one. The adapter accepts exactly one id, which must be a `dc+sd-jwt` credential query with holder binding and without `multiple`, so there is no question which presentation must carry the hash.
3. **sha-256, chosen by the adapter.** `transaction_data_hashes_alg` is never sent, so the default sha-256 applies, and a client may not set it. A Key Binding JWT that names any other algorithm is rejected.
4. **The check.** The Key Binding JWT of the bound credential must carry `transaction_data_hashes` equal to the set of sha-256 hashes of the base64url strings as sent: none missing, none extra, none repeated, in any order (the specification sets none). Hashes in a Key Binding JWT that was sent none are also rejected. A presentation without the bound credential, for example when it was optional in a credential set, is rejected (`transaction_data_not_presented`). Failure code `transaction_data_mismatch`.
5. **The result is the record.** The verified entries are written into the result when the presentation verifies, decoded back to objects. The session row keeps the encrypted entries only while the session is pending and clears them when it ends. The status view, events, webhooks, audit and logs never contain them.
6. **ISO mdoc is refused.** OpenID4VP binds transaction data to an mdoc through data elements that each transaction data type defines (appendix B.2.1), not through a hash this adapter could check. Until a type is implemented, an entry cannot name an `mso_mdoc` query.

## Consequences

- The backend learns that the holder's key signed hashes of these entries, from the adapter. It receives no wallet signature it could keep or show to a third party; a backend that needs that evidence would need the presentation itself, which the adapter does not hand out (data minimization).
- During a rolling upgrade from a version without this feature, a session created on a new pod can be answered on an old one, which neither sends nor checks transaction data. Its result has no `transaction_data`, which the API defines as "no transaction authorized". Replace all pods before clients send transaction data.
- Interop in CI: walt.id Wallet API 2 binds a `payment_card` entry and verifies; the eudi-dev wallet v3.8.0, which ignores `transaction_data` (instead of rejecting the request, as the specification asks of wallets without support), is rejected with `transaction_data_mismatch`. Unit tests cover a missing, wrong, extra or repeated hash, a hash over the decoded JSON, and another algorithm.
