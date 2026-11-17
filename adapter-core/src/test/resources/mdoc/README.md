# mdoc fixtures

Synthetic only. `iaca.crt` (PEM) is a test IACA root created for these fixtures (`C=EU`); its private key was not kept.

The `*.issuer-signed.b64` files are base64url `IssuerSigned` structures issued by the independent eudi-dev wallet
v3.8.0 into a file wallet (`eudi issue mdoc --wallet --key ... --cert ...`), so each MSO binds the wallet's device key and carries a status list reference, signed by document signer certificates issued under `iaca.crt` (PEM):

| File | docType and namespace | Document signer |
| --- | --- | --- |
| `eudi-dev-pid.issuer-signed.b64` | `eu.europa.ec.eudi.pid.1` | with the mDL DS extended key usage |
| `eudi-dev-mdl.issuer-signed.b64` | `org.iso.18013.5.1.mDL` / `org.iso.18013.5.1` | with the mDL DS extended key usage |
| `eudi-dev-mdl-noeku.issuer-signed.b64` | `org.iso.18013.5.1.mDL` / `org.iso.18013.5.1` | without it |

Claims: `age_over_18` true, and in some files a synthetic name (Erika Mustermann). Each MSO is valid for 30 days
from issuance; the tests fix the clock inside that window.
