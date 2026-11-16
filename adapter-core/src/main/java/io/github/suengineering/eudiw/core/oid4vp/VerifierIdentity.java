/*
 * Copyright 2026 su-engineering
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.github.suengineering.eudiw.core.oid4vp;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Objects;

/**
 * The verifier's request-signing identity for the {@code x509_hash} Client Identifier Prefix (OpenID4VP 1.0
 * section 5.9.3, required by HAIP 1.0 section 5).
 *
 * @param signingKey private key matching the end-entity certificate
 * @param certificateChain end-entity certificate first; must not contain the trust anchor or a self-signed leaf
 */
public record VerifierIdentity(PrivateKey signingKey, List<X509Certificate> certificateChain) {

    public VerifierIdentity {
        Objects.requireNonNull(signingKey, "signingKey");
        certificateChain = List.copyOf(certificateChain);
        if (certificateChain.isEmpty()) {
            throw new IllegalArgumentException("certificate chain must not be empty");
        }
        X509Certificate leaf = certificateChain.get(0);
        if (leaf.getSubjectX500Principal().equals(leaf.getIssuerX500Principal())) {
            throw new IllegalArgumentException("the request-signing certificate must not be self-signed (HAIP 1.0)");
        }
        if (!(signingKey instanceof ECPrivateKey) || !(leaf.getPublicKey() instanceof ECPublicKey)) {
            throw new IllegalArgumentException("only EC request-signing keys are supported");
        }
    }

    /** {@code x509_hash:} followed by the base64url SHA-256 of the DER end-entity certificate. */
    public String clientId() {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256")
                    .digest(certificateChain.get(0).getEncoded());
            return "x509_hash:" + Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException | CertificateEncodingException e) {
            throw new IllegalStateException(e);
        }
    }
}
