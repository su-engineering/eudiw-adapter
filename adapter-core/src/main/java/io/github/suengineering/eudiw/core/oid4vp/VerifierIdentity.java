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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.impl.ECDSA;
import io.github.suengineering.eudiw.core.keys.RequestSigner;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * The verifier's request-signing identity for the {@code x509_hash} Client Identifier Prefix (OpenID4VP 1.0
 * section 5.9.3, required by HAIP 1.0 section 5).
 *
 * @param signer the request-signing key, wherever it is held: in memory, in an HSM, or in a key service
 * @param certificateChain end-entity certificate first; must not contain the trust anchor or a self-signed leaf
 */
public record VerifierIdentity(RequestSigner signer, List<X509Certificate> certificateChain) {

    /** A key held in memory. */
    public VerifierIdentity(PrivateKey signingKey, List<X509Certificate> certificateChain) {
        this(RequestSigner.of(signingKey), certificateChain);
    }

    /** A key held in memory, or a handle from {@code provider} (for example SunPKCS11) when one is given. */
    public VerifierIdentity(
            PrivateKey signingKey, List<X509Certificate> certificateChain, Optional<Provider> provider) {
        this(
                provider.map(p -> RequestSigner.of(signingKey, p)).orElseGet(() -> RequestSigner.of(signingKey)),
                certificateChain);
    }

    public VerifierIdentity {
        Objects.requireNonNull(signer, "signer");
        certificateChain = List.copyOf(certificateChain);
        if (certificateChain.isEmpty()) {
            throw new IllegalArgumentException("certificate chain must not be empty");
        }
        X509Certificate leaf = certificateChain.get(0);
        if (leaf.getSubjectX500Principal().equals(leaf.getIssuerX500Principal())) {
            throw new IllegalArgumentException("the request-signing certificate must not be self-signed (HAIP 1.0)");
        }
        if (!(leaf.getPublicKey() instanceof ECPublicKey publicKey)
                || publicKey.getParams().getCurve().getField().getFieldSize() != 256) {
            throw new IllegalArgumentException("the request-signing key must be EC P-256 (ES256, HAIP 1.0)");
        }
        proveKeyMatches(leaf, signer);
        signer = checked(signer, leaf);
    }

    /**
     * Verifies every signature with the certificate before it is used. A key in a key service can be rotated after
     * startup; requests signed with the new version would then fail at every wallet, so signing fails here instead.
     */
    private static RequestSigner checked(RequestSigner signer, X509Certificate leaf) {
        if (signer instanceof CheckedSigner) {
            return signer;
        }
        return new CheckedSigner(signer, leaf);
    }

    private record CheckedSigner(RequestSigner delegate, X509Certificate leaf) implements RequestSigner {
        @Override
        public byte[] signEs256(byte[] data) throws JOSEException {
            byte[] concat = delegate.signEs256(data);
            try {
                Signature verifier = Signature.getInstance("SHA256withECDSA");
                verifier.initVerify(leaf.getPublicKey());
                verifier.update(data);
                if (concat.length == 64 && verifier.verify(ECDSA.transcodeSignatureToDER(concat))) {
                    return concat;
                }
            } catch (GeneralSecurityException e) {
                // reported below
            }
            throw new JOSEException("the signature does not verify with the request-signing certificate;"
                    + " the key no longer matches it (rotated?)");
        }
    }

    /** Signs a probe with the key and verifies it with the certificate, so a wrong HSM key fails at startup. */
    private static void proveKeyMatches(X509Certificate leaf, RequestSigner signer) {
        try {
            byte[] probe = "eudiw-adapter request signing key check".getBytes(StandardCharsets.US_ASCII);
            byte[] concat = signer.signEs256(probe);
            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(leaf.getPublicKey());
            verifier.update(probe);
            if (!verifier.verify(ECDSA.transcodeSignatureToDER(concat))) {
                throw new IllegalArgumentException("the signing key does not match the end-entity certificate");
            }
        } catch (GeneralSecurityException | JOSEException e) {
            throw new IllegalArgumentException("the signing key cannot be used: " + e.getMessage(), e);
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
