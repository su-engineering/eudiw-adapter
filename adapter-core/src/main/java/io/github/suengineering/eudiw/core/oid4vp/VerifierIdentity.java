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
import io.github.suengineering.eudiw.core.keys.HsmEs256Signer;
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
 * @param signingKey private key matching the end-entity certificate: an in-memory key, or an opaque handle to a key
 *     in an HSM or KMS (for example from the PKCS#11 provider)
 * @param certificateChain end-entity certificate first; must not contain the trust anchor or a self-signed leaf
 * @param provider the JCA provider that holds the key, when it is not the default (for example SunPKCS11)
 */
public record VerifierIdentity(
        PrivateKey signingKey, List<X509Certificate> certificateChain, Optional<Provider> provider) {

    public VerifierIdentity(PrivateKey signingKey, List<X509Certificate> certificateChain) {
        this(signingKey, certificateChain, Optional.empty());
    }

    public VerifierIdentity {
        Objects.requireNonNull(signingKey, "signingKey");
        Objects.requireNonNull(provider, "provider");
        certificateChain = List.copyOf(certificateChain);
        if (certificateChain.isEmpty()) {
            throw new IllegalArgumentException("certificate chain must not be empty");
        }
        X509Certificate leaf = certificateChain.get(0);
        if (leaf.getSubjectX500Principal().equals(leaf.getIssuerX500Principal())) {
            throw new IllegalArgumentException("the request-signing certificate must not be self-signed (HAIP 1.0)");
        }
        if (!"EC".equals(signingKey.getAlgorithm())
                || !(leaf.getPublicKey() instanceof ECPublicKey publicKey)
                || publicKey.getParams().getCurve().getField().getFieldSize() != 256) {
            throw new IllegalArgumentException("the request-signing key must be EC P-256 (ES256, HAIP 1.0)");
        }
        proveKeyMatches(leaf, signingKey, provider);
    }

    /** Signs a probe with the key and verifies it with the certificate, so a wrong HSM key fails at startup. */
    private static void proveKeyMatches(X509Certificate leaf, PrivateKey privateKey, Optional<Provider> provider) {
        try {
            byte[] probe = "eudiw-adapter request signing key check".getBytes(StandardCharsets.US_ASCII);
            byte[] concat;
            if (provider.isPresent()) {
                concat = HsmEs256Signer.signConcat(privateKey, provider.get(), probe);
            } else {
                Signature signer = Signature.getInstance("SHA256withECDSA");
                signer.initSign(privateKey);
                signer.update(probe);
                concat = ECDSA.transcodeSignatureToConcat(signer.sign(), 64);
            }
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
