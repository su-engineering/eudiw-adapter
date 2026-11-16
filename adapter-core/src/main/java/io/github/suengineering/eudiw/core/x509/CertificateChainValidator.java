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
package io.github.suengineering.eudiw.core.x509;

import io.github.suengineering.eudiw.core.VerificationFailure;
import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;

/**
 * Validates a certificate chain carried in a token ({@code x5c}) against configured trust anchors with the JDK's
 * PKIX implementation. Revocation is checked separately by the caller's status policy.
 *
 * <p>Additional rules from HAIP 1.0 section 6.1.1: the end-entity certificate must not be self-signed and the
 * chain must not contain a trust anchor.
 */
public final class CertificateChainValidator {

    /** Longest chain accepted, end-entity certificate included. */
    public static final int MAX_CHAIN_LENGTH = 5;

    private static final int DIGITAL_SIGNATURE = 0;

    private CertificateChainValidator() {}

    /** Parses DER certificates, end-entity first. */
    public static List<X509Certificate> parse(List<byte[]> derCertificates) {
        if (derCertificates == null || derCertificates.isEmpty()) {
            throw new VerificationFailure("certificate_chain_invalid", "no certificates");
        }
        if (derCertificates.size() > MAX_CHAIN_LENGTH) {
            throw new VerificationFailure("certificate_chain_invalid", "certificate chain too long");
        }
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            List<X509Certificate> chain = new ArrayList<>(derCertificates.size());
            for (byte[] der : derCertificates) {
                chain.add((X509Certificate) factory.generateCertificate(new ByteArrayInputStream(der)));
            }
            return chain;
        } catch (CertificateException | ClassCastException e) {
            throw new VerificationFailure("certificate_chain_invalid", "certificate cannot be parsed", e);
        }
    }

    /** A validated chain: its end-entity certificate and the trusted certificate it validated to. */
    public record ValidatedPath(X509Certificate leaf, X509Certificate anchor) {}

    /**
     * @param chain end-entity certificate first, trust anchor excluded
     * @param anchors trusted certificates
     * @param at validation time
     * @return the validated end-entity certificate
     * @throws VerificationFailure {@code certificate_chain_invalid} or {@code certificate_untrusted}
     */
    public static X509Certificate validate(List<X509Certificate> chain, Set<TrustAnchor> anchors, Instant at) {
        return validatePath(chain, anchors, at).leaf();
    }

    /**
     * Validates the chain like {@link #validate} and reports which trusted certificate it validated to. A chain
     * of exactly one certificate that is itself trusted is accepted directly (a trusted list can list the
     * issuer's own certificate); the certificate must be within its validity period and must not be
     * self-signed.
     */
    public static ValidatedPath validatePath(List<X509Certificate> chain, Set<TrustAnchor> anchors, Instant at) {
        if (chain.isEmpty() || chain.size() > MAX_CHAIN_LENGTH) {
            throw new VerificationFailure("certificate_chain_invalid", "certificate chain length out of range");
        }
        if (anchors.isEmpty()) {
            throw new VerificationFailure("certificate_untrusted", "no trust anchors configured");
        }
        X509Certificate leaf = chain.get(0);
        if (isSelfSigned(leaf)) {
            throw new VerificationFailure("certificate_chain_invalid", "end-entity certificate is self-signed");
        }
        boolean[] keyUsage = leaf.getKeyUsage();
        if (keyUsage != null && !keyUsage[DIGITAL_SIGNATURE]) {
            throw new VerificationFailure(
                    "certificate_chain_invalid", "end-entity certificate is not for digital signatures");
        }
        if (chain.size() == 1) {
            for (TrustAnchor anchor : anchors) {
                if (leaf.equals(anchor.getTrustedCert())) {
                    try {
                        leaf.checkValidity(Date.from(at));
                    } catch (GeneralSecurityException e) {
                        throw new VerificationFailure(
                                "certificate_untrusted", "trusted certificate is outside its validity period", e);
                    }
                    return new ValidatedPath(leaf, leaf);
                }
            }
        }
        for (X509Certificate certificate : chain) {
            for (TrustAnchor anchor : anchors) {
                if (certificate.equals(anchor.getTrustedCert())) {
                    throw new VerificationFailure(
                            "certificate_chain_invalid", "chain must not include the trust anchor");
                }
            }
        }
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            CertPath path = factory.generateCertPath(chain);
            PKIXParameters parameters = new PKIXParameters(anchors);
            parameters.setRevocationEnabled(false);
            parameters.setDate(Date.from(at));
            PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult)
                    CertPathValidator.getInstance("PKIX").validate(path, parameters);
            return new ValidatedPath(leaf, result.getTrustAnchor().getTrustedCert());
        } catch (GeneralSecurityException e) {
            throw new VerificationFailure("certificate_untrusted", "certificate chain does not validate", e);
        }
    }

    static boolean isSelfSigned(X509Certificate certificate) {
        if (!certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal())) {
            return false;
        }
        try {
            certificate.verify(certificate.getPublicKey());
            return true;
        } catch (GeneralSecurityException e) {
            return false;
        }
    }
}
