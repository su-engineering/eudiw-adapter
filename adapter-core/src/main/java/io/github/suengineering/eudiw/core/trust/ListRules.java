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
package io.github.suengineering.eudiw.core.trust;

import io.github.suengineering.eudiw.core.VerificationFailure;
import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Collection;
import java.util.Date;
import java.util.Optional;

/** Checks shared by both list bindings. */
final class ListRules {

    static final String INVALID = "trusted_list_invalid";
    static final String SIGNATURE_INVALID = "trusted_list_signature_invalid";
    static final String SIGNER_UNTRUSTED = "trusted_list_signer_untrusted";

    /** TS 119 612 clause 5.3.15 and TS 119 602 Annex D: next update at most six months after issue. */
    static final Duration MAX_VALIDITY = Duration.ofDays(31 * 6);

    private ListRules() {}

    /**
     * The signing certificate must be one of the certificates configured, or published by a pointing list, for
     * this list, and valid when the list was issued.
     */
    static void checkSigner(X509Certificate signer, Collection<X509Certificate> allowedSigners, Instant issued) {
        if (!allowedSigners.contains(signer)) {
            throw new VerificationFailure(SIGNER_UNTRUSTED, "trusted list signed by an unexpected certificate");
        }
        try {
            signer.checkValidity(Date.from(issued));
        } catch (GeneralSecurityException e) {
            throw new VerificationFailure(
                    SIGNER_UNTRUSTED, "trusted list signing certificate not valid at issue time", e);
        }
    }

    static void checkDates(Instant issued, Optional<Instant> nextUpdate) {
        if (nextUpdate.isPresent()) {
            if (!nextUpdate.get().isAfter(issued)) {
                throw new VerificationFailure(INVALID, "next update is not after the issue date");
            }
            if (Duration.between(issued, nextUpdate.get()).compareTo(MAX_VALIDITY) > 0) {
                throw new VerificationFailure(INVALID, "next update more than six months after issue");
            }
        }
    }

    /** UTC date-time with the {@code Z} designator (TS 119 612 clause 5.1.3, TS 119 602 clause 6.1.3). */
    static Instant instant(String value) {
        if (value == null || !value.endsWith("Z")) {
            throw new VerificationFailure(INVALID, "date-time must be UTC");
        }
        try {
            return Instant.parse(value);
        } catch (DateTimeParseException e) {
            throw new VerificationFailure(INVALID, "malformed date-time", e);
        }
    }

    static X509Certificate certificate(byte[] der) {
        try {
            return (X509Certificate)
                    CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
        } catch (GeneralSecurityException | ClassCastException e) {
            throw new VerificationFailure(INVALID, "malformed certificate in trusted list", e);
        }
    }
}
