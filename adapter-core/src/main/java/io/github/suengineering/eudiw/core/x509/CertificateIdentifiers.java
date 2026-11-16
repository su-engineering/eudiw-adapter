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

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/** Key identifiers of certificates, as used by DCQL {@code trusted_authorities} of type {@code aki}. */
public final class CertificateIdentifiers {

    private static final String AUTHORITY_KEY_IDENTIFIER = "2.5.29.35";

    private CertificateIdentifiers() {}

    /** The base64url keyIdentifier of the AuthorityKeyIdentifier extension (RFC 5280 section 4.2.1.1). */
    public static Optional<String> authorityKeyId(X509Certificate certificate) {
        byte[] extension = certificate.getExtensionValue(AUTHORITY_KEY_IDENTIFIER);
        if (extension == null) {
            return Optional.empty();
        }
        try {
            // extnValue OCTET STRING -> AuthorityKeyIdentifier SEQUENCE -> [0] keyIdentifier
            Der octets = Der.read(extension, 0, 0x04);
            Der sequence = Der.read(extension, octets.contentStart(), 0x30);
            int position = sequence.contentStart();
            while (position < sequence.contentEnd()) {
                Der element = Der.read(extension, position, -1);
                if (element.tag() == 0x80) {
                    byte[] keyId = Arrays.copyOfRange(extension, element.contentStart(), element.contentEnd());
                    return Optional.of(Base64.getUrlEncoder().withoutPadding().encodeToString(keyId));
                }
                position = element.contentEnd();
            }
            return Optional.empty();
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    /** AuthorityKeyIdentifiers of every certificate in a chain. */
    public static Set<String> authorityKeyIds(List<X509Certificate> chain) {
        Set<String> ids = new LinkedHashSet<>();
        for (X509Certificate certificate : chain) {
            authorityKeyId(certificate).ifPresent(ids::add);
        }
        return ids;
    }

    private record Der(int tag, int contentStart, int contentEnd) {

        static Der read(byte[] data, int offset, int expectedTag) {
            if (offset + 2 > data.length) {
                throw new IllegalArgumentException("truncated DER");
            }
            int tag = data[offset] & 0xFF;
            if (expectedTag >= 0 && tag != expectedTag) {
                throw new IllegalArgumentException("unexpected DER tag");
            }
            int length = data[offset + 1] & 0xFF;
            int start = offset + 2;
            if (length > 0x80) {
                int count = length & 0x7F;
                if (count > 3 || start + count > data.length) {
                    throw new IllegalArgumentException("unsupported DER length");
                }
                length = 0;
                for (int i = 0; i < count; i++) {
                    length = (length << 8) | (data[start + i] & 0xFF);
                }
                start += count;
            } else if (length == 0x80) {
                throw new IllegalArgumentException("indefinite length not allowed in DER");
            }
            if (start + length > data.length) {
                throw new IllegalArgumentException("truncated DER");
            }
            return new Der(tag, start, start + length);
        }
    }
}
