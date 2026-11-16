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
package io.github.suengineering.eudiw.core.sdjwt;

import io.github.suengineering.eudiw.core.VerificationFailure;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * The compact serialization of an SD-JWT or SD-JWT+KB split into its parts (RFC 9901 section 4). Parsing checks
 * only the structure; nothing is verified.
 *
 * @param issuerSignedJwt the Issuer-signed JWT
 * @param disclosures the Disclosures in the order presented
 * @param keyBindingJwt the Key Binding JWT, if present
 * @param sdJwtPart the exact characters the {@code sd_hash} is computed over: the Issuer-signed JWT and each
 *     Disclosure, each followed by {@code ~}
 */
public record SdJwtPresentation(
        String issuerSignedJwt, List<String> disclosures, Optional<String> keyBindingJwt, String sdJwtPart) {

    private static final Pattern JWT = Pattern.compile("[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+");
    private static final Pattern BASE64URL = Pattern.compile("[A-Za-z0-9_-]+");

    public SdJwtPresentation {
        Objects.requireNonNull(issuerSignedJwt, "issuerSignedJwt");
        disclosures = List.copyOf(disclosures);
        Objects.requireNonNull(keyBindingJwt, "keyBindingJwt");
        Objects.requireNonNull(sdJwtPart, "sdJwtPart");
    }

    /**
     * @param maxLength upper bound on the serialized length in characters
     * @param maxDisclosures upper bound on the number of Disclosures
     * @throws VerificationFailure {@code malformed_sd_jwt}
     */
    public static SdJwtPresentation parse(String serialized, int maxLength, int maxDisclosures) {
        if (serialized == null || serialized.isEmpty()) {
            throw malformed("empty SD-JWT");
        }
        if (serialized.length() > maxLength) {
            throw malformed("SD-JWT longer than " + maxLength + " characters");
        }
        int lastTilde = serialized.lastIndexOf('~');
        if (lastTilde < 0) {
            throw malformed("SD-JWT has no '~' separator");
        }
        String sdJwtPart = serialized.substring(0, lastTilde + 1);
        String trailing = serialized.substring(lastTilde + 1);

        // sdJwtPart always ends with '~'; split without dropping the empty final element.
        String[] parts = sdJwtPart.substring(0, sdJwtPart.length() - 1).split("~", -1);
        String issuerJwt = parts[0];
        if (!JWT.matcher(issuerJwt).matches()) {
            throw malformed("Issuer-signed JWT is not a compact JWS");
        }
        if (parts.length - 1 > maxDisclosures) {
            throw malformed("more than " + maxDisclosures + " Disclosures");
        }
        List<String> disclosures = new ArrayList<>(parts.length - 1);
        for (int i = 1; i < parts.length; i++) {
            if (!BASE64URL.matcher(parts[i]).matches()) {
                throw malformed("Disclosure " + i + " is empty or not base64url");
            }
            disclosures.add(parts[i]);
        }

        Optional<String> keyBinding;
        if (trailing.isEmpty()) {
            keyBinding = Optional.empty();
        } else if (JWT.matcher(trailing).matches()) {
            keyBinding = Optional.of(trailing);
        } else {
            throw malformed("final component is neither empty nor a compact JWT");
        }
        return new SdJwtPresentation(issuerJwt, disclosures, keyBinding, sdJwtPart);
    }

    private static VerificationFailure malformed(String message) {
        return new VerificationFailure("malformed_sd_jwt", message);
    }
}
