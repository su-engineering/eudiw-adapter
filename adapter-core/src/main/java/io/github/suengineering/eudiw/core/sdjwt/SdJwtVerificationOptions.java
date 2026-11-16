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

import io.github.suengineering.eudiw.core.jose.AlgorithmPolicy;
import java.time.Clock;
import java.time.Duration;
import java.util.Objects;
import java.util.Set;

/**
 * Verifier policy for one SD-JWT presentation. Key binding is decided here, never by whether the presentation
 * happens to carry a Key Binding JWT (RFC 9901 section 7.3 step 1).
 *
 * @param algorithms JWS algorithms accepted for the Issuer-signed JWT and the Key Binding JWT
 * @param hashAlgorithms accepted {@code _sd_alg} values
 * @param keyBindingRequired whether an SD-JWT+KB is required
 * @param expectedAudience required {@code aud} of the Key Binding JWT
 * @param expectedNonce required {@code nonce} of the Key Binding JWT
 * @param keyBindingMaxAge oldest acceptable Key Binding JWT {@code iat}
 * @param clockSkew tolerance applied to all time checks
 * @param clock time source
 * @param maxLength upper bound on the serialized presentation
 * @param maxDisclosures upper bound on the number of Disclosures
 */
public record SdJwtVerificationOptions(
        AlgorithmPolicy algorithms,
        Set<String> hashAlgorithms,
        boolean keyBindingRequired,
        String expectedAudience,
        String expectedNonce,
        Duration keyBindingMaxAge,
        Duration clockSkew,
        Clock clock,
        int maxLength,
        int maxDisclosures) {

    public static final Set<String> DEFAULT_HASH_ALGORITHMS = Set.of("sha-256", "sha-384", "sha-512");

    public SdJwtVerificationOptions {
        Objects.requireNonNull(algorithms, "algorithms");
        hashAlgorithms = Set.copyOf(hashAlgorithms);
        for (String name : hashAlgorithms) {
            if (!DEFAULT_HASH_ALGORITHMS.contains(name)) {
                throw new IllegalArgumentException("unsupported hash algorithm: " + name);
            }
        }
        if (keyBindingRequired && (isBlank(expectedAudience) || isBlank(expectedNonce))) {
            throw new IllegalArgumentException("key binding requires an expected audience and nonce");
        }
        Objects.requireNonNull(keyBindingMaxAge, "keyBindingMaxAge");
        Objects.requireNonNull(clockSkew, "clockSkew");
        Objects.requireNonNull(clock, "clock");
        if (keyBindingMaxAge.isNegative() || clockSkew.isNegative()) {
            throw new IllegalArgumentException("durations must not be negative");
        }
        if (maxLength <= 0 || maxDisclosures < 0) {
            throw new IllegalArgumentException("limits must be positive");
        }
    }

    /** Key binding required for the given audience and nonce, with conservative defaults. */
    public static SdJwtVerificationOptions keyBound(String audience, String nonce) {
        return new SdJwtVerificationOptions(
                AlgorithmPolicy.DEFAULT,
                DEFAULT_HASH_ALGORITHMS,
                true,
                audience,
                nonce,
                Duration.ofMinutes(5),
                Duration.ofSeconds(60),
                Clock.systemUTC(),
                512 * 1024,
                256);
    }

    public SdJwtVerificationOptions withClock(Clock newClock) {
        return new SdJwtVerificationOptions(
                algorithms,
                hashAlgorithms,
                keyBindingRequired,
                expectedAudience,
                expectedNonce,
                keyBindingMaxAge,
                clockSkew,
                newClock,
                maxLength,
                maxDisclosures);
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
