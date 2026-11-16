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
package io.github.suengineering.eudiw.core.jose;

import com.nimbusds.jose.JWSAlgorithm;
import java.util.Objects;
import java.util.Set;

/**
 * The asymmetric JWS algorithms a verifier accepts. Symmetric algorithms and {@code none} can never be
 * allowed; only ECDSA and RSASSA-PSS are supported.
 *
 * @param allowed accepted algorithms
 * @param minimumRsaKeyBits smallest RSA modulus accepted
 */
public record AlgorithmPolicy(Set<JWSAlgorithm> allowed, int minimumRsaKeyBits) {

    private static final Set<JWSAlgorithm> SUPPORTED = Set.of(
            JWSAlgorithm.ES256,
            JWSAlgorithm.ES384,
            JWSAlgorithm.ES512,
            JWSAlgorithm.PS256,
            JWSAlgorithm.PS384,
            JWSAlgorithm.PS512);

    /** ECDSA on P-256, P-384 and P-521 and RSASSA-PSS with keys of at least 2048 bits. */
    public static final AlgorithmPolicy DEFAULT = new AlgorithmPolicy(SUPPORTED, 2048);

    /** ES256 only, the algorithm HAIP 1.0 requires every party to support. */
    public static final AlgorithmPolicy ES256_ONLY = new AlgorithmPolicy(Set.of(JWSAlgorithm.ES256), 2048);

    public AlgorithmPolicy {
        Objects.requireNonNull(allowed, "allowed");
        if (allowed.isEmpty()) {
            throw new IllegalArgumentException("at least one algorithm must be allowed");
        }
        for (JWSAlgorithm algorithm : allowed) {
            if (!SUPPORTED.contains(algorithm)) {
                throw new IllegalArgumentException("unsupported algorithm: " + algorithm);
            }
        }
        if (minimumRsaKeyBits < 2048) {
            throw new IllegalArgumentException("RSA keys below 2048 bits are not accepted");
        }
        allowed = Set.copyOf(allowed);
    }

    public boolean allows(JWSAlgorithm algorithm) {
        return algorithm != null && allowed.contains(algorithm);
    }
}
