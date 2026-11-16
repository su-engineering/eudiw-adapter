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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import io.github.suengineering.eudiw.core.VerificationFailure;
import java.util.Objects;
import java.util.Set;

/**
 * Verifies a JWS with a key the caller already trusts. The algorithm is derived from the key (curve for EC,
 * policy for RSA); the header {@code alg} must match it and be allowed by the policy, so the token can never
 * choose how it is verified.
 */
public final class JwsSignatureVerifier {

    private JwsSignatureVerifier() {}

    /**
     * @throws VerificationFailure {@code unsupported_algorithm}, {@code unsupported_key} or {@code
     *     invalid_signature}
     */
    public static void verify(JWSObject jws, JWK trustedKey, AlgorithmPolicy policy) {
        verify(jws, trustedKey, policy, Set.of());
    }

    /**
     * Like {@link #verify(JWSObject, JWK, AlgorithmPolicy)}, but accepts a {@code crit} header that lists only
     * names the caller has processed itself.
     *
     * @param understoodCritical header parameter names the caller processes; any other {@code crit} entry rejects
     */
    public static void verify(JWSObject jws, JWK trustedKey, AlgorithmPolicy policy, Set<String> understoodCritical) {
        Objects.requireNonNull(jws, "jws");
        Objects.requireNonNull(trustedKey, "trustedKey");
        Objects.requireNonNull(policy, "policy");

        JWSAlgorithm algorithm = jws.getHeader().getAlgorithm();
        if (!policy.allows(algorithm)) {
            throw new VerificationFailure("unsupported_algorithm", "JWS algorithm not allowed: " + algorithm);
        }
        Set<String> critical = jws.getHeader().getCriticalParams();
        if (critical != null && !understoodCritical.containsAll(critical)) {
            throw new VerificationFailure("unsupported_algorithm", "critical header parameters are not supported");
        }
        if (trustedKey.isPrivate()) {
            throw new VerificationFailure("unsupported_key", "verification key must be a public key");
        }

        JWSVerifier verifier = verifierFor(trustedKey, algorithm, policy, critical == null ? Set.of() : critical);
        boolean valid;
        try {
            valid = jws.verify(verifier);
        } catch (JOSEException | IllegalStateException e) {
            throw new VerificationFailure("invalid_signature", "JWS signature could not be verified", e);
        }
        if (!valid) {
            throw new VerificationFailure("invalid_signature", "JWS signature is invalid");
        }
    }

    private static JWSVerifier verifierFor(
            JWK key, JWSAlgorithm algorithm, AlgorithmPolicy policy, Set<String> deferredCritical) {
        try {
            if (key instanceof ECKey ecKey) {
                JWSAlgorithm expected = algorithmForCurve(ecKey.getCurve());
                if (!algorithm.equals(expected)) {
                    throw new VerificationFailure(
                            "unsupported_algorithm", "algorithm " + algorithm + " does not match key curve");
                }
                return new ECDSAVerifier(ecKey.toECPublicKey(), deferredCritical);
            }
            if (key instanceof RSAKey rsaKey) {
                if (!JWSAlgorithm.Family.RSA.contains(algorithm)) {
                    throw new VerificationFailure(
                            "unsupported_algorithm", "algorithm " + algorithm + " does not match RSA key");
                }
                if (rsaKey.size() < policy.minimumRsaKeyBits()) {
                    throw new VerificationFailure("unsupported_key", "RSA key too short");
                }
                return new RSASSAVerifier(rsaKey.toRSAPublicKey(), deferredCritical);
            }
        } catch (JOSEException e) {
            throw new VerificationFailure("unsupported_key", "key cannot be used for verification", e);
        }
        throw new VerificationFailure("unsupported_key", "unsupported key type: " + key.getKeyType());
    }

    private static JWSAlgorithm algorithmForCurve(Curve curve) {
        if (Curve.P_256.equals(curve)) {
            return JWSAlgorithm.ES256;
        }
        if (Curve.P_384.equals(curve)) {
            return JWSAlgorithm.ES384;
        }
        if (Curve.P_521.equals(curve)) {
            return JWSAlgorithm.ES512;
        }
        throw new VerificationFailure("unsupported_key", "unsupported curve: " + curve);
    }
}
