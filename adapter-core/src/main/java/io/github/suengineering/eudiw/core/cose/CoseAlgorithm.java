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
package io.github.suengineering.eudiw.core.cose;

import io.github.suengineering.eudiw.core.VerificationFailure;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;

/**
 * COSE signature algorithms accepted for mdoc issuer and device signatures (IANA COSE Algorithms registry), each
 * bound to the one key type it may be used with. The header never chooses a verifier on its own: the key's curve
 * must be the one the algorithm names.
 */
public enum CoseAlgorithm {
    ES256(-7, Curve.P256),
    ESP256(-9, Curve.P256),
    ES384(-35, Curve.P384),
    ESP384(-51, Curve.P384),
    ES512(-36, Curve.P521),
    ESP512(-52, Curve.P521),
    EDDSA(-8, null),
    ED25519(-19, Curve.ED25519),
    ED448(-53, Curve.ED448);

    /** Curves keys may use, by COSE Elliptic Curves registry value. */
    public enum Curve {
        P256(1, "secp256r1", "SHA256withECDSAinP1363Format", 32),
        P384(2, "secp384r1", "SHA384withECDSAinP1363Format", 48),
        P521(3, "secp521r1", "SHA512withECDSAinP1363Format", 66),
        ED25519(6, "Ed25519", "Ed25519", 32),
        ED448(7, "Ed448", "Ed448", 57);

        final int coseId;
        final String jdkName;
        final String jcaSignature;
        final int size;

        Curve(int coseId, String jdkName, String jcaSignature, int size) {
            this.coseId = coseId;
            this.jdkName = jdkName;
            this.jcaSignature = jcaSignature;
            this.size = size;
        }

        public int coseId() {
            return coseId;
        }

        static Curve ofCose(long id) {
            for (Curve c : values()) {
                if (c.coseId == id) {
                    return c;
                }
            }
            throw new VerificationFailure("unsupported_key", "unsupported COSE curve " + id);
        }

        static Curve of(PublicKey key) {
            if (key instanceof ECPublicKey ec) {
                int bits = ec.getParams().getCurve().getField().getFieldSize();
                return switch (bits) {
                    case 256 -> requireNamed(ec, P256);
                    case 384 -> requireNamed(ec, P384);
                    case 521 -> requireNamed(ec, P521);
                    default -> throw new VerificationFailure("unsupported_key", "unsupported EC curve");
                };
            }
            if (key instanceof EdECPublicKey ed) {
                return switch (ed.getParams().getName()) {
                    case "Ed25519" -> ED25519;
                    case "Ed448" -> ED448;
                    default -> throw new VerificationFailure("unsupported_key", "unsupported EdDSA curve");
                };
            }
            throw new VerificationFailure("unsupported_key", "unsupported key type");
        }

        /** Brainpool curves share field sizes with NIST curves; only the NIST curves are accepted. */
        private static Curve requireNamed(ECPublicKey key, Curve expected) {
            if (!CoseKeys.parameters(expected).getCurve().equals(key.getParams().getCurve())) {
                throw new VerificationFailure("unsupported_algorithm", "only NIST P-curves are supported");
            }
            return expected;
        }
    }

    private static final java.util.Set<Curve> EDWARDS = java.util.EnumSet.of(Curve.ED25519, Curve.ED448);

    private final int id;
    private final Curve curve;

    CoseAlgorithm(int id, Curve curve) {
        this.id = id;
        this.curve = curve;
    }

    public int id() {
        return id;
    }

    /**
     * The algorithm for a header value, checked against the key.
     *
     * @throws VerificationFailure {@code unsupported_algorithm} for an unknown value or a value the key cannot
     *     be used with
     */
    public static Curve verifyWith(long headerAlg, PublicKey key) {
        CoseAlgorithm alg = null;
        for (CoseAlgorithm a : values()) {
            if (a.id == headerAlg) {
                alg = a;
            }
        }
        if (alg == null) {
            throw new VerificationFailure("unsupported_algorithm", "unsupported COSE algorithm " + headerAlg);
        }
        Curve keyCurve = Curve.of(key);
        // Plain EdDSA (-8) names no curve: either Edwards curve fits. Every other algorithm names exactly one.
        boolean matches = alg.curve == null ? EDWARDS.contains(keyCurve) : alg.curve == keyCurve;
        if (!matches) {
            throw new VerificationFailure("unsupported_algorithm", "COSE algorithm does not match the key");
        }
        return keyCurve;
    }
}
