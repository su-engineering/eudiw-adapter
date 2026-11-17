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
import io.github.suengineering.eudiw.core.crypto.Brainpool;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.util.EnumSet;
import java.util.Set;

/**
 * COSE signature algorithms accepted for mdoc issuer and device signatures (IANA COSE Algorithms registry), each
 * bound to the key types it may be used with. The header never chooses a verifier on its own: the key's curve must
 * be one the algorithm allows. ES256, ES384 and ES512 also allow the brainpool curve of their hash size, as ISO/IEC
 * 18013-5 clause 9.1.5.2 does; the fully specified ESP and ESB algorithms name one curve each (RFC 9864). Brainpool
 * curves need {@link Brainpool#enable}.
 */
public enum CoseAlgorithm {
    ES256(-7, EnumSet.of(Curve.P256, Curve.BP256)),
    ESP256(-9, EnumSet.of(Curve.P256)),
    ES384(-35, EnumSet.of(Curve.P384, Curve.BP320, Curve.BP384)),
    ESP384(-51, EnumSet.of(Curve.P384)),
    ES512(-36, EnumSet.of(Curve.P521, Curve.BP512)),
    ESP512(-52, EnumSet.of(Curve.P521)),
    ESB256(-265, EnumSet.of(Curve.BP256)),
    ESB320(-266, EnumSet.of(Curve.BP320)),
    ESB384(-267, EnumSet.of(Curve.BP384)),
    ESB512(-268, EnumSet.of(Curve.BP512)),
    EDDSA(-8, EnumSet.of(Curve.ED25519, Curve.ED448)),
    ED25519(-19, EnumSet.of(Curve.ED25519)),
    ED448(-53, EnumSet.of(Curve.ED448));

    /**
     * Curves keys may use, by COSE Elliptic Curves registry value. The signature hash follows the curve: SHA-256 up to
     * 256 bits, SHA-384 for brainpoolP320r1 and the 384-bit curves, SHA-512 above.
     */
    public enum Curve {
        P256(1, "secp256r1", "SHA256withECDSAinP1363Format", 32),
        P384(2, "secp384r1", "SHA384withECDSAinP1363Format", 48),
        P521(3, "secp521r1", "SHA512withECDSAinP1363Format", 66),
        ED25519(6, "Ed25519", "Ed25519", 32),
        ED448(7, "Ed448", "Ed448", 57),
        BP256(256, "brainpoolP256r1", "SHA256withPLAIN-ECDSA", 32),
        BP320(257, "brainpoolP320r1", "SHA384withPLAIN-ECDSA", 40),
        BP384(258, "brainpoolP384r1", "SHA384withPLAIN-ECDSA", 48),
        BP512(259, "brainpoolP512r1", "SHA512withPLAIN-ECDSA", 64);

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

        /** Whether this is a brainpool curve, which needs {@link Brainpool#enable}. */
        public boolean brainpool() {
            return coseId >= 256;
        }

        static Curve ofCose(long id) {
            for (Curve c : values()) {
                if (c.coseId == id) {
                    return requireAvailable(c);
                }
            }
            throw new VerificationFailure("unsupported_key", "unsupported COSE curve " + id);
        }

        /** The curve of a key, identified by its full domain parameters, never by its size alone. */
        static Curve of(PublicKey key) {
            if (key instanceof ECPublicKey ec) {
                for (Curve c : values()) {
                    if (c.jcaSignature.contains("ECDSA")
                            && Brainpool.sameCurve(CoseKeys.parameters(c), ec.getParams())) {
                        return requireAvailable(c);
                    }
                }
                throw new VerificationFailure("unsupported_key", "unsupported EC curve");
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

        private static Curve requireAvailable(Curve curve) {
            if (curve.brainpool() && Brainpool.provider().isEmpty()) {
                throw new VerificationFailure(
                        "unsupported_algorithm", "brainpool curves are not enabled (adapter-crypto-brainpool)");
            }
            return curve;
        }
    }

    private final int id;
    private final Set<Curve> curves;

    CoseAlgorithm(int id, Set<Curve> curves) {
        this.id = id;
        this.curves = curves;
    }

    public int id() {
        return id;
    }

    /** Whether this algorithm can be used at all now: false for the ESB algorithms while brainpool is off. */
    public boolean available() {
        return curves.stream().anyMatch(c -> !c.brainpool())
                || Brainpool.provider().isPresent();
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
        if (!alg.curves.contains(keyCurve)) {
            throw new VerificationFailure("unsupported_algorithm", "COSE algorithm does not match the key");
        }
        return keyCurve;
    }
}
