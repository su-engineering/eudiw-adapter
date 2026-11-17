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
import io.github.suengineering.eudiw.core.cbor.CborItem;
import io.github.suengineering.eudiw.core.cose.CoseAlgorithm.Curve;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HexFormat;

/** Public keys from COSE_Key structures (RFC 9052 section 7, RFC 9053 section 7). */
public final class CoseKeys {

    private static final long KTY = 1;
    private static final long CRV = -1;
    private static final long X = -2;
    private static final long Y = -3;
    private static final long KTY_OKP = 1;
    private static final long KTY_EC2 = 2;

    /** SubjectPublicKeyInfo prefixes for raw Ed25519 and Ed448 keys (RFC 8410). */
    private static final byte[] ED25519_SPKI = HexFormat.of().parseHex("302a300506032b6570032100");

    private static final byte[] ED448_SPKI = HexFormat.of().parseHex("3043300506032b6571033a00");

    private CoseKeys() {}

    /**
     * The public key in a COSE_Key. EC2 keys on P-256, P-384 and P-521, with the y coordinate as a byte string or
     * as a sign bit (point compression), and OKP keys on Ed25519 and Ed448 are supported.
     *
     * @throws VerificationFailure {@code unsupported_key} for any other key
     */
    public static PublicKey publicKey(CborItem coseKey) {
        if (!(coseKey instanceof CborItem.MapItem map)) {
            throw new VerificationFailure("unsupported_key", "COSE_Key is not a map");
        }
        long kty = integer(map, KTY);
        Curve curve = Curve.ofCose(integer(map, CRV));
        byte[] x = bytes(map, X);
        try {
            if (kty == KTY_EC2) {
                if (curve == Curve.ED25519 || curve == Curve.ED448 || x.length != curve.size) {
                    throw new VerificationFailure("unsupported_key", "EC2 key does not match its curve");
                }
                ECParameterSpec params = parameters(curve);
                BigInteger px = new BigInteger(1, x);
                BigInteger py = map.get(Y)
                        .map(y -> switch (y) {
                            case CborItem.Bytes b when b.value().length == curve.size -> new BigInteger(1, b.value());
                            case CborItem.Simple s
                            when s.value() == CborItem.Simple.TRUE || s.value() == CborItem.Simple.FALSE ->
                                decompress(params, px, s.value() == CborItem.Simple.TRUE);
                            default -> throw new VerificationFailure("unsupported_key", "invalid EC2 y coordinate");
                        })
                        .orElseThrow(() -> new VerificationFailure("unsupported_key", "EC2 key without y"));
                requireOnCurve(params, px, py);
                return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(px, py), params));
            }
            if (kty == KTY_OKP && (curve == Curve.ED25519 || curve == Curve.ED448) && x.length == curve.size) {
                byte[] prefix = curve == Curve.ED25519 ? ED25519_SPKI : ED448_SPKI;
                byte[] spki = new byte[prefix.length + x.length];
                System.arraycopy(prefix, 0, spki, 0, prefix.length);
                System.arraycopy(x, 0, spki, prefix.length, x.length);
                return KeyFactory.getInstance(curve.jdkName).generatePublic(new X509EncodedKeySpec(spki));
            }
        } catch (GeneralSecurityException e) {
            throw new VerificationFailure("unsupported_key", "COSE_Key cannot be used", e);
        }
        throw new VerificationFailure("unsupported_key", "unsupported COSE key type or curve");
    }

    static ECParameterSpec parameters(Curve curve) {
        try {
            AlgorithmParameters p = AlgorithmParameters.getInstance("EC");
            p.init(new ECGenParameterSpec(curve.jdkName));
            return p.getParameterSpec(ECParameterSpec.class);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("curve unavailable: " + curve, e);
        }
    }

    /** y from x on a curve with p = 3 mod 4 (true for P-256, P-384 and P-521); the point is checked on decode. */
    private static BigInteger decompress(ECParameterSpec params, BigInteger x, boolean odd) {
        BigInteger p = ((java.security.spec.ECFieldFp) params.getCurve().getField()).getP();
        BigInteger rhs = x.pow(3)
                .add(params.getCurve().getA().multiply(x))
                .add(params.getCurve().getB())
                .mod(p);
        BigInteger y = rhs.modPow(p.add(BigInteger.ONE).shiftRight(2), p);
        if (!y.multiply(y).mod(p).equals(rhs)) {
            throw new VerificationFailure("unsupported_key", "compressed point is not on the curve");
        }
        return y.testBit(0) == odd ? y : p.subtract(y);
    }

    private static void requireOnCurve(ECParameterSpec params, BigInteger x, BigInteger y) {
        BigInteger p = ((java.security.spec.ECFieldFp) params.getCurve().getField()).getP();
        if (x.compareTo(p) >= 0 || y.compareTo(p) >= 0) {
            throw new VerificationFailure("unsupported_key", "EC point coordinate out of range");
        }
        BigInteger rhs = x.pow(3)
                .add(params.getCurve().getA().multiply(x))
                .add(params.getCurve().getB())
                .mod(p);
        if (!y.multiply(y).mod(p).equals(rhs)) {
            throw new VerificationFailure("unsupported_key", "EC point is not on the curve");
        }
    }

    private static long integer(CborItem.MapItem map, long label) {
        return map.get(label)
                .filter(CborItem.Int.class::isInstance)
                .flatMap(i -> ((CborItem.Int) i).asLong())
                .orElseThrow(() -> new VerificationFailure("unsupported_key", "COSE_Key without label " + label));
    }

    private static byte[] bytes(CborItem.MapItem map, long label) {
        return map.get(label)
                .filter(CborItem.Bytes.class::isInstance)
                .map(b -> ((CborItem.Bytes) b).value())
                .orElseThrow(() -> new VerificationFailure("unsupported_key", "COSE_Key without label " + label));
    }
}
