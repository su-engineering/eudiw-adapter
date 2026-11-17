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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.authlete.cbor.CBORByteArray;
import com.authlete.cose.COSEProtectedHeaderBuilder;
import com.authlete.cose.COSESign1Builder;
import com.authlete.cose.COSESigner;
import com.authlete.cose.SigStructure;
import com.authlete.cose.SigStructureBuilder;
import io.github.suengineering.eudiw.core.VerificationFailure;
import io.github.suengineering.eudiw.core.cbor.CborDecoder;
import io.github.suengineering.eudiw.core.cbor.CborEncoder;
import io.github.suengineering.eudiw.core.cbor.CborItem;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class CoseTest {

    private static final byte[] PAYLOAD = "payload".getBytes(StandardCharsets.UTF_8);

    @Test
    void verifiesASignatureMadeByAnIndependentImplementation() throws Exception {
        KeyPair keys = ec("secp256r1");
        var header = new COSEProtectedHeaderBuilder().alg(-7).build();
        SigStructure toSign = new SigStructureBuilder()
                .signature1()
                .bodyAttributes(header)
                .payload(PAYLOAD)
                .build();
        byte[] signature = new COSESigner(keys.getPrivate()).sign(toSign, -7);
        byte[] message = new COSESign1Builder()
                .protectedHeader(header)
                .payload(new CBORByteArray(PAYLOAD))
                .signature(signature)
                .build()
                .encode();
        assertThatCode(() -> CoseSign1.parse(CborDecoder.decode(message)).verify(keys.getPublic()))
                .doesNotThrowAnyException();
    }

    @Test
    void theHeaderAlgorithmMustMatchTheKey() throws Exception {
        KeyPair p256 = ec("secp256r1");
        // Signed correctly for P-256, but labelled ES384.
        expect(
                sign1(Map.of(1L, CborEncoder.integer(-35)), p256.getPrivate(), "SHA256withECDSAinP1363Format"),
                p256,
                "unsupported_algorithm");
        expect(
                sign1(Map.of(1L, CborEncoder.integer(-257)), p256.getPrivate(), "SHA256withECDSAinP1363Format"),
                p256,
                "unsupported_algorithm");
        // ESP256 is the fully specified form and verifies.
        assertThatCode(() -> CoseSign1.parse(CborDecoder.decode(sign1(
                                Map.of(1L, CborEncoder.integer(-9)),
                                p256.getPrivate(),
                                "SHA256withECDSAinP1363Format")))
                        .verify(p256.getPublic()))
                .doesNotThrowAnyException();
    }

    @Test
    void criticalHeadersAndRepeatedLabelsAreRejected() throws Exception {
        KeyPair keys = ec("secp256r1");
        Map<Long, CborItem> crit = new LinkedHashMap<>();
        crit.put(1L, CborEncoder.integer(-7));
        crit.put(2L, CborEncoder.array(CborEncoder.integer(99)));
        expect(sign1(crit, keys.getPrivate(), "SHA256withECDSAinP1363Format"), keys, "malformed_credential");

        byte[] good = sign1(Map.of(1L, CborEncoder.integer(-7)), keys.getPrivate(), "SHA256withECDSAinP1363Format");
        CborItem.Array parts = (CborItem.Array) CborDecoder.decode(good);
        Map<CborItem, CborItem> unprotected = new LinkedHashMap<>();
        unprotected.put(CborEncoder.integer(1), CborEncoder.integer(-7));
        byte[] both = CborEncoder.array(
                        parts.items().get(0),
                        CborEncoder.map(unprotected),
                        parts.items().get(2),
                        parts.items().get(3))
                .encoded();
        expect(both, keys, "malformed_credential");

        byte[] noProtected = CborEncoder.array(
                        CborEncoder.bytes(new byte[0]),
                        CborEncoder.map(Map.of()),
                        CborEncoder.bytes(PAYLOAD),
                        parts.items().get(3))
                .encoded();
        expect(noProtected, keys, "malformed_credential");
    }

    @Test
    void tamperedOrTruncatedSignaturesAreRejected() throws Exception {
        KeyPair keys = ec("secp256r1");
        byte[] good = sign1(Map.of(1L, CborEncoder.integer(-7)), keys.getPrivate(), "SHA256withECDSAinP1363Format");
        CborItem.Array parts = (CborItem.Array) CborDecoder.decode(good);
        byte[] signature = ((CborItem.Bytes) parts.items().get(3)).value();
        byte[] flipped = signature.clone();
        flipped[0] ^= 1;
        expect(with(parts, CborEncoder.bytes(flipped)), keys, "invalid_signature");
        expect(with(parts, CborEncoder.bytes(Arrays.copyOf(signature, 63))), keys, "invalid_signature");
    }

    @Test
    void ed25519KeysAndSignaturesWork() throws Exception {
        KeyPair keys = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] raw = Arrays.copyOfRange(keys.getPublic().getEncoded(), 12, 44);
        Map<CborItem, CborItem> coseKey = new LinkedHashMap<>();
        coseKey.put(CborEncoder.integer(1), CborEncoder.integer(1));
        coseKey.put(CborEncoder.integer(-1), CborEncoder.integer(6));
        coseKey.put(CborEncoder.integer(-2), CborEncoder.bytes(raw));
        var publicKey = CoseKeys.publicKey(CborEncoder.map(coseKey));
        byte[] message = sign1(Map.of(1L, CborEncoder.integer(-8)), keys.getPrivate(), "Ed25519");
        assertThatCode(() -> CoseSign1.parse(CborDecoder.decode(message)).verify(publicKey))
                .doesNotThrowAnyException();
        byte[] fully = sign1(Map.of(1L, CborEncoder.integer(-19)), keys.getPrivate(), "Ed25519");
        assertThatCode(() -> CoseSign1.parse(CborDecoder.decode(fully)).verify(publicKey))
                .doesNotThrowAnyException();
    }

    @Test
    void ec2KeysAreCheckedAndCanBeCompressed() throws Exception {
        ECPublicKey key = (ECPublicKey) ec("secp256r1").getPublic();
        byte[] x = fixed(key.getW().getAffineX());
        byte[] y = fixed(key.getW().getAffineY());
        assertThat(CoseKeys.publicKey(ec2(x, CborEncoder.bytes(y)))).isEqualTo(key);
        assertThat(CoseKeys.publicKey(
                        ec2(x, CborEncoder.bool(key.getW().getAffineY().testBit(0)))))
                .isEqualTo(key);
        byte[] offCurve = y.clone();
        offCurve[31] ^= 1;
        assertThatThrownBy(() -> CoseKeys.publicKey(ec2(x, CborEncoder.bytes(offCurve))))
                .isInstanceOfSatisfying(
                        VerificationFailure.class, f -> assertThat(f.code()).isEqualTo("unsupported_key"));
    }

    // -- helpers

    private static void expect(byte[] message, KeyPair keys, String code) {
        assertThatThrownBy(() -> CoseSign1.parse(CborDecoder.decode(message)).verify(keys.getPublic()))
                .isInstanceOfSatisfying(
                        VerificationFailure.class, f -> assertThat(f.code()).isEqualTo(code));
    }

    private static byte[] with(CborItem.Array parts, CborItem signature) {
        return CborEncoder.array(
                        parts.items().get(0),
                        parts.items().get(1),
                        parts.items().get(2),
                        signature)
                .encoded();
    }

    private static byte[] sign1(Map<Long, CborItem> protectedHeader, PrivateKey key, String jca) throws Exception {
        Map<CborItem, CborItem> header = new LinkedHashMap<>();
        protectedHeader.forEach((k, v) -> header.put(CborEncoder.integer(k), v));
        byte[] protectedBytes = CborEncoder.map(header).encoded();
        byte[] toBeSigned = CborEncoder.array(
                        CborEncoder.text("Signature1"),
                        CborEncoder.bytes(protectedBytes),
                        CborEncoder.bytes(new byte[0]),
                        CborEncoder.bytes(PAYLOAD))
                .encoded();
        Signature signer = Signature.getInstance(jca);
        signer.initSign(key);
        signer.update(toBeSigned);
        return CborEncoder.array(
                        CborEncoder.bytes(protectedBytes),
                        CborEncoder.map(Map.of()),
                        CborEncoder.bytes(PAYLOAD),
                        CborEncoder.bytes(signer.sign()))
                .encoded();
    }

    private static CborItem ec2(byte[] x, CborItem y) {
        Map<CborItem, CborItem> key = new LinkedHashMap<>();
        key.put(CborEncoder.integer(1), CborEncoder.integer(2));
        key.put(CborEncoder.integer(-1), CborEncoder.integer(1));
        key.put(CborEncoder.integer(-2), CborEncoder.bytes(x));
        key.put(CborEncoder.integer(-3), y);
        return CborEncoder.map(key);
    }

    private static byte[] fixed(BigInteger value) {
        byte[] raw = value.toByteArray();
        byte[] out = new byte[32];
        int n = Math.min(raw.length, 32);
        System.arraycopy(raw, raw.length - n, out, 32 - n, n);
        return out;
    }

    private static KeyPair ec(String curve) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec(curve));
        return g.generateKeyPair();
    }
}
