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
package io.github.suengineering.eudiw.core.mdoc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.suengineering.eudiw.core.VerificationFailure;
import io.github.suengineering.eudiw.core.cbor.CborDecoder;
import io.github.suengineering.eudiw.core.cbor.CborEncoder;
import io.github.suengineering.eudiw.core.cbor.CborItem;
import io.github.suengineering.eudiw.core.x509.TrustStore;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/** mdoc authentication by device signature over a synthetic document whose device key the test holds. */
class DeviceSignatureAuthenticationTest {

    private static final Instant NOW = Instant.parse("2026-11-17T12:00:00Z");
    private static final String DOCTYPE = "eu.europa.ec.eudi.pid.1";
    private static final CborItem TRANSCRIPT = SessionTranscripts.openId4VpRedirect(
            "x509_hash:verifier", "nonce-1", Optional.of(new byte[32]), "https://verifier.example/response");
    private static final CborItem EMPTY = CborEncoder.embedded(CborEncoder.map(Map.of()));

    private final TestMdocIssuer issuer = issuer();

    @Test
    void anHonestDeviceSignatureVerifies() throws Exception {
        assertThatCode(() -> authenticate(signed(EMPTY, TRANSCRIPT, DOCTYPE))).doesNotThrowAnyException();
    }

    @Test
    void theNamespacesAreSignedAsReceivedNotReEncoded() throws Exception {
        // An empty map with a two-byte head (0xb8 0x00): valid CBOR, not the preferred encoding.
        CborItem longForm = CborEncoder.tag(24, CborEncoder.bytes(HexFormat.of().parseHex("b800")));
        assertThatCode(() -> authenticate(signed(longForm, TRANSCRIPT, DOCTYPE)))
                .doesNotThrowAnyException();
    }

    @Test
    void aSignatureForAnotherRequestDoesNotVerify() throws Exception {
        for (CborItem other : List.of(
                SessionTranscripts.openId4VpRedirect(
                        "x509_hash:other", "nonce-1", Optional.of(new byte[32]), "https://verifier.example/response"),
                SessionTranscripts.openId4VpRedirect(
                        "x509_hash:verifier",
                        "nonce-2",
                        Optional.of(new byte[32]),
                        "https://verifier.example/response"),
                SessionTranscripts.openId4VpRedirect(
                        "x509_hash:verifier", "nonce-1", Optional.empty(), "https://verifier.example/response"),
                SessionTranscripts.openId4VpRedirect(
                        "x509_hash:verifier",
                        "nonce-1",
                        Optional.of(new byte[32]),
                        "https://other.example/response"))) {
            expect(signed(EMPTY, other, DOCTYPE), "holder_binding_invalid");
        }
    }

    @Test
    void aSignatureOverAnotherDocTypeOrOtherNamespacesDoesNotVerify() throws Exception {
        expect(signed(EMPTY, TRANSCRIPT, "org.example.other"), "holder_binding_invalid");
        CborItem signedOver = deviceNamespaces("eu.europa.ec.eudi.pid.1", "given_name", "Mallory");
        issuer.keyAuthorizations = byNamespace("eu.europa.ec.eudi.pid.1");
        CborItem document = issuedDocument();
        CborItem auth = signature(TestMdocIssuer.deviceSignature(
                issuer.deviceKeys.getPrivate(),
                -7,
                TestMdocIssuer.deviceAuthentication(TRANSCRIPT, DOCTYPE, signedOver),
                false));
        expect(TestMdocIssuer.withDeviceSigned(document, EMPTY, auth), "holder_binding_invalid");
    }

    @Test
    void aSignatureByAnotherKeyDoesNotVerify() throws Exception {
        CborItem auth = signature(TestMdocIssuer.deviceSignature(
                otherKey(), -7, TestMdocIssuer.deviceAuthentication(TRANSCRIPT, DOCTYPE, EMPTY), false));
        expect(TestMdocIssuer.withDeviceSigned(issuedDocument(), EMPTY, auth), "holder_binding_invalid");
    }

    @Test
    void theSignatureMustBeDetachedAndItsAlgorithmMustFitTheKey() throws Exception {
        byte[] content = TestMdocIssuer.deviceAuthentication(TRANSCRIPT, DOCTYPE, EMPTY);
        expect(
                TestMdocIssuer.withDeviceSigned(
                        issuedDocument(),
                        EMPTY,
                        signature(TestMdocIssuer.deviceSignature(issuer.deviceKeys.getPrivate(), -7, content, true))),
                "malformed_credential");
        // ES384 announced for a P-256 device key.
        assertThatThrownBy(() -> authenticate(TestMdocIssuer.withDeviceSigned(
                        issuedDocument(),
                        EMPTY,
                        signature(
                                TestMdocIssuer.deviceSignature(issuer.deviceKeys.getPrivate(), -35, content, false)))))
                .isInstanceOfSatisfying(
                        VerificationFailure.class, f -> assertThat(f.code()).isEqualTo("unsupported_algorithm"));
    }

    @Test
    void deviceMacIsRefusedAndDeviceAuthMustHoldExactlyOneProof() throws Exception {
        CborItem sig = TestMdocIssuer.deviceSignature(
                issuer.deviceKeys.getPrivate(),
                -7,
                TestMdocIssuer.deviceAuthentication(TRANSCRIPT, DOCTYPE, EMPTY),
                false);
        Map<CborItem, CborItem> mac = new LinkedHashMap<>();
        mac.put(
                CborEncoder.text("deviceMac"),
                CborEncoder.array(
                        CborEncoder.bytes(new byte[] {(byte) 0xa1, 0x01, 0x05}),
                        CborEncoder.map(Map.of()),
                        CborEncoder.nil(),
                        CborEncoder.bytes(new byte[32])));
        expect(
                TestMdocIssuer.withDeviceSigned(issuedDocument(), EMPTY, CborEncoder.map(mac)),
                "holder_binding_invalid");

        Map<CborItem, CborItem> both = new LinkedHashMap<>(mac);
        both.put(CborEncoder.text("deviceSignature"), sig);
        expect(TestMdocIssuer.withDeviceSigned(issuedDocument(), EMPTY, CborEncoder.map(both)), "malformed_credential");
        expect(
                TestMdocIssuer.withDeviceSigned(issuedDocument(), EMPTY, CborEncoder.map(Map.of())),
                "malformed_credential");
    }

    @Test
    void deviceSignedIsMandatoryAndSoAreItsNamespaces() throws Exception {
        expect(issuedDocument(), "malformed_credential");
        CborItem.MapItem document = (CborItem.MapItem) signed(EMPTY, TRANSCRIPT, DOCTYPE);
        CborItem.MapItem deviceSigned =
                (CborItem.MapItem) document.get("deviceSigned").orElseThrow();
        Map<CborItem, CborItem> withoutNamespaces = new LinkedHashMap<>(deviceSigned.entries());
        withoutNamespaces.remove(CborEncoder.text("nameSpaces"));
        Map<CborItem, CborItem> out = new LinkedHashMap<>(document.entries());
        out.put(CborEncoder.text("deviceSigned"), CborEncoder.map(withoutNamespaces));
        expect(CborEncoder.map(out), "malformed_credential");
    }

    @Test
    void deviceSignedElementsNeedAKeyAuthorization() throws Exception {
        CborItem element = deviceNamespaces("eu.europa.ec.eudi.pid.1", "given_name", "Erika");
        // No keyAuthorizations: nothing may be device-signed.
        expect(signed(element, TRANSCRIPT, DOCTYPE), "holder_binding_invalid");

        issuer.keyAuthorizations = byNamespace("org.example.other");
        expect(signed(element, TRANSCRIPT, DOCTYPE), "holder_binding_invalid");

        issuer.keyAuthorizations = byNamespace("eu.europa.ec.eudi.pid.1");
        assertThatCode(() -> authenticate(signed(element, TRANSCRIPT, DOCTYPE))).doesNotThrowAnyException();

        issuer.keyAuthorizations = byElement("eu.europa.ec.eudi.pid.1", "given_name");
        assertThatCode(() -> authenticate(signed(element, TRANSCRIPT, DOCTYPE))).doesNotThrowAnyException();

        issuer.keyAuthorizations = byElement("eu.europa.ec.eudi.pid.1", "family_name");
        expect(signed(element, TRANSCRIPT, DOCTYPE), "holder_binding_invalid");
    }

    @Test
    void deviceSignedValuesAreNeverReturned() throws Exception {
        issuer.keyAuthorizations = byNamespace("eu.europa.ec.eudi.pid.1");
        CborItem document =
                signed(deviceNamespaces("eu.europa.ec.eudi.pid.1", "given_name", "Mallory"), TRANSCRIPT, DOCTYPE);
        Map<CborItem, CborItem> response = new LinkedHashMap<>();
        response.put(CborEncoder.text("version"), CborEncoder.text("1.0"));
        response.put(CborEncoder.text("documents"), CborEncoder.array(document));
        response.put(CborEncoder.text("status"), CborEncoder.integer(0));
        MdocPresentationVerifier.VerifiedMdoc verified =
                presentationVerifier().verify(base64(CborEncoder.map(response)), DOCTYPE, TRANSCRIPT);
        assertThat(verified.claims()).isEqualTo(Map.of("eu.europa.ec.eudi.pid.1", Map.of("age_over_18", true)));
    }

    @Test
    void aDeviceResponseNeedsVersionAndAZeroStatus() throws Exception {
        CborItem document = signed(EMPTY, TRANSCRIPT, DOCTYPE);
        expectResponse(response("1.0", 0L, document), null);
        expectResponse(response("1.1", 0L, document), null);
        expectResponse(response("2.0", 0L, document), "malformed_credential");
        expectResponse(response(null, 0L, document), "malformed_credential");
        expectResponse(response("1.0", null, document), "malformed_credential");
        // A non-zero status fails whether or not documents are present.
        expectResponse(response("1.0", 10L, document), "unprocessable_presentation");
        expectResponse(response("1.0", 20L, null), "unprocessable_presentation");
        // documentErrors are ignored; DCQL decides whether what is missing matters.
        Map<CborItem, CborItem> withErrors =
                new LinkedHashMap<>(((CborItem.MapItem) response("1.0", 0L, document)).entries());
        withErrors.put(
                CborEncoder.text("documentErrors"),
                CborEncoder.array(CborEncoder.map(Map.of(CborEncoder.text("org.example"), CborEncoder.integer(0)))));
        expectResponse(CborEncoder.map(withErrors), null);
    }

    @Test
    void aDeviceKeyThatCannotSignIsRejected() throws Exception {
        Map<CborItem, CborItem> x25519 = new LinkedHashMap<>();
        x25519.put(CborEncoder.integer(1), CborEncoder.integer(1));
        x25519.put(CborEncoder.integer(-1), CborEncoder.integer(4));
        x25519.put(CborEncoder.integer(-2), CborEncoder.bytes(new byte[32]));
        for (CborItem key : List.of(CborEncoder.map(x25519), CborEncoder.text("not a key"))) {
            issuer.deviceKeyOverride = key;
            expect(signed(EMPTY, TRANSCRIPT, DOCTYPE), "unsupported_key");
        }
    }

    @Test
    void mutatedDeviceResponsesNeverVerifyWithChangedContent() throws Exception {
        issuer.keyAuthorizations = byNamespace("eu.europa.ec.eudi.pid.1");
        byte[] original;
        Map<CborItem, CborItem> response = new LinkedHashMap<>();
        response.put(CborEncoder.text("version"), CborEncoder.text("1.0"));
        response.put(
                CborEncoder.text("documents"),
                CborEncoder.array(signed(
                        deviceNamespaces("eu.europa.ec.eudi.pid.1", "given_name", "Erika"), TRANSCRIPT, DOCTYPE)));
        response.put(CborEncoder.text("status"), CborEncoder.integer(0));
        original = CborEncoder.map(response).encoded();
        MdocPresentationVerifier verifier = presentationVerifier();
        Map<String, Object> claims = verifier.verify(base64(CborEncoder.map(response)), DOCTYPE, TRANSCRIPT)
                .claims();
        java.util.Random random = new java.util.Random(7);
        int verified = 0;
        for (int i = 0; i < 3000; i++) {
            byte[] mutated = original.clone();
            int flips = 1 + random.nextInt(3);
            for (int f = 0; f < flips; f++) {
                mutated[random.nextInt(mutated.length)] ^= (byte) (1 << random.nextInt(8));
            }
            try {
                MdocPresentationVerifier.VerifiedMdoc result = verifier.verify(
                        Base64.getUrlEncoder().withoutPadding().encodeToString(mutated), DOCTYPE, TRANSCRIPT);
                // A flip in bytes nobody signs may still verify, for example a renamed nameSpaces key that drops
                // every element (DCQL then fails), but never with other or changed claims.
                assertThat(result.claims()).isIn(claims, Map.of());
                verified++;
            } catch (VerificationFailure expected) {
                // every other outcome must be a VerificationFailure, never another exception
            }
        }
        assertThat(verified).isLessThan(3000);
    }

    // -- helpers

    private CborItem signed(CborItem nameSpacesBytes, CborItem transcript, String docType) throws Exception {
        CborItem auth = signature(TestMdocIssuer.deviceSignature(
                issuer.deviceKeys.getPrivate(),
                -7,
                TestMdocIssuer.deviceAuthentication(transcript, docType, nameSpacesBytes),
                false));
        return TestMdocIssuer.withDeviceSigned(issuedDocument(), nameSpacesBytes, auth);
    }

    private CborItem issuedDocument() throws Exception {
        return issuer.document(
                DOCTYPE,
                DOCTYPE,
                DOCTYPE,
                Map.of("age_over_18", CborEncoder.bool(true)),
                NOW.minusSeconds(60),
                NOW.minusSeconds(60),
                NOW.plus(Duration.ofDays(30)));
    }

    private void authenticate(CborItem document) {
        CborItem.MapItem doc = (CborItem.MapItem) CborDecoder.decode(document.encoded());
        VerifiedIssuerSigned issuerSigned = issuerVerifier().verify(doc);
        MdocDeviceAuthentication.SIGNATURE.authenticate(doc, issuerSigned, TRANSCRIPT);
    }

    private void expect(CborItem document, String code) {
        assertThatThrownBy(() -> authenticate(document))
                .isInstanceOfSatisfying(
                        VerificationFailure.class, f -> assertThat(f.code()).isEqualTo(code));
    }

    private void expectResponse(CborItem response, String code) {
        if (code == null) {
            assertThatCode(() -> presentationVerifier().verify(base64(response), DOCTYPE, TRANSCRIPT))
                    .doesNotThrowAnyException();
        } else {
            assertThatThrownBy(() -> presentationVerifier().verify(base64(response), DOCTYPE, TRANSCRIPT))
                    .isInstanceOfSatisfying(
                            VerificationFailure.class, f -> assertThat(f.code()).isEqualTo(code));
        }
    }

    private static CborItem response(String version, Long status, CborItem document) {
        Map<CborItem, CborItem> response = new LinkedHashMap<>();
        if (version != null) {
            response.put(CborEncoder.text("version"), CborEncoder.text(version));
        }
        if (document != null) {
            response.put(CborEncoder.text("documents"), CborEncoder.array(document));
        }
        if (status != null) {
            response.put(CborEncoder.text("status"), CborEncoder.integer(status));
        }
        return CborEncoder.map(response);
    }

    private MdocIssuerVerifier issuerVerifier() {
        return new MdocIssuerVerifier(
                () -> TrustStore.of(List.of(issuer.iaca), "test"),
                Clock.fixed(NOW, ZoneOffset.UTC),
                Duration.ofMinutes(1),
                null,
                MdocIssuerVerifier.mdlOnly());
    }

    private MdocPresentationVerifier presentationVerifier() {
        return new MdocPresentationVerifier(issuerVerifier(), MdocDeviceAuthentication.SIGNATURE);
    }

    private static CborItem signature(CborItem coseSign1) {
        return CborEncoder.map(Map.of(CborEncoder.text("deviceSignature"), coseSign1));
    }

    private static CborItem deviceNamespaces(String namespace, String element, String value) {
        return CborEncoder.embedded(CborEncoder.map(Map.of(
                CborEncoder.text(namespace),
                CborEncoder.map(Map.of(CborEncoder.text(element), CborEncoder.text(value))))));
    }

    private static CborItem byNamespace(String namespace) {
        return CborEncoder.map(Map.of(CborEncoder.text("nameSpaces"), CborEncoder.array(CborEncoder.text(namespace))));
    }

    private static CborItem byElement(String namespace, String element) {
        return CborEncoder.map(Map.of(
                CborEncoder.text("dataElements"),
                CborEncoder.map(Map.of(CborEncoder.text(namespace), CborEncoder.array(CborEncoder.text(element))))));
    }

    private static String base64(CborItem item) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(item.encoded());
    }

    private static PrivateKey otherKey() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        return g.generateKeyPair().getPrivate();
    }

    private static TestMdocIssuer issuer() {
        try {
            return new TestMdocIssuer(
                    "CN=Test IACA,C=DE",
                    "CN=Test DS,C=DE",
                    true,
                    NOW.minus(Duration.ofDays(30)),
                    NOW.plus(Duration.ofDays(300)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
