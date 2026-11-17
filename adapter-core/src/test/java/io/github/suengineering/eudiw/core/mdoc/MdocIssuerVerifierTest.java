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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.authlete.cbor.CBORDecoder;
import com.authlete.cose.COSESign1;
import com.authlete.cose.COSEVerifier;
import io.github.suengineering.eudiw.core.VerificationFailure;
import io.github.suengineering.eudiw.core.cbor.CborDecoder;
import io.github.suengineering.eudiw.core.cbor.CborEncoder;
import io.github.suengineering.eudiw.core.cbor.CborItem;
import io.github.suengineering.eudiw.core.cose.CoseSign1;
import io.github.suengineering.eudiw.core.x509.CertificateChainValidator;
import io.github.suengineering.eudiw.core.x509.TestPki;
import io.github.suengineering.eudiw.core.x509.TrustStore;
import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Predicate;
import org.junit.jupiter.api.Test;

/** Issuer data authentication against mdocs issued by the independent eudi-dev wallet. */
class MdocIssuerVerifierTest {

    private static final X509Certificate IACA = certificate("src/test/resources/mdoc/iaca.crt");

    @Test
    void verifiesAnIndependentlyIssuedPid() {
        VerifiedIssuerSigned verified =
                verifier("pid", MdocIssuerVerifier.mdlOnly(), 0).verify(document("pid"));
        assertThat(verified.docType()).isEqualTo("eu.europa.ec.eudi.pid.1");
        Map<String, CborItem> pid = verified.elements().get("eu.europa.ec.eudi.pid.1");
        assertThat(pid).containsKeys("age_over_18", "given_name", "family_name");
        assertThat(pid.get("age_over_18")).isInstanceOf(CborItem.Simple.class);
        assertThat(((CborItem.Simple) pid.get("age_over_18")).value()).isEqualTo(CborItem.Simple.TRUE);
        assertThat(((CborItem.Text) pid.get("given_name")).value()).isEqualTo("Erika");
        assertThat(verified.trustSources()).containsExactly("test");
        assertThat(verified.mso().deviceKey()).isInstanceOf(CborItem.MapItem.class);
    }

    @Test
    void anIndependentCoseImplementationAgreesOnTheSignature() throws Exception {
        CborItem.MapItem issuerSigned = (CborItem.MapItem) CborDecoder.decode(fixture("pid"));
        CborItem issuerAuth = issuerSigned.get("issuerAuth").orElseThrow();
        X509Certificate signer = CertificateChainValidator.parse(
                        CoseSign1.parse(issuerAuth).x5chain())
                .get(0);
        COSESign1 theirs = COSESign1.build(new CBORDecoder(issuerAuth.encoded()).next());
        assertThat(new COSEVerifier(signer.getPublicKey()).verify(theirs)).isTrue();
    }

    @Test
    void theIacaProfileAppliesToTheMdlDocType() {
        assertThat(verifier("mdl", MdocIssuerVerifier.mdlOnly(), 0)
                        .verify(document("mdl"))
                        .elements())
                .containsKey("org.iso.18013.5.1");
        assertThatThrownBy(() ->
                        verifier("mdl-noeku", MdocIssuerVerifier.mdlOnly(), 0).verify(document("mdl-noeku")))
                .isInstanceOfSatisfying(
                        VerificationFailure.class, f -> assertThat(f.code()).isEqualTo("certificate_chain_invalid"))
                .hasMessageContaining("extended key usage");
        // Without the profile the same credential verifies: only the profile needs the EKU.
        assertThat(verifier("mdl-noeku", d -> false, 0)
                        .verify(document("mdl-noeku"))
                        .docType())
                .isEqualTo("org.iso.18013.5.1.mDL");
    }

    @Test
    void aChangedElementValueBreaksItsDigest() {
        CborItem tampered = withItems("pid", items -> {
            List<CborItem> out = new ArrayList<>();
            for (CborItem bytes : items) {
                CborItem.MapItem item = embedded(bytes);
                if (text(item, "elementIdentifier").equals("age_over_18")) {
                    item = replace(item, "elementValue", CborEncoder.bool(false));
                }
                out.add(CborEncoder.embedded(item));
            }
            return out;
        });
        expect(tampered, "invalid_disclosure");
    }

    @Test
    void anItemWithAnUnknownDigestIdIsRejected() {
        expect(
                withItems(
                        "pid",
                        items -> List.of(CborEncoder.embedded(
                                replace(embedded(items.get(0)), "digestID", CborEncoder.integer(999_999))))),
                "invalid_disclosure");
    }

    @Test
    void aRepeatedItemIsRejected() {
        expect(withItems("pid", items -> List.of(items.get(0), items.get(0))), "duplicate_disclosure");
    }

    @Test
    void theDocumentTypeMustMatchTheMso() {
        CborItem.MapItem doc = (CborItem.MapItem) document("pid");
        expect(replace(doc, "docType", CborEncoder.text("org.iso.18013.5.1.mDL")), "credential_mismatch");
    }

    @Test
    void aChangedSignatureIsRejected() {
        CborItem.MapItem doc = (CborItem.MapItem) document("pid");
        CborItem.MapItem issuerSigned =
                (CborItem.MapItem) doc.get("issuerSigned").orElseThrow();
        CborItem.Array auth = (CborItem.Array) issuerSigned.get("issuerAuth").orElseThrow();
        byte[] signature = ((CborItem.Bytes) auth.items().get(3)).value();
        signature[10] ^= 0x01;
        List<CborItem> parts = new ArrayList<>(auth.items());
        parts.set(3, CborEncoder.bytes(signature));
        expect(
                replace(doc, "issuerSigned", replace(issuerSigned, "issuerAuth", CborEncoder.array(parts))),
                "invalid_signature");
    }

    @Test
    void anUntrustedIssuerIsRejected() {
        X509Certificate other = TestPki.rootCa(
                        "CN=Other IACA",
                        Instant.now().minusSeconds(3600),
                        Instant.now().plusSeconds(86400))
                .certificate();
        MdocIssuerVerifier untrusted = new MdocIssuerVerifier(
                () -> TrustStore.of(List.of(other), "test"),
                clockAt("pid", 0),
                Duration.ofMinutes(1),
                null,
                MdocIssuerVerifier.mdlOnly());
        assertThatThrownBy(() -> untrusted.verify(document("pid")))
                .isInstanceOfSatisfying(
                        VerificationFailure.class, f -> assertThat(f.code()).isEqualTo("certificate_untrusted"));
    }

    @Test
    void validityIsEnforced() {
        MobileSecurityObject mso = mso("pid");
        // Inside the signer certificate validity, outside the one-minute skew.
        long beforeFrom = Duration.between(mso.signed(), mso.validFrom()).toSeconds() - 120;
        long afterUntil = Duration.between(mso.signed(), mso.validUntil()).toSeconds() + 3600;
        assertThatThrownBy(() -> verifier("pid", MdocIssuerVerifier.mdlOnly(), beforeFrom)
                        .verify(document("pid")))
                .isInstanceOfSatisfying(
                        VerificationFailure.class, f -> assertThat(f.code()).isEqualTo("credential_not_yet_valid"));
        assertThatThrownBy(() -> verifier("pid", MdocIssuerVerifier.mdlOnly(), afterUntil)
                        .verify(document("pid")))
                .isInstanceOfSatisfying(
                        VerificationFailure.class, f -> assertThat(f.code()).isEqualTo("credential_expired"));
    }

    // -- rejection cases the independent fixtures cannot produce, with a synthetic issuer

    private static final Instant NOW = Instant.parse("2026-06-01T12:00:00Z");

    private static VerifiedIssuerSigned verifyBuilt(TestMdocIssuer issuer, CborItem document) {
        return new MdocIssuerVerifier(
                        () -> TrustStore.of(List.of(issuer.iaca), "test"),
                        Clock.fixed(NOW, ZoneOffset.UTC),
                        Duration.ofMinutes(1),
                        null,
                        MdocIssuerVerifier.mdlOnly())
                .verify(document);
    }

    private static TestMdocIssuer issuer(String iaca, String signer, boolean eku) throws Exception {
        return new TestMdocIssuer(iaca, signer, eku, NOW.minus(Duration.ofDays(30)), NOW.plus(Duration.ofDays(300)));
    }

    private static CborItem mdl(TestMdocIssuer issuer, Instant signed, Instant from, String msoNamespace)
            throws Exception {
        return issuer.document(
                MdocIssuerVerifier.MDL_DOCTYPE,
                "org.iso.18013.5.1",
                msoNamespace,
                Map.of("age_over_18", CborEncoder.bool(true)),
                signed,
                from,
                NOW.plus(Duration.ofDays(30)));
    }

    @Test
    void aSyntheticIssuerVerifiesAndMayRoundValidFromDown() throws Exception {
        TestMdocIssuer issuer = issuer("CN=Test IACA,ST=BY,C=DE", "CN=Test DS,ST=BY,C=DE", true);
        assertThat(verifyBuilt(issuer, mdl(issuer, NOW.minusSeconds(60), NOW.minusSeconds(60), "org.iso.18013.5.1"))
                        .elements())
                .containsKey("org.iso.18013.5.1");
        // validFrom earlier than signed is an issuer's choice, not a reason to refuse.
        assertThat(verifyBuilt(
                                issuer,
                                mdl(issuer, NOW.minusSeconds(60), NOW.minus(Duration.ofDays(1)), "org.iso.18013.5.1"))
                        .docType())
                .isEqualTo(MdocIssuerVerifier.MDL_DOCTYPE);
    }

    @Test
    void anMsoSignedOutsideTheSignerValidityIsRejected() throws Exception {
        TestMdocIssuer issuer = issuer("CN=Test IACA,C=DE", "CN=Test DS,C=DE", true);
        CborItem document = mdl(issuer, NOW.minus(Duration.ofDays(60)), NOW.minusSeconds(60), "org.iso.18013.5.1");
        assertThatThrownBy(() -> verifyBuilt(issuer, document))
                .isInstanceOfSatisfying(
                        VerificationFailure.class, f -> assertThat(f.code()).isEqualTo("certificate_chain_invalid"))
                .hasMessageContaining("outside the certificate validity");
    }

    @Test
    void theIacaCountryAndStateMustMatchTheSigner() throws Exception {
        TestMdocIssuer country = issuer("CN=Test IACA,C=DE", "CN=Test DS,C=FR", true);
        assertThatThrownBy(() -> verifyBuilt(
                        country, mdl(country, NOW.minusSeconds(60), NOW.minusSeconds(60), "org.iso.18013.5.1")))
                .isInstanceOfSatisfying(
                        VerificationFailure.class, f -> assertThat(f.code()).isEqualTo("certificate_chain_invalid"))
                .hasMessageContaining("country");
        TestMdocIssuer state = issuer("CN=Test IACA,ST=BY,C=DE", "CN=Test DS,ST=BE,C=DE", true);
        assertThatThrownBy(() ->
                        verifyBuilt(state, mdl(state, NOW.minusSeconds(60), NOW.minusSeconds(60), "org.iso.18013.5.1")))
                .hasMessageContaining("state");
        // A state in the IACA must be repeated in the document signer; one only in the signer is fine.
        TestMdocIssuer dropped = issuer("CN=Test IACA,ST=BY,C=DE", "CN=Test DS,C=DE", true);
        assertThatThrownBy(() -> verifyBuilt(
                        dropped, mdl(dropped, NOW.minusSeconds(60), NOW.minusSeconds(60), "org.iso.18013.5.1")))
                .hasMessageContaining("state");
        TestMdocIssuer added = issuer("CN=Test IACA,C=DE", "CN=Test DS,ST=BY,C=DE", true);
        assertThat(verifyBuilt(added, mdl(added, NOW.minusSeconds(60), NOW.minusSeconds(60), "org.iso.18013.5.1"))
                        .docType())
                .isEqualTo(MdocIssuerVerifier.MDL_DOCTYPE);
    }

    @Test
    void issuingCountryAndJurisdictionMustMatchTheSigner() throws Exception {
        TestMdocIssuer issuer = issuer("CN=Test IACA,ST=BY,C=DE", "CN=Test DS,ST=BY,C=DE", true);
        java.util.function.BiFunction<String, String, CborItem> mdl = (element, value) -> {
            try {
                return issuer.document(
                        MdocIssuerVerifier.MDL_DOCTYPE,
                        "org.iso.18013.5.1",
                        "org.iso.18013.5.1",
                        Map.of(element, CborEncoder.text(value)),
                        NOW.minusSeconds(60),
                        NOW.minusSeconds(60),
                        NOW.plus(Duration.ofDays(30)));
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        };
        assertThat(verifyBuilt(issuer, mdl.apply("issuing_country", "DE")).elements())
                .isNotEmpty();
        assertThat(verifyBuilt(issuer, mdl.apply("issuing_jurisdiction", "BY")).elements())
                .isNotEmpty();
        assertThatThrownBy(() -> verifyBuilt(issuer, mdl.apply("issuing_country", "FR")))
                .isInstanceOfSatisfying(
                        VerificationFailure.class, f -> assertThat(f.code()).isEqualTo("credential_mismatch"));
        assertThatThrownBy(() -> verifyBuilt(issuer, mdl.apply("issuing_jurisdiction", "BE")))
                .isInstanceOfSatisfying(
                        VerificationFailure.class, f -> assertThat(f.code()).isEqualTo("credential_mismatch"));
    }

    @Test
    void aNamespaceWithoutDigestsIsRejected() throws Exception {
        TestMdocIssuer issuer = issuer("CN=Test IACA,C=DE", "CN=Test DS,C=DE", true);
        CborItem document = mdl(issuer, NOW.minusSeconds(60), NOW.minusSeconds(60), "org.iso.18013.5.1.DE");
        assertThatThrownBy(() -> verifyBuilt(issuer, document))
                .isInstanceOfSatisfying(
                        VerificationFailure.class, f -> assertThat(f.code()).isEqualTo("invalid_disclosure"));
    }

    /**
     * Random mutations of a real Document: nothing but a VerificationFailure escapes, and whatever still verifies
     * (a mutation can hide the optional nameSpaces entry, which discloses nothing) never carries a changed value.
     */
    @Test
    void mutatedDocumentsNeverVerifyWithChangedContent() {
        byte[] original = document("pid").encoded();
        MdocIssuerVerifier verifier = verifier("pid", MdocIssuerVerifier.mdlOnly(), 0);
        Map<String, Map<String, CborItem>> genuine =
                verifier.verify(CborDecoder.decode(original)).elements();
        java.util.Random random = new java.util.Random(9312);
        for (int i = 0; i < 3000; i++) {
            byte[] mutated = original.clone();
            for (int f = 1 + random.nextInt(3); f > 0; f--) {
                mutated[random.nextInt(mutated.length)] = (byte) random.nextInt(256);
            }
            VerifiedIssuerSigned verified;
            try {
                verified = verifier.verify(CborDecoder.decode(mutated));
            } catch (VerificationFailure expected) {
                continue;
            }
            verified.elements()
                    .forEach((ns, values) ->
                            values.forEach((element, value) -> assertThat(genuine.getOrDefault(ns, Map.of())
                                            .get(element)
                                            .encoded())
                                    .isEqualTo(value.encoded())));
        }
    }

    // -- helpers

    private static void expect(CborItem document, String code) {
        assertThatThrownBy(
                        () -> verifier("pid", MdocIssuerVerifier.mdlOnly(), 0).verify(document))
                .isInstanceOfSatisfying(
                        VerificationFailure.class, f -> assertThat(f.code()).isEqualTo(code));
    }

    /** A verifier trusting the test IACA, with the clock {@code offsetSeconds} after the MSO was signed. */
    private static MdocIssuerVerifier verifier(String fixture, Predicate<String> profile, long offsetSeconds) {
        return new MdocIssuerVerifier(
                () -> TrustStore.of(List.of(IACA), "test"),
                clockAt(fixture, offsetSeconds == 0 ? 3600 : offsetSeconds),
                Duration.ofMinutes(1),
                null,
                profile);
    }

    private static Clock clockAt(String fixture, long offsetSeconds) {
        return Clock.fixed(mso(fixture).signed().plusSeconds(offsetSeconds), ZoneOffset.UTC);
    }

    private static MobileSecurityObject mso(String fixture) {
        CborItem.MapItem issuerSigned = (CborItem.MapItem) CborDecoder.decode(fixture(fixture));
        return MobileSecurityObject.parse(
                CoseSign1.parse(issuerSigned.get("issuerAuth").orElseThrow())
                        .payload()
                        .orElseThrow());
    }

    /** A Document (clause 8.3.2.1.2.2) around a fixture's IssuerSigned; device signing is not part of this test. */
    static CborItem document(String fixture) {
        CborItem issuerSigned = CborDecoder.decode(fixture(fixture));
        CborItem.MapItem mso = (CborItem.MapItem) issuerSigned;
        String docType = mso(fixture).docType();
        Map<CborItem, CborItem> doc = new LinkedHashMap<>();
        doc.put(CborEncoder.text("docType"), CborEncoder.text(docType));
        doc.put(CborEncoder.text("issuerSigned"), mso);
        return CborEncoder.map(doc);
    }

    private static CborItem withItems(String fixture, Function<List<CborItem>, List<CborItem>> change) {
        CborItem.MapItem doc = (CborItem.MapItem) document(fixture);
        CborItem.MapItem issuerSigned =
                (CborItem.MapItem) doc.get("issuerSigned").orElseThrow();
        CborItem.MapItem nameSpaces =
                (CborItem.MapItem) issuerSigned.get("nameSpaces").orElseThrow();
        Map<CborItem, CborItem> changed = new LinkedHashMap<>();
        nameSpaces
                .entries()
                .forEach((ns, items) ->
                        changed.put(ns, CborEncoder.array(change.apply(((CborItem.Array) items).items()))));
        return replace(doc, "issuerSigned", replace(issuerSigned, "nameSpaces", CborEncoder.map(changed)));
    }

    private static CborItem.MapItem replace(CborItem.MapItem map, String key, CborItem value) {
        Map<CborItem, CborItem> out = new LinkedHashMap<>();
        map.entries()
                .forEach((k, v) ->
                        out.put(k, k instanceof CborItem.Text t && t.value().equals(key) ? value : v));
        return CborEncoder.map(out);
    }

    private static CborItem.MapItem embedded(CborItem item) {
        return (CborItem.MapItem) CborDecoder.decode(((CborItem.Bytes) ((CborItem.Tag) item).content()).value());
    }

    private static String text(CborItem.MapItem map, String key) {
        return ((CborItem.Text) map.get(key).orElseThrow()).value();
    }

    static byte[] fixture(String name) {
        try {
            return Base64.getUrlDecoder()
                    .decode(Files.readString(Path.of("src/test/resources/mdoc/eudi-dev-" + name + ".issuer-signed.b64"))
                            .strip());
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static X509Certificate certificate(String path) {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(Files.readAllBytes(Path.of(path))));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
