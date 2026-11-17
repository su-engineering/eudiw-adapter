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
package io.github.suengineering.eudiw.core.trust;

import static io.github.suengineering.eudiw.core.trust.TrustedListFixtures.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import io.github.suengineering.eudiw.core.VerificationFailure;
import io.github.suengineering.eudiw.core.json.Json;
import io.github.suengineering.eudiw.core.net.HttpFetcher;
import io.github.suengineering.eudiw.core.x509.TestPki;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.interfaces.ECPrivateKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.jupiter.api.Test;

class TrustedListTest {

    private static final Instant NOW = Instant.parse("2026-11-16T12:00:00Z");
    private static final Instant ISSUED = Instant.parse("2026-11-01T00:00:00Z");
    private static final Instant NEXT = Instant.parse("2027-04-01T00:00:00Z");
    private static final String LOTL = "https://lotl.example/lotl.xml";
    private static final String TL_AA = "https://tl.example/aa.xml";
    private static final String TL_BB = "https://tl.example/bb.xml";

    private static final TestPki.Issued SIGNER_ROOT =
            TestPki.rootCa("CN=List Signing Root", NOW.minus(Duration.ofDays(400)), NOW.plus(Duration.ofDays(4000)));
    private static final TestPki.Issued LOTL_SIGNER = signer("CN=LOTL Signer,O=Example Operator,C=EU");
    private static final TestPki.Issued TL_SIGNER = signer("CN=TL Signer,O=Example Operator,C=AA");
    private static final TestPki.Issued OTHER_SIGNER = signer("CN=Someone Else,O=Elsewhere,C=ZZ");
    private static final TestPki.Issued EAA_CA =
            TestPki.rootCa("CN=QEAA Provider CA", NOW.minus(Duration.ofDays(30)), NOW.plus(Duration.ofDays(3000)));
    private static final TestPki.Issued WITHDRAWN_CA =
            TestPki.rootCa("CN=Withdrawn CA", NOW.minus(Duration.ofDays(30)), NOW.plus(Duration.ofDays(3000)));
    private static final TestPki.Issued QC_CA =
            TestPki.rootCa("CN=QC CA", NOW.minus(Duration.ofDays(30)), NOW.plus(Duration.ofDays(3000)));

    private static TestPki.Issued signer(String name) {
        return TestPki.endEntity(
                name,
                SIGNER_ROOT,
                NOW.minus(Duration.ofDays(365)),
                NOW.plus(Duration.ofDays(1000)),
                KeyUsage.digitalSignature,
                List.of());
    }

    private static String nationalXml(long sequence) {
        return xml(
                "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric",
                "AA",
                sequence,
                ISSUED,
                NEXT,
                List.of(),
                List.of(
                        new XmlService("QEAA Provider", EAA_Q, GRANTED, EAA_CA.certificate()),
                        new XmlService("Former Provider", EAA_Q, WITHDRAWN, WITHDRAWN_CA.certificate()),
                        new XmlService("QC Provider", CA_QC, GRANTED, QC_CA.certificate())));
    }

    private static String lotlXml() {
        return xml(
                TrustedList.TSL_TYPE_EU_LOTL,
                "EU",
                7,
                ISSUED,
                NEXT,
                List.of(
                        new XmlPointer(LOTL, "EU", TrustedList.MIME_TSL_XML, LOTL_SIGNER.certificate()),
                        new XmlPointer(TL_AA, "AA", TrustedList.MIME_TSL_XML, TL_SIGNER.certificate()),
                        new XmlPointer(TL_BB, "BB", "application/pdf", TL_SIGNER.certificate())),
                List.of());
    }

    // ---- TS 119 612 XML ----

    @Test
    void onlySha2SignatureAndDigestAlgorithmsAreAccepted() {
        String sha1 = "http://www.w3.org/2000/09/xmldsig#sha1";
        String sha224 = "http://www.w3.org/2001/04/xmldsig-more#sha224";
        String ecdsaSha1 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1";
        // SHA-1 is also refused by the JDK's secure validation; SHA-224 is not, so the allow-list refuses it.
        for (String[] algorithms : List.of(
                new String[] {sha1, javax.xml.crypto.dsig.SignatureMethod.ECDSA_SHA256, ""},
                new String[] {javax.xml.crypto.dsig.DigestMethod.SHA256, ecdsaSha1, ""},
                new String[] {sha224, javax.xml.crypto.dsig.SignatureMethod.ECDSA_SHA256, "not allowed"},
                new String[] {
                    javax.xml.crypto.dsig.DigestMethod.SHA256,
                    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224",
                    "not allowed"
                })) {
            byte[] signed = TrustedListFixtures.signXml(nationalXml(3), TL_SIGNER, "", algorithms[0], algorithms[1]);
            assertThatThrownBy(() -> TslXmlParser.verify(signed, TL_AA, List.of(TL_SIGNER.certificate())))
                    .isInstanceOfSatisfying(VerificationFailure.class, f -> assertThat(f.code())
                            .isEqualTo("trusted_list_signature_invalid"))
                    .hasMessageContaining(algorithms[2]);
        }
        byte[] sha512 = TrustedListFixtures.signXml(
                nationalXml(3),
                TL_SIGNER,
                "",
                javax.xml.crypto.dsig.DigestMethod.SHA512,
                javax.xml.crypto.dsig.SignatureMethod.ECDSA_SHA512);
        assertThat(TslXmlParser.verify(sha512, TL_AA, List.of(TL_SIGNER.certificate()))
                        .sequenceNumber())
                .isEqualTo(3);
    }

    @Test
    void readsASignedXmlTrustedList() {
        TrustedList list =
                TslXmlParser.verify(signXml(nationalXml(3), TL_SIGNER), TL_AA, List.of(TL_SIGNER.certificate()));

        assertThat(list.format()).isEqualTo(TrustedList.Format.TSL_XML);
        assertThat(list.territory()).contains("AA");
        assertThat(list.sequenceNumber()).isEqualTo(3);
        assertThat(list.nextUpdate()).contains(NEXT);
        assertThat(list.services()).hasSize(3);
        assertThat(list.services().get(0).entityName()).isEqualTo("QEAA Provider");
        assertThat(list.services().get(0).type()).contains(EAA_Q);
        assertThat(list.services().get(0).certificates()).containsExactly(EAA_CA.certificate());
    }

    @Test
    void readsPointersOfAListOfTrustedLists() {
        TrustedList lotl =
                TslXmlParser.verify(signXml(lotlXml(), LOTL_SIGNER), LOTL, List.of(LOTL_SIGNER.certificate()));

        assertThat(lotl.pointers()).hasSize(3);
        TrustedList.Pointer aa = lotl.pointers().get(1);
        assertThat(aa.location()).isEqualTo(TL_AA);
        assertThat(aa.territory()).contains("AA");
        assertThat(aa.mimeType()).contains(TrustedList.MIME_TSL_XML);
        assertThat(aa.signerCertificates()).containsExactly(TL_SIGNER.certificate());
    }

    @Test
    void referenceToTheRootIdAlsoCoversTheList() {
        TrustedList list = TslXmlParser.verify(
                signXml(nationalXml(3), TL_SIGNER, "#tsl"), TL_AA, List.of(TL_SIGNER.certificate()));
        assertThat(list.services()).hasSize(3);
    }

    @Test
    void rejectsATamperedXmlList() {
        String signed = new String(signXml(nationalXml(3), TL_SIGNER), StandardCharsets.UTF_8);
        String tampered = signed.replaceFirst(WITHDRAWN, GRANTED);
        assertThat(tampered).isNotEqualTo(signed);

        assertFailure(
                () -> TslXmlParser.verify(
                        tampered.getBytes(StandardCharsets.UTF_8), TL_AA, List.of(TL_SIGNER.certificate())),
                "trusted_list_signature_invalid");
    }

    @Test
    void rejectsAnXmlListFromAnotherSigner() {
        assertFailure(
                () -> TslXmlParser.verify(
                        signXml(nationalXml(3), OTHER_SIGNER), TL_AA, List.of(TL_SIGNER.certificate())),
                "trusted_list_signer_untrusted");
    }

    @Test
    void rejectsDoctypesAndEntities() {
        String xxe = "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]>"
                + "<tsl:TrustServiceStatusList xmlns:tsl=\"http://uri.etsi.org/02231/v2#\">&e;</tsl:TrustServiceStatusList>";
        assertFailure(
                () -> TslXmlParser.verify(
                        xxe.getBytes(StandardCharsets.UTF_8), TL_AA, List.of(TL_SIGNER.certificate())),
                "trusted_list_invalid");
    }

    @Test
    void rejectsASignatureThatCoversOnlyPartOfTheList() {
        // Signature wrapping: a valid signature over one element must not authenticate the rest.
        String xml = nationalXml(3).replace("<tsl:SchemeInformation>", "<tsl:SchemeInformation Id=\"part\">");
        byte[] signed = signXmlWithIdOn(xml, "SchemeInformation", "#part");
        assertFailure(
                () -> TslXmlParser.verify(signed, TL_AA, List.of(TL_SIGNER.certificate())),
                "trusted_list_signature_invalid");
    }

    @Test
    void rejectsExternalReferencesBeforeDereferencingThem() {
        String signed = new String(signXml(nationalXml(3), TL_SIGNER), StandardCharsets.UTF_8);
        String external = "<ds:Reference URI=\"https://attacker.example/x\"><ds:DigestMethod"
                + " Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference>";
        String injected = signed.replaceFirst(
                "(<ds:SignedInfo[^>]*>.*?</ds:SignatureMethod>|<ds:SignedInfo[^>]*>.*?<ds:SignatureMethod[^>]*/>)",
                "$1" + external);
        assertThat(injected).contains("attacker.example");

        assertThatThrownBy(() -> TslXmlParser.verify(
                        injected.getBytes(StandardCharsets.UTF_8), TL_AA, List.of(TL_SIGNER.certificate())))
                .isInstanceOfSatisfying(VerificationFailure.class, f -> {
                    assertThat(f.code()).isEqualTo("trusted_list_signature_invalid");
                    assertThat(f.getMessage()).contains("same-document");
                });
    }

    @Test
    void rejectsTwoSignatures() {
        String once = new String(signXml(nationalXml(3), TL_SIGNER), StandardCharsets.UTF_8);
        int start = once.indexOf("<ds:Signature");
        String signature = once.substring(start, once.indexOf("</ds:Signature>") + "</ds:Signature>".length());
        String twice = once.replace("</tsl:TrustServiceStatusList>", signature + "</tsl:TrustServiceStatusList>");
        assertFailure(
                () -> TslXmlParser.verify(
                        twice.getBytes(StandardCharsets.UTF_8), TL_AA, List.of(TL_SIGNER.certificate())),
                "trusted_list_signature_invalid");
    }

    @Test
    void rejectsAListValidForMoreThanSixMonths() {
        String xml = xml("t", "AA", 1, ISSUED, ISSUED.plus(Duration.ofDays(200)), List.of(), List.of());
        assertFailure(
                () -> TslXmlParser.verify(signXml(xml, TL_SIGNER), TL_AA, List.of(TL_SIGNER.certificate())),
                "trusted_list_invalid");
    }

    @Test
    void acceptsTheXadesShapeWithSignedPropertiesAndDetectsTheirTampering() {
        byte[] signed = signXmlXades(nationalXml(3), TL_SIGNER);
        assertThat(TslXmlParser.verify(signed, TL_AA, List.of(TL_SIGNER.certificate()))
                        .services())
                .hasSize(3);

        String tampered = new String(signed, StandardCharsets.UTF_8)
                .replace("2026-11-01T00:00:00Z</xades", "2026-11-02T00:00:00Z</xades");
        assertThat(tampered).isNotEqualTo(new String(signed, StandardCharsets.UTF_8));
        assertFailure(
                () -> TslXmlParser.verify(
                        tampered.getBytes(StandardCharsets.UTF_8), TL_AA, List.of(TL_SIGNER.certificate())),
                "trusted_list_signature_invalid");
    }

    @Test
    void rejectsAForgedRootWrappingAGenuineSignedList() {
        String genuine = new String(signXml(nationalXml(3), TL_SIGNER, "#tsl"), StandardCharsets.UTF_8)
                .replaceFirst("<\\?xml[^>]*>", "");
        int start = genuine.indexOf("<ds:Signature");
        int end = genuine.indexOf("</ds:Signature>") + "</ds:Signature>".length();
        String signature = genuine.substring(start, end);
        String unsignedGenuine = genuine.substring(0, start) + genuine.substring(end);
        String forgedBody = nationalXml(3)
                .replace(WITHDRAWN, GRANTED)
                .replaceFirst("<tsl:TrustServiceStatusList [^>]*>", "")
                .replace("</tsl:TrustServiceStatusList>", "");
        for (String rootAttributes : List.of("", " Id=\"tsl\"")) {
            String forged = "<tsl:TrustServiceStatusList xmlns:tsl=\"http://uri.etsi.org/02231/v2#\""
                    + " xmlns:tslx=\"http://uri.etsi.org/02231/v2/additionaltypes#\"" + rootAttributes + ">"
                    + forgedBody
                    + signature
                    + "<tsl:Hidden>" + unsignedGenuine + "</tsl:Hidden>"
                    + "</tsl:TrustServiceStatusList>";
            assertFailure(
                    () -> TslXmlParser.verify(
                            forged.getBytes(StandardCharsets.UTF_8), TL_AA, List.of(TL_SIGNER.certificate())),
                    "trusted_list_signature_invalid");
        }
    }

    @Test
    void mutatedListsFailOnlyWithCodedFailures() {
        java.util.Random random = new java.util.Random(20261117);
        List<byte[]> seeds = List.of(
                signXml(nationalXml(3), TL_SIGNER),
                signLote(
                        lote("t", 1, ISSUED, NEXT, List.of(entity("P", PID_ISSUANCE, EAA_CA.certificate()))),
                        LOTL_SIGNER,
                        Map.of()));
        int accepted = 0;
        for (int i = 0; i < 3000; i++) {
            byte[] seed = seeds.get(i % 2);
            byte[] mutated = mutate(seed, random);
            try {
                if (i % 2 == 0) {
                    TslXmlParser.verify(mutated, TL_AA, List.of(TL_SIGNER.certificate()));
                } else {
                    LoteJsonParser.verify(mutated, "x", List.of(LOTL_SIGNER.certificate()));
                }
                accepted++;
            } catch (VerificationFailure expected) {
                assertThat(expected.code()).startsWith("trusted_list_");
            }
        }
        // Some mutations land in insignificant whitespace or base64 padding and keep the list valid.
        assertThat(accepted).isLessThan(300);
    }

    private static byte[] mutate(byte[] seed, java.util.Random random) {
        byte[] copy = seed.clone();
        switch (random.nextInt(3)) {
            case 0 -> copy[random.nextInt(copy.length)] = (byte) random.nextInt(256);
            case 1 -> copy = java.util.Arrays.copyOf(copy, random.nextInt(copy.length));
            default -> {
                int at = random.nextInt(copy.length);
                byte[] longer = new byte[copy.length + 1];
                System.arraycopy(copy, 0, longer, 0, at);
                String pool = "<>&\"'{}[],:\\=.~";
                longer[at] = (byte) pool.charAt(random.nextInt(pool.length()));
                System.arraycopy(copy, at, longer, at + 1, copy.length - at);
                copy = longer;
            }
        }
        return copy;
    }

    // ---- TS 119 602 JSON ----

    @Test
    void readsASignedListOfTrustedEntities() {
        byte[] signed = signLote(
                lote(
                        "http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList",
                        1,
                        ISSUED,
                        NEXT,
                        List.of(entity("PID Provider AA", PID_ISSUANCE, EAA_CA.certificate()))),
                LOTL_SIGNER,
                Map.of());
        TrustedList list =
                LoteJsonParser.verify(signed, "https://pid.example/list.jwt", List.of(LOTL_SIGNER.certificate()));

        assertThat(list.format()).isEqualTo(TrustedList.Format.LOTE_JSON);
        assertThat(list.type()).contains("http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList");
        assertThat(list.services()).singleElement().satisfies(s -> {
            assertThat(s.entityName()).isEqualTo("PID Provider AA");
            assertThat(s.type()).contains(PID_ISSUANCE);
            assertThat(s.status()).isEmpty();
            assertThat(s.certificates()).containsExactly(EAA_CA.certificate());
        });
    }

    @Test
    void identifiesTheSignerByThumbprint() throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .x509CertSHA256Thumbprint(Base64URL.encode(MessageDigest.getInstance("SHA-256")
                        .digest(LOTL_SIGNER.certificate().getEncoded())))
                .build();
        byte[] signed = sign(header, lote("t", 1, ISSUED, NEXT, List.of()), LOTL_SIGNER);
        assertThat(LoteJsonParser.verify(signed, "x", List.of(LOTL_SIGNER.certificate()))
                        .services())
                .isEmpty();

        assertFailure(
                () -> LoteJsonParser.verify(signed, "x", List.of(TL_SIGNER.certificate())),
                "trusted_list_signer_untrusted");
    }

    @Test
    void rejectsATamperedListOfTrustedEntities() {
        String jws = new String(
                signLote(lote("t", 1, ISSUED, NEXT, List.of()), LOTL_SIGNER, Map.of()), StandardCharsets.US_ASCII);
        String[] parts = jws.split("\\.");
        String payload = Base64URL.encode(Json.toJson(lote("t", 9, ISSUED, NEXT, List.of())))
                .toString();
        byte[] tampered = (parts[0] + "." + payload + "." + parts[2]).getBytes(StandardCharsets.US_ASCII);

        assertFailure(
                () -> LoteJsonParser.verify(tampered, "x", List.of(LOTL_SIGNER.certificate())),
                "trusted_list_signature_invalid");
    }

    @Test
    void rejectsAListOfTrustedEntitiesFromAnotherSigner() {
        byte[] signed = signLote(lote("t", 1, ISSUED, NEXT, List.of()), OTHER_SIGNER, Map.of());
        assertFailure(
                () -> LoteJsonParser.verify(signed, "x", List.of(LOTL_SIGNER.certificate())),
                "trusted_list_signer_untrusted");
    }

    @Test
    void rejectsDetachedAndUnknownCriticalJadesSignatures() throws Exception {
        byte[] detached = signLote(lote("t", 1, ISSUED, NEXT, List.of()), LOTL_SIGNER, Map.of("sigD", Map.of()));
        assertFailure(
                () -> LoteJsonParser.verify(detached, "x", List.of(LOTL_SIGNER.certificate())), "trusted_list_invalid");

        JWSHeader critical = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .x509CertChain(List.of(Base64.encode(LOTL_SIGNER.certificate().getEncoded())))
                .criticalParams(Set.of("sigPl"))
                .customParam("sigPl", Map.of())
                .build();
        byte[] signed = sign(critical, lote("t", 1, ISSUED, NEXT, List.of()), LOTL_SIGNER);
        assertFailure(
                () -> LoteJsonParser.verify(signed, "x", List.of(LOTL_SIGNER.certificate())),
                "trusted_list_signature_invalid");

        JWSHeader sigT = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .x509CertChain(List.of(Base64.encode(LOTL_SIGNER.certificate().getEncoded())))
                .criticalParams(Set.of("sigT"))
                .customParam("sigT", "2026-11-01T00:00:00Z")
                .build();
        byte[] accepted = sign(sigT, lote("t", 1, ISSUED, NEXT, List.of()), LOTL_SIGNER);
        assertThat(LoteJsonParser.verify(accepted, "x", List.of(LOTL_SIGNER.certificate()))
                        .sequenceNumber())
                .isEqualTo(1);
    }

    @Test
    void aMalformedOrFutureJadesSigningTimeIsRefused() throws Exception {
        for (Object value : List.of(
                "2026-11-01T01:00:00+01:00",
                "yesterday",
                1_793_491_200L,
                Instant.now().plus(Duration.ofHours(1)).toString())) {
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .x509CertChain(
                            List.of(Base64.encode(LOTL_SIGNER.certificate().getEncoded())))
                    .criticalParams(Set.of("sigT"))
                    .customParam("sigT", value)
                    .build();
            byte[] signed = sign(header, lote("t", 1, ISSUED, NEXT, List.of()), LOTL_SIGNER);
            assertFailure(
                    () -> LoteJsonParser.verify(signed, "x", List.of(LOTL_SIGNER.certificate())),
                    "trusted_list_invalid");
        }
    }

    // ---- loading, pointers, freshness ----

    @Test
    void followsTheListOfTrustedListsAndKeepsOnlyApprovedServicesOfTheWantedType() {
        Map<String, byte[]> served = new HashMap<>();
        served.put(LOTL, signXml(lotlXml(), LOTL_SIGNER));
        served.put(TL_AA, signXml(nationalXml(3), TL_SIGNER));
        TrustedLists lists = registry(served, Clock.fixed(NOW, ZoneOffset.UTC));

        List<TrustedLists.LoadResult> results = lists.refresh();

        assertThat(results).extracting(TrustedLists.LoadResult::location).containsExactly(LOTL, TL_AA);
        assertThat(results).allMatch(TrustedLists.LoadResult::ok);
        assertThat(lists.issuance().certificates()).containsExactly(EAA_CA.certificate());
        assertThat(lists.issuance().sourcesOf(EAA_CA.certificate())).containsExactlyInAnyOrder(TL_AA, LOTL);
        // The provider that publishes a certificate names it for issuer allow lists.
        assertThat(lists.issuance().entityNamesOf(EAA_CA.certificate())).containsExactly("QEAA Provider");
    }

    @Test
    void aNationalListSignedByAKeyTheListOfListsDoesNotPublishIsRejected() {
        Map<String, byte[]> served = new HashMap<>();
        served.put(LOTL, signXml(lotlXml(), LOTL_SIGNER));
        served.put(TL_AA, signXml(nationalXml(3), OTHER_SIGNER));
        TrustedLists lists = registry(served, Clock.fixed(NOW, ZoneOffset.UTC));

        assertThat(lists.refresh())
                .filteredOn(r -> r.location().equals(TL_AA))
                .singleElement()
                .satisfies(r -> assertThat(r.code()).isEqualTo("trusted_list_signer_untrusted"));
        assertThat(lists.issuance().isEmpty()).isTrue();
    }

    @Test
    void anUnreachableListKeepsItsLastVersionOnlyUntilItsNextUpdate() {
        Map<String, byte[]> served = new HashMap<>();
        served.put(LOTL, signXml(lotlXml(), LOTL_SIGNER));
        served.put(TL_AA, signXml(nationalXml(3), TL_SIGNER));
        AtomicReference<Instant> now = new AtomicReference<>(NOW);
        TrustedLists lists = registry(served, movingClock(now));
        lists.refresh();

        served.clear();
        assertThat(lists.refresh()).noneMatch(TrustedLists.LoadResult::ok);
        assertThat(lists.issuance().certificates()).containsExactly(EAA_CA.certificate());

        now.set(NEXT);
        assertThat(lists.issuance().isEmpty()).isTrue();
    }

    @Test
    void anOlderListCannotReplaceANewerOne() {
        Map<String, byte[]> served = new HashMap<>();
        served.put(LOTL, signXml(lotlXml(), LOTL_SIGNER));
        served.put(TL_AA, signXml(nationalXml(5), TL_SIGNER));
        TrustedLists lists = registry(served, Clock.fixed(NOW, ZoneOffset.UTC));
        lists.refresh();

        served.put(TL_AA, signXml(nationalXml(4), TL_SIGNER));
        assertThat(lists.refresh())
                .filteredOn(r -> r.location().equals(TL_AA))
                .singleElement()
                .satisfies(r -> assertThat(r.code()).isEqualTo("trusted_list_rollback"));
    }

    @Test
    void anExpiredListIsNeverLoaded() {
        Map<String, byte[]> served = new HashMap<>();
        served.put(LOTL, signXml(lotlXml(), LOTL_SIGNER));
        TrustedLists lists = registry(served, Clock.fixed(NEXT.plusSeconds(1), ZoneOffset.UTC));
        assertThat(lists.refresh().get(0).code()).isEqualTo("trusted_list_expired");
    }

    @Test
    void anExpiredListOfListsStopsVouchingForTheListsItPointedTo() {
        Instant lotlNext = NOW.plus(Duration.ofDays(10));
        Map<String, byte[]> served = new HashMap<>();
        served.put(LOTL, signXml(lotl(7, lotlNext, TL_SIGNER, true), LOTL_SIGNER));
        served.put(TL_AA, signXml(nationalXml(3), TL_SIGNER));
        AtomicReference<Instant> now = new AtomicReference<>(NOW);
        TrustedLists lists = registry(served, movingClock(now));
        lists.refresh();
        assertThat(lists.issuance().certificates()).containsExactly(EAA_CA.certificate());

        served.remove(LOTL);
        now.set(lotlNext.plusSeconds(1));
        lists.refresh();
        assertThat(lists.issuance().isEmpty()).isTrue();
    }

    @Test
    void anExpiredListOfListsStopsVouchingBeforeTheNextRefresh() {
        Instant lotlNext = NOW.plus(Duration.ofDays(10));
        Map<String, byte[]> served = new HashMap<>();
        served.put(LOTL, signXml(lotl(7, lotlNext, TL_SIGNER, true), LOTL_SIGNER));
        served.put(TL_AA, signXml(nationalXml(3), TL_SIGNER));
        AtomicReference<Instant> now = new AtomicReference<>(NOW);
        TrustedLists lists = registry(served, movingClock(now));
        lists.refresh();
        assertThat(lists.issuance().certificates()).containsExactly(EAA_CA.certificate());

        // The national list is valid until NEXT, but the LOTL that vouched for it is not.
        now.set(lotlNext.plusSeconds(1));
        assertThat(lists.issuance().isEmpty()).isTrue();
        assertThat(lists.status().isEmpty()).isTrue();
        assertThat(lists.hasCurrentList()).isFalse();
    }

    @Test
    void aPointerThisSourceNoLongerFollowsEvictsThatList() {
        Map<String, byte[]> served = new HashMap<>();
        served.put(LOTL, signXml(lotl(7, NEXT, TL_SIGNER, true), LOTL_SIGNER));
        served.put(TL_AA, signXml(nationalXml(3), TL_SIGNER));
        TrustedLists lists = registry(served, Clock.fixed(NOW, ZoneOffset.UTC));
        lists.refresh();
        assertThat(lists.issuance().certificates()).containsExactly(EAA_CA.certificate());

        // Same location and signer, but no longer a pointer to a trusted list in XML.
        served.put(
                LOTL,
                signXml(
                        xml(
                                TrustedList.TSL_TYPE_EU_LOTL,
                                "EU",
                                8,
                                ISSUED,
                                NEXT,
                                List.of(new XmlPointer(TL_AA, "AA", "application/pdf", TL_SIGNER.certificate())),
                                List.of()),
                        LOTL_SIGNER));
        lists.refresh();
        assertThat(lists.issuance().isEmpty()).isTrue();
    }

    @Test
    void aListOfListsThatDropsAPointerOrRotatesItsSignerEvictsThatList() {
        Map<String, byte[]> served = new HashMap<>();
        served.put(LOTL, signXml(lotl(7, NEXT, TL_SIGNER, true), LOTL_SIGNER));
        served.put(TL_AA, signXml(nationalXml(3), TL_SIGNER));
        TrustedLists lists = registry(served, Clock.fixed(NOW, ZoneOffset.UTC));
        lists.refresh();
        assertThat(lists.issuance().certificates()).containsExactly(EAA_CA.certificate());

        served.put(LOTL, signXml(lotl(8, NEXT, OTHER_SIGNER, true), LOTL_SIGNER));
        lists.refresh();
        assertThat(lists.issuance().isEmpty()).isTrue();

        served.put(LOTL, signXml(lotl(9, NEXT, TL_SIGNER, true), LOTL_SIGNER));
        lists.refresh();
        assertThat(lists.issuance().certificates()).containsExactly(EAA_CA.certificate());

        served.put(LOTL, signXml(lotl(10, NEXT, TL_SIGNER, false), LOTL_SIGNER));
        lists.refresh();
        assertThat(lists.issuance().isEmpty()).isTrue();
    }

    @Test
    void anUnexpectedErrorInOneListDoesNotStopTheOthers() {
        Map<String, byte[]> served = new HashMap<>();
        served.put(LOTL, signXml(lotlXml(), LOTL_SIGNER));
        HttpFetcher failing = (uri, accept, max) -> {
            if (uri.toString().equals(TL_AA)) {
                throw new IllegalStateException("boom");
            }
            return fetcher(served).get(uri, accept, max);
        };
        TestPki.Issued pidSigner = signer("CN=PID List Signer");
        String pidLocation = "https://pid.example/list.jwt";
        served.put(
                pidLocation,
                signLote(
                        lote("t", 1, ISSUED, NEXT, List.of(entity("P", PID_ISSUANCE, QC_CA.certificate()))),
                        pidSigner,
                        Map.of()));
        TrustedLists lists = new TrustedLists(
                List.of(
                        lotlSource(),
                        new TrustedListSource(
                                pidLocation,
                                URI.create(pidLocation),
                                TrustedList.Format.LOTE_JSON,
                                List.of(pidSigner.certificate()),
                                false,
                                Set.of(),
                                Set.of(PID_ISSUANCE),
                                Set.of(),
                                TrustedListSource.DEFAULT_ACCEPTED_STATUSES)),
                failing,
                Clock.fixed(NOW, ZoneOffset.UTC));

        assertThat(lists.refresh())
                .extracting(TrustedLists.LoadResult::location, TrustedLists.LoadResult::code)
                .containsExactly(
                        org.assertj.core.groups.Tuple.tuple(LOTL, "ok"),
                        org.assertj.core.groups.Tuple.tuple(TL_AA, "trusted_list_invalid"),
                        org.assertj.core.groups.Tuple.tuple(pidLocation, "ok"));
        assertThat(lists.issuance().certificates()).containsExactly(QC_CA.certificate());
    }

    @Test
    void aPersistedSequenceNumberRefusesRollbackAfterARestart() {
        TrustedLists.SequenceStore store = TrustedLists.SequenceStore.inMemory();
        Map<String, byte[]> served = new HashMap<>();
        served.put(LOTL, signXml(lotlXml(), LOTL_SIGNER));
        served.put(TL_AA, signXml(nationalXml(5), TL_SIGNER));
        new TrustedLists(
                        List.of(lotlSource()),
                        fetcher(served),
                        Clock.fixed(NOW, ZoneOffset.UTC),
                        io.github.suengineering.eudiw.core.x509.TrustStore.empty(),
                        store)
                .refresh();

        served.put(TL_AA, signXml(nationalXml(4), TL_SIGNER));
        TrustedLists restarted = new TrustedLists(
                List.of(lotlSource()),
                fetcher(served),
                Clock.fixed(NOW, ZoneOffset.UTC),
                io.github.suengineering.eudiw.core.x509.TrustStore.empty(),
                store);
        assertThat(restarted.refresh())
                .filteredOn(r -> r.location().equals(TL_AA))
                .singleElement()
                .satisfies(r -> assertThat(r.code()).isEqualTo("trusted_list_rollback"));
        assertThat(restarted.issuance().isEmpty()).isTrue();
    }

    @Test
    void pointersBeyondTheLimitAreSkippedAndKeepTheirLastVersion() {
        Map<String, byte[]> served = new HashMap<>();
        served.put(LOTL, signXml(lotlXml(), LOTL_SIGNER));
        served.put(TL_AA, signXml(nationalXml(5), TL_SIGNER));
        TrustedLists none = new TrustedLists(
                List.of(lotlSource()),
                fetcher(served),
                Clock.fixed(NOW, ZoneOffset.UTC),
                io.github.suengineering.eudiw.core.x509.TrustStore.empty(),
                TrustedLists.SequenceStore.inMemory(),
                new TrustedLists.Limits(0, Duration.ofMinutes(1)));
        assertThat(none.refresh())
                .extracting(TrustedLists.LoadResult::location, TrustedLists.LoadResult::code)
                .containsExactly(
                        org.assertj.core.groups.Tuple.tuple(LOTL, "ok"),
                        org.assertj.core.groups.Tuple.tuple(TL_AA, TrustedLists.SKIPPED));
        assertThat(none.issuance().isEmpty()).isTrue();
    }

    @Test
    void aSlowRefreshStopsAtItsBudgetAndKeepsTheListsItHad() {
        Map<String, byte[]> served = new HashMap<>();
        served.put(LOTL, signXml(lotlXml(), LOTL_SIGNER));
        served.put(TL_AA, signXml(nationalXml(5), TL_SIGNER));
        java.util.concurrent.atomic.AtomicBoolean slow = new java.util.concurrent.atomic.AtomicBoolean();
        java.util.concurrent.atomic.AtomicInteger fetches = new java.util.concurrent.atomic.AtomicInteger();
        HttpFetcher fetcher = (uri, accept, maxBytes) -> {
            fetches.incrementAndGet();
            if (slow.get()) {
                try {
                    Thread.sleep(300);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            return fetcher(served).get(uri, accept, maxBytes);
        };
        TrustedLists lists = new TrustedLists(
                List.of(lotlSource()),
                fetcher,
                Clock.fixed(NOW, ZoneOffset.UTC),
                io.github.suengineering.eudiw.core.x509.TrustStore.empty(),
                TrustedLists.SequenceStore.inMemory(),
                new TrustedLists.Limits(64, Duration.ofMillis(100)));
        assertThat(lists.refresh()).allSatisfy(r -> assertThat(r.ok()).isTrue());
        var trusted = lists.issuance().certificates();
        assertThat(trusted).isNotEmpty();

        slow.set(true);
        fetches.set(0);
        assertThat(lists.refresh())
                .extracting(TrustedLists.LoadResult::location, TrustedLists.LoadResult::code)
                .containsExactly(
                        org.assertj.core.groups.Tuple.tuple(LOTL, "ok"),
                        org.assertj.core.groups.Tuple.tuple(TL_AA, TrustedLists.SKIPPED));
        assertThat(fetches.get()).isEqualTo(1);
        assertThat(lists.issuance().certificates()).isEqualTo(trusted);
    }

    @Test
    void anEqualSequenceNumberIsAcceptedOnlyWithTheSameContent() {
        TrustedLists.SequenceStore store = TrustedLists.SequenceStore.inMemory();
        Map<String, byte[]> served = new HashMap<>();
        served.put(LOTL, signXml(lotlXml(), LOTL_SIGNER));
        served.put(TL_AA, signXml(nationalXml(5), TL_SIGNER));
        TrustedLists lists = new TrustedLists(
                List.of(lotlSource()),
                fetcher(served),
                Clock.fixed(NOW, ZoneOffset.UTC),
                io.github.suengineering.eudiw.core.x509.TrustStore.empty(),
                store);
        lists.refresh();

        // Re-signed with the same content and number: new signature bytes, same digest, still accepted.
        served.put(TL_AA, signXml(nationalXml(5), TL_SIGNER));
        assertThat(lists.refresh())
                .filteredOn(r -> r.location().equals(TL_AA))
                .singleElement()
                .satisfies(r -> assertThat(r.ok()).isTrue());

        // Same number, different services: refused by this node and, after a restart, by the stored digest.
        String changed = xml(
                "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric",
                "AA",
                5,
                ISSUED,
                NEXT,
                List.of(),
                List.of(new XmlService("Rogue Provider", EAA_Q, GRANTED, WITHDRAWN_CA.certificate())));
        served.put(TL_AA, signXml(changed, TL_SIGNER));
        assertThat(lists.refresh())
                .filteredOn(r -> r.location().equals(TL_AA))
                .singleElement()
                .satisfies(r -> assertThat(r.code()).isEqualTo("trusted_list_rollback"));
        TrustedLists restarted = new TrustedLists(
                List.of(lotlSource()),
                fetcher(served),
                Clock.fixed(NOW, ZoneOffset.UTC),
                io.github.suengineering.eudiw.core.x509.TrustStore.empty(),
                store);
        assertThat(restarted.refresh())
                .filteredOn(r -> r.location().equals(TL_AA))
                .singleElement()
                .satisfies(r -> assertThat(r.code()).isEqualTo("trusted_list_rollback"));
        assertThat(restarted.issuance().certificates()).doesNotContain(WITHDRAWN_CA.certificate());
    }

    @Test
    void aListIsRefusedWhenAnotherNodeRecordedAHigherNumberFirst() {
        // highest() read before another node's write; only the atomic advance() sees the newer number.
        TrustedLists.SequenceStore racing = new TrustedLists.SequenceStore() {
            @Override
            public long highest(String identifier) {
                return -1;
            }

            @Override
            public void record(String identifier, long sequenceNumber) {
                throw new AssertionError("record() must not be used on its own");
            }

            @Override
            public boolean advance(String identifier, long sequenceNumber, String digest) {
                return !identifier.equals(TL_AA);
            }
        };
        Map<String, byte[]> served = new HashMap<>();
        served.put(LOTL, signXml(lotlXml(), LOTL_SIGNER));
        served.put(TL_AA, signXml(nationalXml(5), TL_SIGNER));
        TrustedLists lists = new TrustedLists(
                List.of(lotlSource()),
                fetcher(served),
                Clock.fixed(NOW, ZoneOffset.UTC),
                io.github.suengineering.eudiw.core.x509.TrustStore.empty(),
                racing);
        assertThat(lists.refresh())
                .filteredOn(r -> r.location().equals(TL_AA))
                .singleElement()
                .satisfies(r -> assertThat(r.code()).isEqualTo("trusted_list_rollback"));
        assertThat(lists.issuance().isEmpty()).isTrue();
    }

    @Test
    void statusAnchorsAddStatusServicesButIssuanceAnchorsDoNot() {
        TestPki.Issued revocationCa =
                TestPki.rootCa("CN=PID Status CA", NOW.minus(Duration.ofDays(1)), NOW.plus(Duration.ofDays(900)));
        byte[] signed = signLote(
                lote(
                        "http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList",
                        1,
                        ISSUED,
                        NEXT,
                        List.of(
                                entity("PID Provider", PID_ISSUANCE, EAA_CA.certificate()),
                                entity("PID Provider", PID_REVOCATION, revocationCa.certificate()))),
                LOTL_SIGNER,
                Map.of());
        String location = "https://pid.example/list.jwt";
        TrustedListSource source = new TrustedListSource(
                location,
                URI.create(location),
                TrustedList.Format.LOTE_JSON,
                List.of(LOTL_SIGNER.certificate()),
                false,
                Set.of(),
                Set.of(PID_ISSUANCE),
                Set.of(PID_REVOCATION),
                TrustedListSource.DEFAULT_ACCEPTED_STATUSES);
        TrustedLists lists =
                new TrustedLists(List.of(source), fetcher(Map.of(location, signed)), Clock.fixed(NOW, ZoneOffset.UTC));
        lists.refresh();

        assertThat(lists.issuance().certificates()).containsExactly(EAA_CA.certificate());
        assertThat(lists.status().certificates())
                .containsExactlyInAnyOrder(EAA_CA.certificate(), revocationCa.certificate());
    }

    @Test
    void aListedIssuerCertificateIsTrustedDirectlyAndReportsItsList() throws Exception {
        TestPki.Issued issuer = TestPki.endEntity(
                "CN=PID Issuer",
                EAA_CA,
                NOW.minus(Duration.ofDays(1)),
                NOW.plus(Duration.ofDays(300)),
                KeyUsage.digitalSignature,
                List.of(TestPki.uri("https://pid.example")));
        io.github.suengineering.eudiw.core.x509.TrustStore store =
                io.github.suengineering.eudiw.core.x509.TrustStore.of(
                        List.of(issuer.certificate()), "https://pid.example/list.jwt");
        var resolver = io.github.suengineering.eudiw.core.sdjwt.X5cIssuerKeyResolver.withTrustStore(
                () -> store, Clock.fixed(NOW, ZoneOffset.UTC));
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .x509CertChain(List.of(Base64.encode(issuer.certificate().getEncoded())))
                .build();

        var resolved = resolver.resolve(header, Map.of("iss", "https://pid.example"));
        assertThat(resolved.trustSources()).containsExactly("https://pid.example/list.jwt");

        // A longer chain that contains the listed certificate is still refused (HAIP: no anchor in x5c).
        JWSHeader withParent = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .x509CertChain(List.of(
                        Base64.encode(issuer.certificate().getEncoded()),
                        Base64.encode(EAA_CA.certificate().getEncoded())))
                .build();
        assertFailure(
                () -> resolver.resolve(withParent, Map.of("iss", "https://pid.example")), "certificate_chain_invalid");
    }

    // ---- helpers ----

    private static String lotl(long sequence, Instant next, TestPki.Issued aaSigner, boolean pointToAa) {
        List<XmlPointer> pointers = new java.util.ArrayList<>();
        pointers.add(new XmlPointer(LOTL, "EU", TrustedList.MIME_TSL_XML, LOTL_SIGNER.certificate()));
        if (pointToAa) {
            pointers.add(new XmlPointer(TL_AA, "AA", TrustedList.MIME_TSL_XML, aaSigner.certificate()));
        }
        return xml(TrustedList.TSL_TYPE_EU_LOTL, "EU", sequence, ISSUED, next, pointers, List.of());
    }

    private static TrustedListSource lotlSource() {
        return new TrustedListSource(
                LOTL,
                URI.create(LOTL),
                TrustedList.Format.TSL_XML,
                List.of(LOTL_SIGNER.certificate()),
                true,
                Set.of(),
                Set.of(EAA_Q),
                Set.of(),
                TrustedListSource.DEFAULT_ACCEPTED_STATUSES);
    }

    private static TrustedLists registry(Map<String, byte[]> served, Clock clock) {
        TrustedListSource source = new TrustedListSource(
                LOTL,
                URI.create(LOTL),
                TrustedList.Format.TSL_XML,
                List.of(LOTL_SIGNER.certificate()),
                true,
                Set.of(),
                Set.of(EAA_Q),
                Set.of(),
                TrustedListSource.DEFAULT_ACCEPTED_STATUSES);
        return new TrustedLists(List.of(source), fetcher(served), clock);
    }

    private static HttpFetcher fetcher(Map<String, byte[]> served) {
        return (uri, accept, maxBytes) -> {
            byte[] body = served.get(uri.toString());
            if (body == null) {
                throw new HttpFetcher.FetchException("not found");
            }
            return body;
        };
    }

    private static Clock movingClock(AtomicReference<Instant> now) {
        return new Clock() {
            @Override
            public java.time.ZoneId getZone() {
                return ZoneOffset.UTC;
            }

            @Override
            public Clock withZone(java.time.ZoneId zone) {
                return this;
            }

            @Override
            public Instant instant() {
                return now.get();
            }
        };
    }

    private static byte[] sign(JWSHeader header, Map<String, Object> lote, TestPki.Issued signer) throws Exception {
        JWSObject jws = new JWSObject(header, new Payload(Json.toJson(lote)));
        jws.sign(new ECDSASigner((ECPrivateKey) signer.keyPair().getPrivate()));
        return jws.serialize().getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] signXmlWithIdOn(String xml, String localName, String referenceUri) {
        try {
            var dbf = javax.xml.parsers.DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            var document = dbf.newDocumentBuilder()
                    .parse(new java.io.ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
            var element =
                    (org.w3c.dom.Element) document.getElementsByTagNameNS("http://uri.etsi.org/02231/v2#", localName)
                            .item(0);
            element.setIdAttribute("Id", true);
            var factory = javax.xml.crypto.dsig.XMLSignatureFactory.getInstance("DOM");
            var reference = factory.newReference(
                    referenceUri,
                    factory.newDigestMethod(javax.xml.crypto.dsig.DigestMethod.SHA256, null),
                    List.of(factory.newTransform(
                            javax.xml.crypto.dsig.CanonicalizationMethod.EXCLUSIVE,
                            (javax.xml.crypto.dsig.spec.TransformParameterSpec) null)),
                    null,
                    null);
            var signedInfo = factory.newSignedInfo(
                    factory.newCanonicalizationMethod(
                            javax.xml.crypto.dsig.CanonicalizationMethod.EXCLUSIVE,
                            (javax.xml.crypto.dsig.spec.C14NMethodParameterSpec) null),
                    factory.newSignatureMethod(javax.xml.crypto.dsig.SignatureMethod.ECDSA_SHA256, null),
                    List.of(reference));
            var kif = factory.getKeyInfoFactory();
            factory.newXMLSignature(
                            signedInfo, kif.newKeyInfo(List.of(kif.newX509Data(List.of(TL_SIGNER.certificate())))))
                    .sign(new javax.xml.crypto.dsig.dom.DOMSignContext(
                            TL_SIGNER.keyPair().getPrivate(), document.getDocumentElement()));
            var out = new java.io.ByteArrayOutputStream();
            javax.xml.transform.TransformerFactory.newInstance()
                    .newTransformer()
                    .transform(
                            new javax.xml.transform.dom.DOMSource(document),
                            new javax.xml.transform.stream.StreamResult(out));
            return out.toByteArray();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static void assertFailure(org.assertj.core.api.ThrowableAssert.ThrowingCallable call, String code) {
        assertThatThrownBy(call).isInstanceOfSatisfying(VerificationFailure.class, f -> assertThat(f.code())
                .isEqualTo(code));
    }
}
