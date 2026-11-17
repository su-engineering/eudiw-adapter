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

import io.github.suengineering.eudiw.core.VerificationFailure;
import io.github.suengineering.eudiw.core.cbor.CborDecoder;
import io.github.suengineering.eudiw.core.cbor.CborEncoder;
import io.github.suengineering.eudiw.core.cbor.CborItem;
import io.github.suengineering.eudiw.core.cose.CoseSign1;
import io.github.suengineering.eudiw.core.dcql.DcqlEvaluator.SelectedCredential;
import io.github.suengineering.eudiw.core.dcql.DcqlQuery;
import io.github.suengineering.eudiw.core.jose.AlgorithmPolicy;
import io.github.suengineering.eudiw.core.json.Json;
import io.github.suengineering.eudiw.core.oid4vp.VpTokenVerifier;
import io.github.suengineering.eudiw.core.oid4vp.VpTokenVerifier.StatusPolicy;
import io.github.suengineering.eudiw.core.sdjwt.SdJwtVcVerifier;
import io.github.suengineering.eudiw.core.sdjwt.X5cIssuerKeyResolver;
import io.github.suengineering.eudiw.core.status.StatusListChecker;
import io.github.suengineering.eudiw.core.x509.TrustStore;
import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

/** An {@code mso_mdoc} presentation through the VP Token verifier, from DeviceResponse to DCQL selection. */
class MdocVpTokenTest {

    private static final String DOCTYPE = "eu.europa.ec.eudi.pid.1";
    private static final String CLIENT_ID = "x509_hash:test-verifier";
    private static final String NONCE = "request-nonce-1";
    private static final String RESPONSE_URI = "https://verifier.example/response";
    private static final byte[] THUMBPRINT = new byte[32];

    private final DcqlQuery query = DcqlQuery.parse(Json.parseObject("""
            {"credentials":[{"id":"pid","format":"mso_mdoc","meta":{"doctype_value":"%s"},
              "claims":[{"path":["%s","age_over_18"],"intent_to_retain":false}]}]}""".formatted(DOCTYPE, DOCTYPE), "test"));

    private final VpTokenVerifier.Context context =
            new VpTokenVerifier.Context(CLIENT_ID, NONCE, "tenant-1", RESPONSE_URI, Optional.of(THUMBPRINT));

    @Test
    void anMdocWithoutDeviceAuthenticationIsRejected() {
        assertThatThrownBy(() -> verifier(MdocDeviceAuthentication.SIGNATURE, StatusPolicy.IGNORE)
                        .verify(vpToken(deviceResponse(document())), query, context))
                .isInstanceOfSatisfying(
                        VerificationFailure.class, f -> assertThat(f.code()).isEqualTo("malformed_credential"));
    }

    @Test
    void anAuthenticatedMdocSatisfiesTheQuery() {
        AtomicReference<CborItem> transcript = new AtomicReference<>();
        VpTokenVerifier.Result result = verifier(
                        (doc, issuer, t) -> transcript.set(t), StatusPolicy.REJECT_KNOWN_INVALID)
                .verify(vpToken(deviceResponse(document())), query, context);
        SelectedCredential pid = result.credentials().get("pid").get(0);
        assertThat(pid.format()).isEqualTo("mso_mdoc");
        assertThat(pid.type()).isEqualTo(DOCTYPE);
        assertThat(pid.claims()).hasSize(1);
        assertThat(pid.claims().get(0).values()).containsExactly(true);
        // Device authentication receives this request's transcript.
        assertThat(transcript.get().encoded())
                .isEqualTo(SessionTranscripts.openId4VpRedirect(CLIENT_ID, NONCE, Optional.of(THUMBPRINT), RESPONSE_URI)
                        .encoded());
    }

    @Test
    void anMdocStatusReferenceCannotSatisfyRequireValid() {
        assertThatThrownBy(() -> verifier((d, i, t) -> {}, StatusPolicy.REQUIRE_VALID)
                        .verify(vpToken(deviceResponse(document())), query, context))
                .isInstanceOfSatisfying(
                        VerificationFailure.class, f -> assertThat(f.code()).isEqualTo("credential_status_unknown"));
    }

    @Test
    void theDeviceResponseShapeIsChecked() {
        VpTokenVerifier verifier = verifier((d, i, t) -> {}, StatusPolicy.REJECT_KNOWN_INVALID);
        expect(verifier, "not base64url!", "malformed_credential");
        expect(verifier, encode(deviceResponseWith(List.of())), "malformed_credential");
        expect(verifier, encode(deviceResponseWith(List.of(document(), document()))), "malformed_credential");
        CborItem.MapItem otherType =
                replace((CborItem.MapItem) document(), "docType", CborEncoder.text("org.example.other"));
        expect(verifier, encode(deviceResponseWith(List.of(otherType))), "credential_type_not_allowed");
    }

    @Test
    void elementValuesBecomeJsonTypes() {
        Map<CborItem, CborItem> map = new LinkedHashMap<>();
        map.put(CborEncoder.text("n"), CborEncoder.integer(42));
        CborItem value = CborEncoder.array(
                CborEncoder.tag(1004, CborEncoder.text("1990-01-01")),
                CborEncoder.bytes(new byte[] {1, 2}),
                CborEncoder.bool(false),
                CborEncoder.map(map));
        assertThat(MdocPresentationVerifier.MdocValues.toJson(value))
                .isEqualTo(List.of("1990-01-01", "AQI", false, Map.of("n", 42L)));
    }

    // -- helpers

    private static void expect(VpTokenVerifier verifier, String presentation, String code) {
        assertThatThrownBy(() -> verifier.verify(
                        Map.of("pid", List.of(presentation)),
                        DcqlQuery.parse(Json.parseObject("""
                {"credentials":[{"id":"pid","format":"mso_mdoc","meta":{"doctype_value":"%s"}}]}""".formatted(DOCTYPE), "test")),
                        new VpTokenVerifier.Context(
                                CLIENT_ID, NONCE, "tenant-1", RESPONSE_URI, Optional.of(THUMBPRINT))))
                .isInstanceOfSatisfying(
                        VerificationFailure.class, f -> assertThat(f.code()).isEqualTo(code));
    }

    private VpTokenVerifier verifier(MdocDeviceAuthentication deviceAuthentication, StatusPolicy statusPolicy) {
        X509Certificate iaca = iaca();
        Clock clock = Clock.fixed(signed().plusSeconds(3600), ZoneOffset.UTC);
        MdocIssuerVerifier issuer = new MdocIssuerVerifier(
                () -> TrustStore.of(List.of(iaca), "test"),
                clock,
                Duration.ofMinutes(1),
                null,
                MdocIssuerVerifier.mdlOnly());
        Optional<StatusListChecker> checker = statusPolicy == StatusPolicy.IGNORE
                ? Optional.empty()
                : Optional.of(new StatusListChecker(
                        (uri, accept, max) -> {
                            throw new io.github.suengineering.eudiw.core.net.HttpFetcher.FetchException("unused");
                        },
                        Set::of,
                        AlgorithmPolicy.DEFAULT,
                        clock,
                        Duration.ofSeconds(60),
                        Duration.ofMinutes(10),
                        10));
        return new VpTokenVerifier(
                new SdJwtVcVerifier(new X5cIssuerKeyResolver(Set::of, clock), false),
                Optional.of(new MdocPresentationVerifier(issuer, deviceAuthentication)),
                checker,
                new VpTokenVerifier.Settings(
                        clock,
                        Duration.ofMinutes(5),
                        Duration.ofSeconds(60),
                        AlgorithmPolicy.DEFAULT,
                        true,
                        statusPolicy));
    }

    private static CborItem document() {
        return MdocIssuerVerifierTest.document("pid");
    }

    private static CborItem deviceResponse(CborItem document) {
        return deviceResponseWith(List.of(document));
    }

    private static CborItem deviceResponseWith(List<CborItem> documents) {
        Map<CborItem, CborItem> response = new LinkedHashMap<>();
        response.put(CborEncoder.text("version"), CborEncoder.text("1.0"));
        response.put(CborEncoder.text("documents"), CborEncoder.array(documents));
        response.put(CborEncoder.text("status"), CborEncoder.integer(0));
        return CborEncoder.map(response);
    }

    private static Map<String, Object> vpToken(CborItem deviceResponse) {
        return Map.of("pid", List.of(encode(deviceResponse)));
    }

    private static String encode(CborItem item) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(item.encoded());
    }

    private static CborItem.MapItem replace(CborItem.MapItem map, String key, CborItem value) {
        Map<CborItem, CborItem> out = new LinkedHashMap<>();
        map.entries()
                .forEach((k, v) ->
                        out.put(k, k instanceof CborItem.Text t && t.value().equals(key) ? value : v));
        return CborEncoder.map(out);
    }

    private static java.time.Instant signed() {
        CborItem.MapItem issuerSigned = (CborItem.MapItem) CborDecoder.decode(MdocIssuerVerifierTest.fixture("pid"));
        return MobileSecurityObject.parse(
                        CoseSign1.parse(issuerSigned.get("issuerAuth").orElseThrow())
                                .payload()
                                .orElseThrow())
                .signed();
    }

    private static X509Certificate iaca() {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(
                            new ByteArrayInputStream(Files.readAllBytes(Path.of("src/test/resources/mdoc/iaca.crt"))));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
