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
package io.github.suengineering.eudiw.core.oid4vp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.util.Base64;
import io.github.suengineering.eudiw.core.dcql.DcqlQuery;
import io.github.suengineering.eudiw.core.json.Json;
import io.github.suengineering.eudiw.core.oid4vp.RelyingPartyRegistration.RegistrationCertificate;
import io.github.suengineering.eudiw.core.x509.TestPki;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.jupiter.api.Test;

/**
 * Registration data in {@code verifier_info} (ETSI TS 119 472-2 V1.3.1 clause 6.3.2.2) and the registration
 * certificate (ETSI TS 119 475 V1.2.1 clause 5.2). Every certificate here is synthetic.
 */
class RelyingPartyRegistrationTest {

    private static final Instant NOW = Instant.parse("2026-11-17T10:00:00Z");
    private static final String RP_ID = "VATBE-0999999999";
    private static final String VCT = "https://pid.example/vct/v1";

    private final TestPki.Issued registrarRoot = TestPki.rootCa(
            "CN=Registration Certificate Provider", NOW.minus(Duration.ofDays(30)), NOW.plus(Duration.ofDays(900)));
    private final TestPki.Issued rpRoot =
            TestPki.rootCa("CN=Access CA", NOW.minus(Duration.ofDays(30)), NOW.plus(Duration.ofDays(900)));
    private final TestPki.Issued access = TestPki.endEntity(
            "CN=Example Shop,O=Example Shop SA,2.5.4.97=" + RP_ID + ",C=BE",
            rpRoot,
            NOW.minus(Duration.ofDays(1)),
            NOW.plus(Duration.ofDays(300)),
            KeyUsage.digitalSignature,
            List.of(TestPki.dns("shop.example")));

    private final DcqlQuery query = DcqlQuery.parse(Map.of(
            "credentials",
            List.of(Map.of(
                    "id",
                    "pid",
                    "format",
                    "dc+sd-jwt",
                    "meta",
                    Map.of("vct_values", List.of(VCT)),
                    "claims",
                    List.of(Map.of("path", List.of("age_equal_or_over", "18")))))));

    private static Map<String, Object> declaredPid(List<List<Object>> paths) {
        Map<String, Object> credential = new LinkedHashMap<>();
        credential.put("format", "dc+sd-jwt");
        credential.put("meta", Map.of("vct_values", List.of(VCT, "https://other.example/vct")));
        if (paths != null) {
            credential.put("claim", paths.stream().map(p -> Map.of("path", p)).toList());
        }
        return credential;
    }

    private static Map<String, Object> dataset() {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("identifier", RP_ID);
        data.put("srvDescription", List.of(Map.of("lang", "en", "content", "Online shop")));
        data.put("registryURI", "https://registrar.example/api");
        data.put("intendedUseIdentifier", "iu-42");
        data.put("purpose", List.of(Map.of("lang", "en", "content", "Age check before alcohol sales")));
        data.put("policyURI", "https://shop.example/privacy");
        data.put("credential", List.of(declaredPid(List.of(List.of("age_equal_or_over", "18")))));
        return data;
    }

    private String certificate(String typ, Map<String, Object> overrides) throws Exception {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("name", "Example Shop");
        claims.put("sub", RP_ID);
        claims.put("country", "BE");
        claims.put("iat", NOW.minus(Duration.ofDays(2)).getEpochSecond());
        claims.put("exp", NOW.plus(Duration.ofDays(200)).getEpochSecond());
        claims.put("credentials", List.of(declaredPid(List.of(List.of("age_equal_or_over", "18")))));
        claims.putAll(overrides);
        claims.values().removeIf(v -> v == null);
        JWSHeader.Builder header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .x509CertChain(List.of(Base64.encode(registrarRoot.certificate().getEncoded())));
        if (typ != null) {
            header.type(new JOSEObjectType(typ));
        }
        JWSObject jws = new JWSObject(header.build(), new Payload(Json.toJson(claims)));
        jws.sign(new ECDSASigner(registrarRoot.keyPair().getPrivate(), Curve.P_256));
        return jws.serialize();
    }

    private String certificate(Map<String, Object> overrides) throws Exception {
        return certificate(RelyingPartyRegistration.REGISTRATION_CERT_TYPE, overrides);
    }

    @Test
    void parsesARegistrationCertificate() throws Exception {
        RegistrationCertificate rc = RegistrationCertificate.parse(certificate(Map.of()) + "\n");
        assertThat(rc.subject()).isEqualTo(RP_ID);
        assertThat(rc.intermediary()).isEmpty();
        assertThat(rc.expiresAt())
                .contains(Instant.ofEpochSecond(NOW.plus(Duration.ofDays(200)).getEpochSecond()));
        assertThat(rc.credentials()).hasSize(1);
        assertThat(rc.missingMembers())
                .containsExactly(
                        "registry_uri",
                        "srv_description",
                        "entitlements",
                        "privacy_policy",
                        "info_uri",
                        "support_uri",
                        "supervisory_authority",
                        "policy_id",
                        "certificate_policy",
                        "status");
        assertThat(rc.isCurrentAt(NOW)).isTrue();
        assertThat(rc.isCurrentAt(NOW.plus(Duration.ofDays(201)))).isFalse();
        assertThat(rc.isCurrentAt(NOW.minus(Duration.ofDays(3)))).isFalse();
    }

    @Test
    void refusesWhatIsNotARegistrationCertificate() throws Exception {
        assertThatThrownBy(() -> RegistrationCertificate.parse("not a jwt")).hasMessageContaining("compact JWS");
        assertThatThrownBy(() -> RegistrationCertificate.parse(certificate("JWT", Map.of())))
                .hasMessageContaining("typ");
        assertThatThrownBy(() -> RegistrationCertificate.parse(certificate(null, Map.of())))
                .hasMessageContaining("typ");
        Map<String, Object> noSub = new HashMap<>();
        noSub.put("sub", null);
        assertThatThrownBy(() -> RegistrationCertificate.parse(certificate(noSub)))
                .hasMessageContaining("sub");
        Map<String, Object> noIat = new HashMap<>();
        noIat.put("iat", null);
        assertThatThrownBy(() -> RegistrationCertificate.parse(certificate(noIat)))
                .hasMessageContaining("iat");
        assertThatThrownBy(() -> RegistrationCertificate.parse(
                        certificate(Map.of("exp", NOW.minus(Duration.ofDays(5)).getEpochSecond()))))
                .hasMessageContaining("expires before");
        JWSObject noChain = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .type(new JOSEObjectType(RelyingPartyRegistration.REGISTRATION_CERT_TYPE))
                        .build(),
                new Payload(Map.of("sub", RP_ID, "iat", NOW.getEpochSecond())));
        noChain.sign(new ECDSASigner(registrarRoot.keyPair().getPrivate(), Curve.P_256));
        assertThatThrownBy(() -> RegistrationCertificate.parse(noChain.serialize()))
                .hasMessageContaining("x5c");
    }

    @Test
    void linksTheCertificateToTheAccessCertificate() throws Exception {
        assertThat(RelyingPartyRegistration.subjectIdentifiers(access.certificate()))
                .containsExactly(RP_ID);
        assertThat(RegistrationCertificate.parse(certificate(Map.of())).names(access.certificate()))
                .isTrue();

        RegistrationCertificate other = RegistrationCertificate.parse(certificate(Map.of("sub", "VATFR-123")));
        assertThat(other.names(access.certificate())).isFalse();

        // An intermediary presents the final relying party's certificate with its own access certificate.
        RegistrationCertificate viaIntermediary = RegistrationCertificate.parse(
                certificate(Map.of("sub", "VATFR-123", "intermediary", Map.of("sub", RP_ID, "sname", "Hosting"))));
        assertThat(viaIntermediary.intermediary()).contains(RP_ID);
        assertThat(viaIntermediary.names(access.certificate())).isTrue();
        RegistrationCertificate viaAct =
                RegistrationCertificate.parse(certificate(Map.of("sub", "VATFR-123", "act", Map.of("sub", RP_ID))));
        assertThat(viaAct.names(access.certificate())).isTrue();
    }

    @Test
    void buildsVerifierInfoAsTs119472Profiles() throws Exception {
        String serialized = certificate(Map.of());
        RelyingPartyRegistration registration =
                RelyingPartyRegistration.of(dataset(), Optional.of(RegistrationCertificate.parse(serialized)));
        List<Map<String, Object>> info = registration.verifierInfo(NOW);
        assertThat(info).hasSize(2);
        assertThat(info.get(0)).containsOnlyKeys("format", "data").containsEntry("format", "registrar_dataset");
        assertThat(info.get(0).get("data")).isEqualTo(dataset());
        assertThat(info.get(1)).containsOnlyKeys("format", "data").containsEntry("format", "registration_cert");
        String data = (String) info.get(1).get("data");
        assertThat(data).doesNotContain("=", "+", "/");
        assertThat(new String(java.util.Base64.getUrlDecoder().decode(data), StandardCharsets.US_ASCII))
                .isEqualTo(serialized);

        // After expiry only the dataset is sent.
        assertThat(registration.verifierInfo(NOW.plus(Duration.ofDays(400))))
                .singleElement()
                .satisfies(e -> assertThat(e).containsEntry("format", "registrar_dataset"));
        // Without a certificate, likewise.
        assertThat(RelyingPartyRegistration.of(dataset(), Optional.empty()).verifierInfo(NOW))
                .hasSize(1);
    }

    @Test
    void theDatasetNeedsTheMembersTs119472Requires() {
        for (String key : List.of(
                "identifier", "srvDescription", "registryURI", "intendedUseIdentifier", "purpose", "policyURI")) {
            Map<String, Object> data = dataset();
            data.remove(key);
            assertThatThrownBy(() -> RelyingPartyRegistration.of(data, Optional.empty()))
                    .as(key)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining(key);
        }
        Map<String, Object> badText = dataset();
        badText.put("purpose", List.of(Map.of("lang", "en", "value", "uses the certificate's member name")));
        assertThatThrownBy(() -> RelyingPartyRegistration.of(badText, Optional.empty()))
                .hasMessageContaining("content");
        assertThatThrownBy(() -> RelyingPartyRegistration.of(Map.of(), Optional.empty()))
                .hasMessageContaining("empty");
        Map<String, Object> noCredential = dataset();
        noCredential.remove("credential");
        assertThat(RelyingPartyRegistration.of(noCredential, Optional.empty()).undeclaredByDataset(query))
                .isEmpty();
    }

    @Test
    void reportsOverAsking() {
        assertThat(RelyingPartyRegistration.undeclared(
                        query, List.of(declaredPid(List.of(List.of("age_equal_or_over", "18"))))))
                .isEmpty();

        DcqlQuery asksMore = DcqlQuery.parse(Map.of(
                "credentials",
                List.of(Map.of(
                        "id",
                        "pid",
                        "format",
                        "dc+sd-jwt",
                        "meta",
                        Map.of("vct_values", List.of(VCT)),
                        "claims",
                        List.of(
                                Map.of("path", List.of("age_equal_or_over", "18")),
                                Map.of("path", List.of("birthdate")))))));
        assertThat(RelyingPartyRegistration.undeclared(
                        asksMore, List.of(declaredPid(List.of(List.of("age_equal_or_over", "18"))))))
                .singleElement()
                .asString()
                .contains("birthdate");

        // A declared credential without claims declares none.
        assertThat(RelyingPartyRegistration.undeclared(query, List.of(declaredPid(null))))
                .singleElement()
                .asString()
                .contains("age_equal_or_over");

        // Another type or format is not declared at all.
        Map<String, Object> otherType = new LinkedHashMap<>(declaredPid(List.of(List.of("age_equal_or_over", "18"))));
        otherType.put("meta", Map.of("vct_values", List.of("https://other.example/vct")));
        assertThat(RelyingPartyRegistration.undeclared(query, List.of(otherType)))
                .singleElement()
                .asString()
                .contains("credential pid");
        Map<String, Object> mdoc = new LinkedHashMap<>(declaredPid(List.of(List.of("age_equal_or_over", "18"))));
        mdoc.put("format", "mso_mdoc");
        assertThat(RelyingPartyRegistration.undeclared(query, List.of(mdoc))).hasSize(1);
        assertThat(RelyingPartyRegistration.undeclared(query, List.of())).hasSize(1);
    }

    @Test
    void theRequestObjectCarriesVerifierInfo() throws Exception {
        VerifierIdentity identity = new VerifierIdentity(
                access.keyPair().getPrivate(), List.of(access.certificate(), rpRoot.certificate()));
        RelyingPartyRegistration registration = RelyingPartyRegistration.of(
                dataset(), Optional.of(RegistrationCertificate.parse(certificate(Map.of()))));
        String request = AuthorizationRequests.signRequestObject(
                identity,
                new AuthorizationRequests.Parameters(
                        URI.create("https://adapter.example/oid4vp/responses"),
                        "n",
                        "s",
                        query,
                        AuthorizationRequests.newResponseEncryptionKey(),
                        null,
                        Duration.ofMinutes(5),
                        registration.verifierInfo(NOW)),
                NOW);
        Map<String, Object> claims = JWSObject.parse(request).getPayload().toJSONObject();
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> info = (List<Map<String, Object>>) claims.get("verifier_info");
        assertThat(info).hasSize(2).allSatisfy(e -> assertThat(e).doesNotContainKey("credential_ids"));

        String without = AuthorizationRequests.signRequestObject(
                identity,
                new AuthorizationRequests.Parameters(
                        URI.create("https://adapter.example/oid4vp/responses"),
                        "n",
                        "s",
                        query,
                        AuthorizationRequests.newResponseEncryptionKey(),
                        null,
                        Duration.ofMinutes(5)),
                NOW);
        assertThat(JWSObject.parse(without).getPayload().toJSONObject()).doesNotContainKey("verifier_info");
    }
}
