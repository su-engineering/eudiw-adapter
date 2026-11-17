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
package io.github.suengineering.eudiw.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.suengineering.eudiw.core.oid4vp.VpTokenVerifier;
import io.github.suengineering.eudiw.core.x509.TestPki;
import io.github.suengineering.eudiw.service.config.AdapterConfig;
import io.github.suengineering.eudiw.service.config.ConfigLoader;
import io.github.suengineering.eudiw.service.config.ConfigLoader.ConfigException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Security settings and identifiers in the configuration file are checked strictly, never coerced. */
class ConfigValidationTest {

    private static final String DCQL = """
            {"credentials":[{"id":"age","format":"dc+sd-jwt","meta":{"vct_values":["https://credentials.test.example/age"]},
              "claims":[{"path":["age_over_18"]}]}]}""";

    @TempDir
    Path dir;

    @BeforeEach
    void keys() throws Exception {
        Instant from = Instant.now().minus(Duration.ofDays(1));
        Instant until = Instant.now().plus(Duration.ofDays(365));
        TestPki.Issued root = TestPki.rootCa("CN=Root", from, until);
        TestPki.Issued rp =
                TestPki.endEntity("CN=RP,2.5.4.97=VATBE-1", root, from, until, KeyUsage.digitalSignature, List.of());
        Files.writeString(dir.resolve("rp.pem"), pem(rp.certificate()));
        Files.writeString(
                dir.resolve("rp-key.pem"),
                "-----BEGIN " + "PRIVATE KEY-----\n"
                        + Base64.getMimeEncoder()
                                .encodeToString(rp.keyPair().getPrivate().getEncoded())
                        + "\n-----END PRIVATE KEY-----\n");
        Files.writeString(dir.resolve("anchors.pem"), pem(root.certificate()));
    }

    private static String pem(X509Certificate c) throws Exception {
        return "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder().encodeToString(c.getEncoded())
                + "\n-----END CERTIFICATE-----\n";
    }

    /** One tenant, one client, one policy; {@code policyExtra} is spliced into the policy object. */
    private AdapterConfig load(String clientId, String policyExtra) throws Exception {
        String tenants = """
                {"tenants":[{"id":"t","verifier":{"private_key_file":"rp-key.pem","certificate_chain_file":"rp.pem"},
                  "clients":[{"client_id":%s,"policies":["p"]}],
                  "policies":[{"id":"p","dcql":%s,
                    "output":{"age_over_18":{"credential":"age","path":["age_over_18"]}},
                    "trust_anchors_file":"anchors.pem"%s}]}]}""".formatted(jsonString(clientId), DCQL, policyExtra);
        Path file = dir.resolve("tenants.json");
        Files.writeString(file, tenants, StandardCharsets.UTF_8);
        return ConfigLoader.load(file, false);
    }

    private static String jsonString(String value) {
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\t", "\\t") + "\"";
    }

    private AdapterConfig.Policy policy(String policyExtra) throws Exception {
        return load("c", policyExtra).tenant("t").orElseThrow().policies().get("p");
    }

    @Test
    void enforceTrustedAuthoritiesDefaultsToTrueAndTakesBooleansOnly() throws Exception {
        assertThat(policy("").enforceTrustedAuthorities()).isTrue();
        assertThat(policy(",\"enforce_trusted_authorities\":true").enforceTrustedAuthorities())
                .isTrue();
        assertThat(policy(",\"enforce_trusted_authorities\":false").enforceTrustedAuthorities())
                .isFalse();
        for (String value : List.of("\"true\"", "\"false\"", "1", "0")) {
            assertThatThrownBy(() -> policy(",\"enforce_trusted_authorities\":" + value))
                    .isInstanceOf(ConfigException.class)
                    .hasMessageContaining("enforce_trusted_authorities must be true or false");
        }
    }

    @Test
    void followPointersTakesBooleansOnly() throws Exception {
        String list = ",\"trusted_lists\":[{\"location\":\"https://lotl.example/lotl.xml\",\"format\":\"tsl_xml\","
                + "\"signer_certificates_file\":\"anchors.pem\","
                + "\"issuance_service_types\":[\"http://uri.etsi.org/TrstSvc/Svctype/EAA/Q\"],"
                + "\"follow_pointers\":%s}]";
        assertThat(policy(list.formatted("true")).trustedLists().get(0).followPointers())
                .isTrue();
        assertThat(policy(list.formatted("false")).trustedLists().get(0).followPointers())
                .isFalse();
        assertThatThrownBy(() -> policy(list.formatted("\"true\"")))
                .isInstanceOf(ConfigException.class)
                .hasMessageContaining("follow_pointers must be true or false");
    }

    @Test
    void statusOptionsDefaultToTheCurrentBehaviour() throws Exception {
        AdapterConfig.Policy policy = policy("");
        assertThat(policy.requireStatus()).isFalse();
        assertThat(policy.statusSigner()).isEqualTo(VpTokenVerifier.StatusSigner.ANY_ANCHOR);
        assertThat(policy.issuerExtendedKeyUsages()).isEmpty();
    }

    @Test
    void requireStatusTakesBooleansOnlyAndNeedsAStatusPolicy() throws Exception {
        assertThat(policy(",\"require_status\":true").requireStatus()).isTrue();
        assertThatThrownBy(() -> policy(",\"require_status\":\"true\""))
                .isInstanceOf(ConfigException.class)
                .hasMessageContaining("require_status must be true or false");
        assertThatThrownBy(() -> policy(",\"require_status\":true,\"status_policy\":\"ignore\""))
                .isInstanceOf(ConfigException.class)
                .hasMessageContaining("require_status");
    }

    @Test
    void statusSignerIsOneOfTwoValues() throws Exception {
        assertThat(policy(",\"status_signer\":\"credential_issuer\"").statusSigner())
                .isEqualTo(VpTokenVerifier.StatusSigner.CREDENTIAL_ISSUER);
        assertThat(policy(",\"status_signer\":\"any_anchor\"").statusSigner())
                .isEqualTo(VpTokenVerifier.StatusSigner.ANY_ANCHOR);
        assertThatThrownBy(() -> policy(",\"status_signer\":\"issuer\""))
                .isInstanceOf(ConfigException.class)
                .hasMessageContaining("status_signer");
    }

    @Test
    void issuerExtendedKeyUsagesMustBeOids() throws Exception {
        assertThat(policy(",\"issuer_extended_key_usages\":[\"1.3.6.1.4.1.55555.1.1\"]")
                        .issuerExtendedKeyUsages())
                .containsExactly("1.3.6.1.4.1.55555.1.1");
        for (String value : List.of("[]", "[\"issuer\"]", "[\"1.02.3\"]", "[1]", "\"1.2.3\"")) {
            assertThatThrownBy(() -> policy(",\"issuer_extended_key_usages\":" + value))
                    .as(value)
                    .isInstanceOf(ConfigException.class);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"portal-a\"", "\"portal-a\"", "portal a", "portal\\a", "portal\ta", ""})
    void refusesClientIdsThatCannotBeComparedVerbatim(String clientId) {
        assertThatThrownBy(() -> load(clientId, ""))
                .isInstanceOf(ConfigException.class)
                .hasMessageContaining("client_id");
    }

    @Test
    void acceptsUsualClientIds() throws Exception {
        for (String clientId : List.of("portal-a", "svc.account_1", "https://rp.example/client", "urn:x:y@z")) {
            assertThat(load(clientId, "").client(clientId)).isPresent();
        }
    }

    @Test
    void aClientBindingCarriesItsConfigurationRevision() throws Exception {
        AdapterConfig config = load("c", "");
        assertThat(config.client("c").orElseThrow().revision()).isEqualTo(config.revision());
    }
}
