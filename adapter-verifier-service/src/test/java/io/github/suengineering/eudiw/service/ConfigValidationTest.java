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

    /** One tenant whose {@code verifier} object is {@code verifier}; {@code production} as given. */
    private AdapterConfig loadVerifier(String verifier, boolean production) throws Exception {
        String tenants = """
                {"tenants":[{"id":"t","verifier":%s,
                  "clients":[{"client_id":"c","policies":["p"]}],
                  "policies":[{"id":"p","dcql":%s,
                    "output":{"age_over_18":{"credential":"age","path":["age_over_18"]}},
                    "trust_anchors_file":"anchors.pem"}]}]}""".formatted(verifier, DCQL);
        Path file = dir.resolve("tenants.json");
        Files.writeString(file, tenants, StandardCharsets.UTF_8);
        return ConfigLoader.load(file, production);
    }

    @Test
    void theVerifierKeyHasExactlyOneSource() throws Exception {
        Files.writeString(dir.resolve("vault-token"), "token\n");
        assertThatThrownBy(() -> loadVerifier("""
                        {"private_key_file":"rp-key.pem","certificate_chain_file":"rp.pem",
                         "vault_transit":{"address":"https://vault.test","key_name":"rp","token_file":"vault-token"}}""", false))
                .isInstanceOf(ConfigException.class)
                .hasMessageContaining(
                        "exactly one of verifier.private_key_file, verifier.pkcs11, verifier.vault_transit and verifier.aws_kms");
        assertThatThrownBy(() -> loadVerifier("{\"certificate_chain_file\":\"rp.pem\"}", false))
                .isInstanceOf(ConfigException.class)
                .hasMessageContaining("exactly one of");
    }

    @Test
    void vaultTransitNeedsHttpsInProductionAndAReadableTokenFile() throws Exception {
        Files.writeString(dir.resolve("vault-token"), "token\n");
        assertThatThrownBy(() -> loadVerifier("""
                        {"certificate_chain_file":"rp.pem",
                         "vault_transit":{"address":"http://vault.test:8200","key_name":"rp","token_file":"vault-token"}}""", true))
                .isInstanceOf(ConfigException.class)
                .hasMessageContaining("vault_transit.address must use https in production");
        assertThatThrownBy(() -> loadVerifier("""
                        {"certificate_chain_file":"rp.pem",
                         "vault_transit":{"address":"https://vault.test","key_name":"rp","token_file":"missing-token"}}""", false))
                .isInstanceOf(ConfigException.class)
                .hasMessageContaining("cannot read the Vault token file");
        assertThatThrownBy(() -> loadVerifier("""
                        {"certificate_chain_file":"rp.pem",
                         "vault_transit":{"address":"https://vault.test","key_name":"rp/../sys","token_file":"vault-token"}}""", false))
                .isInstanceOf(ConfigException.class)
                .hasMessageContaining("vault_transit.key_name");
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "https://shop.example/",
                "https://shop.example/path",
                "https://Shop.example",
                "https://shop.example:443",
                "http://shop.example:80",
                "shop.example",
                "ftp://shop.example",
                "https://shop.example?x=1"
            })
    void dcApiOriginsMustBeExactOrigins(String origin) {
        assertThatThrownBy(() -> ConfigLoader.dcApiOrigin(origin, false, "client c"))
                .isInstanceOf(ConfigException.class)
                .hasMessageContaining("dc_api_origins");
    }

    @Test
    void dcApiOriginsAreHttpsInProduction() {
        assertThat(ConfigLoader.dcApiOrigin("https://shop.example", true, "c")).isEqualTo("https://shop.example");
        assertThat(ConfigLoader.dcApiOrigin("http://localhost:3000", false, "c"))
                .isEqualTo("http://localhost:3000");
        assertThat(ConfigLoader.dcApiOrigin("https://shop.example:8443", true, "c"))
                .isEqualTo("https://shop.example:8443");
        assertThatThrownBy(() -> ConfigLoader.dcApiOrigin("http://localhost:3000", true, "c"))
                .isInstanceOf(ConfigException.class)
                .hasMessageContaining("https in production");
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

    @Test
    void theRevisionIsAFullSha256() throws Exception {
        assertThat(load("c", "").revision()).matches("[0-9a-f]{64}");
    }

    @Test
    void theConfigurationNamesEveryFileItRead() throws Exception {
        AdapterConfig config = load("c", "");
        assertThat(config.sources().keySet())
                .containsExactly(
                        dir.resolve("tenants.json").toAbsolutePath().normalize(),
                        dir.resolve("rp.pem").toAbsolutePath().normalize(),
                        dir.resolve("rp-key.pem").toAbsolutePath().normalize(),
                        dir.resolve("anchors.pem").toAbsolutePath().normalize());
        config.sources()
                .forEach((path, hash) ->
                        assertThat(ConfigLoader.contentHash(path)).isEqualTo(hash));
    }

    @Test
    void aChangedReferencedFileIsANewRevision() throws Exception {
        String before = load("c", "").revision();
        // The parsed key material is the same, but the file is not: before, only parsed certificates counted, so a
        // rewritten key or webhook secret file was read and then ignored.
        Files.writeString(dir.resolve("rp-key.pem"), Files.readString(dir.resolve("rp-key.pem")) + "\n");
        assertThat(load("c", "").revision()).isNotEqualTo(before);
    }

    @Test
    void aFailedLoadReportsAMissingFileSoItsCreationIsNoticed() throws Exception {
        java.util.Map<Path, String> sources = new java.util.LinkedHashMap<>();
        Path file = dir.resolve("tenants.json");
        Files.writeString(file, """
                {"tenants":[{"id":"t","verifier":{"private_key_file":"rp-key.pem","certificate_chain_file":"rp.pem"},
                  "clients":[{"client_id":"c","policies":["p"]}],
                  "policies":[{"id":"p","dcql":%s,
                    "output":{"age_over_18":{"credential":"age","path":["age_over_18"]}},
                    "trust_anchors_file":"not-there-yet.pem"}]}]}""".formatted(DCQL));
        Path missing = dir.resolve("not-there-yet.pem").toAbsolutePath().normalize();
        assertThatThrownBy(() -> ConfigLoader.load(file, false, sources)).isInstanceOf(ConfigException.class);
        assertThat(sources).containsEntry(missing, "missing");
        assertThat(ConfigLoader.contentHash(missing)).isEqualTo("missing");

        // Once the file exists its hash differs from the one recorded, which is what makes the reloader try again.
        Files.copy(dir.resolve("anchors.pem"), missing);
        assertThat(ConfigLoader.contentHash(missing)).isNotEqualTo(sources.get(missing));
        assertThat(ConfigLoader.load(file, false).sources()).containsKey(missing);
    }

    @Test
    void aFailedLoadStillReportsTheFilesItRead() throws Exception {
        Files.writeString(dir.resolve("anchors.pem"), "not a certificate");
        java.util.Map<Path, String> sources = new java.util.LinkedHashMap<>();
        Path file = dir.resolve("tenants.json");
        Files.writeString(file, """
                {"tenants":[{"id":"t","verifier":{"private_key_file":"rp-key.pem","certificate_chain_file":"rp.pem"},
                  "clients":[{"client_id":"c","policies":["p"]}],
                  "policies":[{"id":"p","dcql":%s,
                    "output":{"age_over_18":{"credential":"age","path":["age_over_18"]}},
                    "trust_anchors_file":"anchors.pem"}]}]}""".formatted(DCQL));
        assertThatThrownBy(() -> ConfigLoader.load(file, false, sources)).isInstanceOf(ConfigException.class);
        assertThat(sources)
                .containsKey(dir.resolve("anchors.pem").toAbsolutePath().normalize());
    }

    /** A wallet login client (ADR-018) with {@code oidc} as its oidc object; the policy outputs age_over_18 only. */
    private AdapterConfig loadOidc(String provider, String oidc, boolean production) throws Exception {
        java.security.KeyPairGenerator rsa = java.security.KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        Files.writeString(
                dir.resolve("id-token-key.pem"),
                "-----BEGIN " + "PRIVATE KEY-----\n"
                        + Base64.getMimeEncoder()
                                .encodeToString(
                                        rsa.generateKeyPair().getPrivate().getEncoded())
                        + "\n-----END PRIVATE KEY-----\n");
        Files.writeString(dir.resolve("subject.key"), Base64.getEncoder().encodeToString(new byte[32]));
        Files.writeString(dir.resolve("short.key"), Base64.getEncoder().encodeToString(new byte[16]));
        Files.writeString(dir.resolve("client.secret"), "a-client-secret-of-at-least-32-characters");
        String tenants = """
                {"tenants":[{"id":"t","verifier":{"private_key_file":"rp-key.pem","certificate_chain_file":"rp.pem"},
                  %s
                  "clients":[{"client_id":"login","policies":["p"],"oidc":%s}],
                  "policies":[{"id":"p","dcql":%s,
                    "output":{"age_over_18":{"credential":"age","path":["age_over_18"]}},
                    "trust_anchors_file":"anchors.pem"}]}]}""".formatted(provider, oidc, DCQL);
        Path file = dir.resolve("tenants.json");
        Files.writeString(file, tenants, StandardCharsets.UTF_8);
        return ConfigLoader.load(file, production);
    }

    private static final String PROVIDER =
            "\"oidc_provider\":{\"signing_key_file\":\"id-token-key.pem\",\"subject_key_file\":\"subject.key\"},";

    private static String oidc(String extra) {
        return """
                {"client_secret_file":"client.secret","redirect_uris":["https://idp.example/cb"],"policy_id":"p",
                 "subject_claims":["age_over_18"]%s}""".formatted(extra);
    }

    @Test
    void walletLoginClientsAreValidated() throws Exception {
        assertThat(loadOidc(PROVIDER, oidc(",\"subject_from_personal_attributes\":true"), false)
                        .tenant("t")
                        .orElseThrow()
                        .clients()
                        .get("login")
                        .oidc())
                .isPresent();
        assertThatThrownBy(() -> loadOidc("", oidc(",\"subject_from_personal_attributes\":true"), false))
                .hasMessageContaining("need the tenant's oidc_provider");
        assertThatThrownBy(() -> loadOidc(PROVIDER, oidc(""), false))
                .hasMessageContaining("include no persistent identifier");
        assertThatThrownBy(() -> loadOidc(
                        PROVIDER,
                        oidc(
                                ",\"subject_from_personal_attributes\":true,\"id_token_claims\":{\"email\":\"age_over_18\"}"),
                        false))
                .hasMessageContaining("must not contain email");
        assertThatThrownBy(() -> loadOidc(
                        PROVIDER,
                        oidc(
                                ",\"subject_from_personal_attributes\":true,\"id_token_claims\":{\"sub\":\"age_over_18\"}"),
                        false))
                .hasMessageContaining("cannot set sub");
        assertThatThrownBy(() -> loadOidc(
                        PROVIDER,
                        oidc(",\"subject_from_personal_attributes\":true,\"redirect_uris\":[\"http://idp.example/cb\"]")
                                .replace("\"redirect_uris\":[\"https://idp.example/cb\"],", ""),
                        true))
                .hasMessageContaining("redirect URIs must use https");
        assertThatThrownBy(() -> loadOidc(
                        PROVIDER.replace("subject.key", "short.key"),
                        oidc(",\"subject_from_personal_attributes\":true"),
                        false))
                .hasMessageContaining("at least 32 random bytes");
    }
}
