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

import io.github.suengineering.eudiw.core.json.Json;
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** How a policy's {@code registration} block is loaded and checked at startup. */
class RegistrationConfigTest {

    private static final String VCT = "https://credentials.test.example/age";
    private static final String DCQL = """
            {"credentials":[{"id":"age","format":"dc+sd-jwt","meta":{"vct_values":["%s"]},
              "claims":[{"path":["age_over_18"]}]}]}""".formatted(VCT);

    @TempDir
    Path dir;

    private TestPki.Issued registrar;

    @BeforeEach
    void keys() throws Exception {
        Instant from = Instant.now().minus(Duration.ofDays(1));
        Instant until = Instant.now().plus(Duration.ofDays(365));
        TestPki.Issued root = TestPki.rootCa("CN=Root", from, until);
        TestPki.Issued rp =
                TestPki.endEntity("CN=RP,2.5.4.97=VATBE-1", root, from, until, KeyUsage.digitalSignature, List.of());
        registrar = TestPki.rootCa("CN=Registrar", from, until);
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

    private static Map<String, Object> dataset(List<String> declaredClaim) {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("identifier", "VATBE-1");
        data.put("srvDescription", List.of(Map.of("lang", "en", "content", "Portal")));
        data.put("registryURI", "https://registrar.example/api");
        data.put("intendedUseIdentifier", "iu-1");
        data.put("purpose", List.of(Map.of("lang", "en", "content", "Age check")));
        data.put("policyURI", "https://rp.example/privacy");
        data.put(
                "credential",
                List.of(Map.of(
                        "format", "dc+sd-jwt",
                        "meta", Map.of("vct_values", List.of(VCT)),
                        "claim", List.of(Map.of("path", declaredClaim)))));
        return data;
    }

    private String certificate(String typ, Instant expires) throws Exception {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("sub", "VATBE-1");
        claims.put("iat", Instant.now().minus(Duration.ofDays(10)).getEpochSecond());
        claims.put("exp", expires.getEpochSecond());
        claims.put(
                "credentials",
                List.of(Map.of(
                        "format", "dc+sd-jwt",
                        "meta", Map.of("vct_values", List.of(VCT)),
                        "claim", List.of(Map.of("path", List.of("age_over_18"))))));
        return TestWallet.sign(claims, registrar.keyPair().getPrivate(), typ, List.of(registrar.certificate()));
    }

    private AdapterConfig load(Map<String, Object> registration) throws Exception {
        String tenants = """
                {"tenants":[{"id":"t","verifier":{"private_key_file":"rp-key.pem","certificate_chain_file":"rp.pem"},
                  "clients":[{"client_id":"c","policies":["p"]}],
                  "policies":[{"id":"p","dcql":%s,
                    "output":{"age_over_18":{"credential":"age","path":["age_over_18"]}},
                    "trust_anchors_file":"anchors.pem","registration":%s}]}]}""".formatted(DCQL, Json.toJson(registration));
        Path file = dir.resolve("tenants.json");
        Files.writeString(file, tenants, StandardCharsets.UTF_8);
        return ConfigLoader.load(file, false);
    }

    @Test
    void loadsAnInlineDatasetAndACertificate() throws Exception {
        Files.writeString(
                dir.resolve("rc.jwt"), certificate("rc-wrp+jwt", Instant.now().plus(Duration.ofDays(100))));
        AdapterConfig config =
                load(Map.of("registrar_dataset", dataset(List.of("age_over_18")), "certificate_file", "rc.jwt"));
        var registration =
                config.tenants().get("t").policies().get("p").registration().orElseThrow();
        assertThat(registration.certificate()).isPresent();
        assertThat(registration.verifierInfo(Instant.now())).hasSize(2);
    }

    @Test
    void loadsADatasetFile() throws Exception {
        Files.writeString(dir.resolve("dataset.json"), Json.toJson(dataset(List.of("age_over_18"))));
        AdapterConfig config = load(Map.of("registrar_dataset_file", "dataset.json"));
        assertThat(config.tenants()
                        .get("t")
                        .policies()
                        .get("p")
                        .registration()
                        .orElseThrow()
                        .certificate())
                .isEmpty();
    }

    @Test
    void refusesAQueryTheDatasetDoesNotDeclare() {
        assertThatThrownBy(() -> load(Map.of("registrar_dataset", dataset(List.of("age_over_21")))))
                .isInstanceOf(ConfigException.class)
                .hasMessageContaining("more than the registrar dataset declares");
    }

    @Test
    void refusesAnIncompleteDataset() {
        Map<String, Object> data = dataset(List.of("age_over_18"));
        data.remove("registryURI");
        assertThatThrownBy(() -> load(Map.of("registrar_dataset", data)))
                .isInstanceOf(ConfigException.class)
                .hasMessageContaining("registryURI");
        assertThatThrownBy(() -> load(Map.of())).hasMessageContaining("exactly one");
    }

    @Test
    void refusesAnExpiredOrMistypedCertificate() throws Exception {
        Files.writeString(
                dir.resolve("old.jwt"), certificate("rc-wrp+jwt", Instant.now().minus(Duration.ofDays(1))));
        assertThatThrownBy(() -> load(
                        Map.of("registrar_dataset", dataset(List.of("age_over_18")), "certificate_file", "old.jwt")))
                .isInstanceOf(ConfigException.class)
                .hasMessageContaining("expired");
        Files.writeString(
                dir.resolve("typ.jwt"), certificate("JWT", Instant.now().plus(Duration.ofDays(1))));
        assertThatThrownBy(() -> load(
                        Map.of("registrar_dataset", dataset(List.of("age_over_18")), "certificate_file", "typ.jwt")))
                .isInstanceOf(ConfigException.class)
                .hasMessageContaining("typ");
    }
}
