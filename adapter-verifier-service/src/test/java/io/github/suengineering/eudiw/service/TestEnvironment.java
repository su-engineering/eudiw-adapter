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

import io.github.suengineering.eudiw.core.x509.TestPki;
import io.github.suengineering.eudiw.core.x509.TestPki.Issued;
import io.quarkus.test.common.QuarkusTestResourceLifecycleManager;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.bouncycastle.asn1.x509.KeyUsage;

/**
 * Generates synthetic key material and a two-tenant configuration on disk before Quarkus starts. Tests read the
 * same files back, because the test class and this manager run in different class loaders.
 */
public class TestEnvironment implements QuarkusTestResourceLifecycleManager {

    public static final Path DIR = Path.of("target", "test-environment").toAbsolutePath();
    public static final String TOKEN_ISSUER = "https://auth.test.example/realms/test";
    public static final String AUDIENCE = "eudiw-adapter";
    public static final String ISSUER_A = "https://issuer-a.test.example";
    public static final String ISSUER_B = "https://issuer-b.test.example";
    public static final String VCT = "https://credentials.test.example/age";
    public static final String COMPLETION_URI = "https://portal-a.test.example/done";

    @Override
    public Map<String, String> start() {
        try {
            generate();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        return Map.of(
                "eudiw.config-file",
                DIR.resolve("tenants.json").toString(),
                "eudiw.public-base-url",
                "https://adapter.test.example",
                "eudiw.data-key",
                Base64.getEncoder().encodeToString(new byte[32]),
                "eudiw.production",
                "false",
                "quarkus.oidc.auth-server-url",
                "",
                "quarkus.oidc.discovery-enabled",
                "false",
                "quarkus.oidc.public-key",
                read("token-public.b64"),
                "quarkus.oidc.token.issuer",
                TOKEN_ISSUER,
                "quarkus.oidc.token.audience",
                AUDIENCE,
                "eudiw.sweep-interval",
                "off");
    }

    @Override
    public void stop() {}

    private static void generate() throws Exception {
        Files.createDirectories(DIR);
        Instant from = Instant.now().minus(1, ChronoUnit.DAYS);
        Instant until = Instant.now().plus(3650, ChronoUnit.DAYS);

        Issued rootA = TestPki.rootCa("CN=Issuer Root A", from, until);
        Issued issuerA = TestPki.endEntity(
                "CN=Issuer A",
                rootA,
                from,
                until,
                KeyUsage.digitalSignature,
                List.of(TestPki.dns("issuer-a.test.example")));
        Issued rootB = TestPki.rootCa("CN=Issuer Root B", from, until);
        Issued issuerB = TestPki.endEntity(
                "CN=Issuer B",
                rootB,
                from,
                until,
                KeyUsage.digitalSignature,
                List.of(TestPki.dns("issuer-b.test.example")));
        Issued rpRoot = TestPki.rootCa("CN=RP Root", from, until);
        Issued rpA = TestPki.endEntity("CN=Verifier A", rpRoot, from, until, KeyUsage.digitalSignature, List.of());
        Issued rpB = TestPki.endEntity("CN=Verifier B", rpRoot, from, until, KeyUsage.digitalSignature, List.of());

        write("issuer-a-root.pem", pem(rootA.certificate()));
        write("issuer-a.pem", pem(issuerA.certificate()));
        write("issuer-a-key.pem", pem(issuerA.keyPair().getPrivate()));
        write("issuer-b-root.pem", pem(rootB.certificate()));
        write("issuer-b.pem", pem(issuerB.certificate()));
        write("issuer-b-key.pem", pem(issuerB.keyPair().getPrivate()));
        write("rp-root.pem", pem(rpRoot.certificate()));
        write("rp-a.pem", pem(rpA.certificate()));
        write("rp-a-key.pem", pem(rpA.keyPair().getPrivate()));
        write("rp-b.pem", pem(rpB.certificate()));
        write("rp-b-key.pem", pem(rpB.keyPair().getPrivate()));

        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        KeyPair tokenKeys = rsa.generateKeyPair();
        write("token-key.pem", pem(tokenKeys.getPrivate()));
        write(
                "token-public.b64",
                Base64.getEncoder().encodeToString(tokenKeys.getPublic().getEncoded()));

        String dcql = """
                {"credentials":[{"id":"age","format":"dc+sd-jwt","meta":{"vct_values":["%s"]},
                  "claims":[{"path":["age_over_18"]}]}]}""".formatted(VCT);
        String tenants = """
                {"tenants":[
                  {"id":"tenant-a",
                   "verifier":{"private_key_file":"rp-a-key.pem","certificate_chain_file":"rp-a.pem"},
                   "clients":[
                     {"client_id":"portal-a","policies":["age-over-18"],"completion_uri":"%s"},
                     {"client_id":"other-app-a","policies":[]}],
                   "policies":[{"id":"age-over-18","dcql":%s,
                     "output":{"age_over_18":{"credential":"age","path":["age_over_18"]}},
                     "trust_anchors_file":"issuer-a-root.pem","allowed_issuers":["%s"],
                     "status_policy":"require_valid","session_ttl_seconds":300,"result_ttl_seconds":600}]},
                  {"id":"tenant-b",
                   "verifier":{"private_key_file":"rp-b-key.pem","certificate_chain_file":"rp-b.pem"},
                   "clients":[{"client_id":"portal-b","policies":["age-over-18"]}],
                   "policies":[{"id":"age-over-18","dcql":%s,
                     "output":{"age_over_18":{"credential":"age","path":["age_over_18"]}},
                     "trust_anchors_file":"issuer-b-root.pem",
                     "status_policy":"require_valid"}]}
                ]}""".formatted(COMPLETION_URI, dcql, ISSUER_A, dcql);
        write("tenants.json", tenants);
    }

    public static String read(String name) {
        try {
            return Files.readString(DIR.resolve(name), StandardCharsets.US_ASCII);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    public static X509Certificate certificate(String name) {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(Files.newInputStream(DIR.resolve(name)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static PrivateKey privateKey(String name, String algorithm) {
        String pem = read(name).replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
        try {
            return KeyFactory.getInstance(algorithm)
                    .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(pem)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static void write(String name, String content) throws IOException {
        Files.writeString(DIR.resolve(name), content, StandardCharsets.US_ASCII);
    }

    private static String pem(X509Certificate certificate) throws Exception {
        return "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                        .encodeToString(certificate.getEncoded())
                + "\n-----END CERTIFICATE-----\n";
    }

    private static String pem(PrivateKey key) {
        return "-----BEGIN " + "PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                        .encodeToString(key.getEncoded())
                + "\n-----END PRIVATE KEY-----\n";
    }
}
