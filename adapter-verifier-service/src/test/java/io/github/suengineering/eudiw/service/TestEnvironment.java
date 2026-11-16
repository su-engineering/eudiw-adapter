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
    public static final String PID_LIST_ID = "https://lists.test.example/pid-providers.jwt";
    public static final String PID_ISSUANCE = "http://uri.etsi.org/19602/SvcType/PID/Issuance";
    /** Webhook requests received by the test receiver, and the statuses it answers with (200 when empty). */
    public static final java.util.List<WebhookCall> WEBHOOK_CALLS = new java.util.concurrent.CopyOnWriteArrayList<>();

    public static final java.util.Deque<Integer> WEBHOOK_STATUSES = new java.util.concurrent.ConcurrentLinkedDeque<>();
    public static final byte[] WEBHOOK_SECRET =
            "test-webhook-secret-0123456789abcdef".getBytes(StandardCharsets.US_ASCII);
    private static com.sun.net.httpserver.HttpServer webhookServer;

    public record WebhookCall(Map<String, String> headers, String body) {}

    public static final String COMPLETION_URI = "https://portal-a.test.example/done";

    @Override
    public Map<String, String> start() {
        try {
            generate();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        Map<String, String> settings = new java.util.HashMap<>(Map.of(
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
                "off"));
        settings.put("eudiw.trusted-lists.refresh-interval", "off");
        settings.put("eudiw.webhook.interval", "off");
        return settings;
    }

    @Override
    public void stop() {}

    private static synchronized int startWebhookReceiver() throws IOException {
        if (webhookServer == null) {
            webhookServer = com.sun.net.httpserver.HttpServer.create(
                    new java.net.InetSocketAddress(java.net.InetAddress.getLoopbackAddress(), 0), 0);
            webhookServer.createContext("/hook", exchange -> {
                Map<String, String> headers = new java.util.HashMap<>();
                exchange.getRequestHeaders()
                        .forEach((k, v) -> headers.put(k.toLowerCase(java.util.Locale.ROOT), v.get(0)));
                String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                WEBHOOK_CALLS.add(new WebhookCall(headers, body));
                Integer status = WEBHOOK_STATUSES.poll();
                exchange.sendResponseHeaders(status == null ? 200 : status, -1);
                exchange.close();
            });
            webhookServer.start();
        }
        return webhookServer.getAddress().getPort();
    }

    private static void generate() throws Exception {
        Files.createDirectories(DIR);
        int webhookPort = startWebhookReceiver();
        write("portal-a.whsec", "whsec_" + Base64.getEncoder().encodeToString(WEBHOOK_SECRET));
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

        Issued listSigner = TestPki.endEntity(
                "CN=List Signer,O=Test Operator,C=EU", rpRoot, from, until, KeyUsage.digitalSignature, List.of());
        write("list-signer.pem", pem(listSigner.certificate()));
        write("pid-list.jwt", pidList(listSigner, rootA.certificate()));

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
        String listedDcql = """
                {"credentials":[{"id":"age","format":"dc+sd-jwt","meta":{"vct_values":["%s"]},
                  "trusted_authorities":[{"type":"etsi_tl","values":["%s"]}],
                  "claims":[{"path":["age_over_18"]}]}]}""".formatted(VCT, PID_LIST_ID);
        String tenants =
                """
                {"tenants":[
                  {"id":"tenant-a",
                   "verifier":{"private_key_file":"rp-a-key.pem","certificate_chain_file":"rp-a.pem"},
                   "clients":[
                     {"client_id":"portal-a","policies":["age-over-18"],"completion_uri":"%s",
                      "webhook":{"url":"http://127.0.0.1:%d/hook","secret_file":"portal-a.whsec"}},
                     {"client_id":"other-app-a","policies":[]}],
                   "policies":[{"id":"age-over-18","dcql":%s,
                     "output":{"age_over_18":{"credential":"age","path":["age_over_18"]}},
                     "trust_anchors_file":"issuer-a-root.pem","allowed_issuers":["%s"],
                     "status_policy":"require_valid","session_ttl_seconds":300,"result_ttl_seconds":600}]},
                  {"id":"tenant-b",
                   "verifier":{"private_key_file":"rp-b-key.pem","certificate_chain_file":"rp-b.pem"},
                   "clients":[{"client_id":"portal-b","policies":["age-over-18","age-over-18-listed"]}],
                   "policies":[{"id":"age-over-18","dcql":%s,
                     "output":{"age_over_18":{"credential":"age","path":["age_over_18"]}},
                     "trust_anchors_file":"issuer-b-root.pem",
                     "status_policy":"require_valid"},
                    {"id":"age-over-18-listed","dcql":%s,
                     "output":{"age_over_18":{"credential":"age","path":["age_over_18"]}},
                     "trusted_lists":[{"identifier":"%s","location":"pid-list.jwt","format":"lote_json",
                       "signer_certificates_file":"list-signer.pem","issuance_service_types":["%s"]}],
                     "status_policy":"require_valid"}]}
                ]}""".formatted(COMPLETION_URI, webhookPort, dcql, ISSUER_A, dcql, listedDcql, PID_LIST_ID, PID_ISSUANCE);
        write("tenants.json", tenants);
    }

    /** A TS 119 602 PID providers list (JSON, compact JAdES) that lists issuer root A. Synthetic. */
    private static String pidList(Issued signer, X509Certificate listed) throws Exception {
        Instant issued = Instant.now().minus(1, ChronoUnit.DAYS).truncatedTo(ChronoUnit.SECONDS);
        Map<String, Object> service = Map.of(
                "ServiceInformation",
                Map.of(
                        "ServiceName",
                        List.of(Map.of("lang", "en", "value", "PID issuance")),
                        "ServiceTypeIdentifier",
                        PID_ISSUANCE,
                        "ServiceDigitalIdentity",
                        Map.of(
                                "X509Certificates",
                                List.of(Map.of("val", Base64.getEncoder().encodeToString(listed.getEncoded()))))));
        Map<String, Object> entity = Map.of(
                "TrustedEntityInformation",
                Map.of(
                        "TEName", List.of(Map.of("lang", "en", "value", "Issuer A")),
                        "TEAddress", Map.of(),
                        "TEInformationURI", List.of(Map.of("lang", "en", "uriValue", ISSUER_A))),
                "TrustedEntityServices",
                List.of(service));
        Map<String, Object> scheme = Map.of(
                "LoTEVersionIdentifier",
                1,
                "LoTESequenceNumber",
                1,
                "LoTEType",
                "http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList",
                "SchemeOperatorName",
                List.of(Map.of("lang", "en", "value", "Test Operator")),
                "SchemeTerritory",
                "EU",
                "ListIssueDateTime",
                issued.toString(),
                "NextUpdate",
                issued.plus(90, ChronoUnit.DAYS).toString());
        Map<String, Object> lote =
                Map.of("LoTE", Map.of("ListAndSchemeInformation", scheme, "TrustedEntitiesList", List.of(entity)));
        com.nimbusds.jose.JWSObject jws = new com.nimbusds.jose.JWSObject(
                new com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.ES256)
                        .x509CertChain(List.of(com.nimbusds.jose.util.Base64.encode(
                                signer.certificate().getEncoded())))
                        .customParam("iat", issued.getEpochSecond())
                        .build(),
                new com.nimbusds.jose.Payload(com.nimbusds.jose.util.JSONObjectUtils.toJSONString(lote)));
        jws.sign(new com.nimbusds.jose.crypto.ECDSASigner(
                (java.security.interfaces.ECPrivateKey) signer.keyPair().getPrivate()));
        return jws.serialize();
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
