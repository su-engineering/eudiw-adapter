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

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

import io.agroal.api.AgroalDataSource;
import io.github.suengineering.eudiw.core.cbor.CborEncoder;
import io.github.suengineering.eudiw.core.cbor.CborItem;
import io.github.suengineering.eudiw.core.mdoc.SessionTranscripts;
import io.github.suengineering.eudiw.core.mdoc.TestMdocIssuer;
import io.github.suengineering.eudiw.core.net.HttpFetcher;
import io.github.suengineering.eudiw.service.engine.AdapterRuntime;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import io.restassured.path.json.JsonPath;
import io.restassured.response.Response;
import jakarta.inject.Inject;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * End-to-end scenarios against the running service and a real PostgreSQL database: V-01 (happy path with
 * minimized result), V-04 (tenant isolation), V-06 (wallet decline), V-07 (concurrent responses), plus expiry,
 * cancellation, idempotency, same-device response codes and revocation.
 */
@QuarkusTest
@QuarkusTestResource(TestEnvironment.class)
class VerificationFlowTest {

    @Inject
    AdapterRuntime runtime;

    @Inject
    AgroalDataSource dataSource;

    @Inject
    io.github.suengineering.eudiw.service.store.TrustedListSequenceStore sequenceStore;

    @Inject
    io.github.suengineering.eudiw.service.engine.VerificationEngine engine;

    @Inject
    io.micrometer.core.instrument.MeterRegistry registry;

    private static final String MDOC_STATUS = "https://mdoc-issuer.test.example/status/";

    private final TestWallet wallet = new TestWallet();
    private final MutableClock clock = new MutableClock(Instant.now());

    @BeforeEach
    void setUp() {
        HttpFetcher fetcher = (uri, accept, max) -> {
            if (uri.toString().startsWith(MDOC_STATUS)) {
                try {
                    return TestEnvironment.mdocIssuer.statusListCwt(uri.toString());
                } catch (Exception e) {
                    throw new HttpFetcher.FetchException("unavailable", e);
                }
            }
            if (uri.toString().equals(TestEnvironment.CRL_C)) {
                try {
                    return java.nio.file.Files.readAllBytes(TestEnvironment.DIR.resolve("issuer-c-root.crl"));
                } catch (java.io.IOException e) {
                    throw new HttpFetcher.FetchException("unreadable", e);
                }
            }
            if (uri.toString().startsWith(TestEnvironment.ISSUER_C)) {
                return TestWallet.statusListToken(TestEnvironment.ISSUER_C, "issuer-c-key.pem", "issuer-c.pem")
                        .getBytes(StandardCharsets.US_ASCII);
            }
            String issuer = uri.toString().startsWith(TestEnvironment.ISSUER_A) ? "a" : "b";
            return TestWallet.statusListToken(
                            issuer.equals("a") ? TestEnvironment.ISSUER_A : TestEnvironment.ISSUER_B,
                            "issuer-" + issuer + "-key.pem",
                            "issuer-" + issuer + ".pem")
                    .getBytes(StandardCharsets.US_ASCII);
        };
        runtime.reconfigureForTests(clock, fetcher);
    }

    private JsonPath create(String clientId, String mode) {
        return create(clientId, mode, "age-over-18");
    }

    private JsonPath create(String clientId, String mode, String policyId) {
        return given().auth()
                .oauth2(TestWallet.fullToken(clientId))
                .header("Idempotency-Key", UUID.randomUUID().toString())
                .contentType(ContentType.JSON)
                .body(Map.of("policy_id", policyId, "mode", mode, "client_reference", "ref-1"))
                .post("/v1/verification-sessions")
                .then()
                .statusCode(201)
                .extract()
                .jsonPath();
    }

    private Map<String, Object> presentAgeOver18(Map<String, Object> request, int statusIndex) {
        return Map.of(
                "vp_token",
                Map.of(
                        "age",
                        List.of(wallet.presentation(
                                request,
                                TestEnvironment.ISSUER_A,
                                "issuer-a-key.pem",
                                "issuer-a.pem",
                                Map.of("age_over_18", true, "given_name", "Erika-Canary"),
                                statusIndex))));
    }

    @Test
    void v01HappyPathReturnsOnlyTheMinimizedClaim() throws Exception {
        JsonPath session = create("portal-a", "cross_device");
        String id = session.getString("id");
        assertThat(session.getString("status")).isEqualTo("pending");
        assertThat(session.getString("wallet_launch.launch_uri")).startsWith("openid4vp://?client_id=x509_hash%3A");

        Map<String, Object> request = TestWallet.fetchRequest(session.getString("wallet_launch.request_uri"));
        // The registered intended use travels in verifier_info (ETSI TS 119 472-2 RO-01 to RO-16).
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> verifierInfo = (List<Map<String, Object>>) request.get("verifier_info");
        assertThat(verifierInfo)
                .extracting(e -> e.get("format"))
                .containsExactly("registrar_dataset", "registration_cert");
        assertThat(((Map<?, ?>) verifierInfo.get(0).get("data")).get("identifier"))
                .isEqualTo(TestEnvironment.RP_A_ID);
        assertThat(new String(
                        java.util.Base64.getUrlDecoder()
                                .decode((String) verifierInfo.get(1).get("data")),
                        java.nio.charset.StandardCharsets.US_ASCII))
                .isEqualTo(java.nio.file.Files.readString(TestEnvironment.DIR.resolve("rc-a.jwt"))
                        .strip());
        assertThat(request).containsEntry("response_mode", "direct_post.jwt");
        Map<String, Object> response = presentAgeOver18(request, 1);
        @SuppressWarnings("unchecked")
        String presentation = ((List<String>) ((Map<String, Object>) response.get("vp_token")).get("age")).get(0);
        String[] parts = presentation.split("~");
        String issuerJwt = parts[0];
        List<String> disclosures = List.of(parts).subList(1, parts.length - 1);
        Response walletReply = TestWallet.respond(request, response);
        assertThat(walletReply.statusCode()).isEqualTo(200);

        String token = TestWallet.fullToken("portal-a");
        given().auth()
                .oauth2(token)
                .get("/v1/verification-sessions/" + id)
                .then()
                .statusCode(200)
                .body("status", org.hamcrest.Matchers.equalTo("verified"))
                .body("result_available", org.hamcrest.Matchers.equalTo(true));

        String result = given().auth()
                .oauth2(token)
                .get("/v1/verification-sessions/" + id + "/result")
                .then()
                .statusCode(200)
                .extract()
                .asString();
        JsonPath json = new JsonPath(result);
        assertThat(json.getBoolean("claims.age_over_18")).isTrue();
        assertThat(json.getMap("claims")).containsOnlyKeys("age_over_18");
        assertThat(result).doesNotContain("Erika-Canary").doesNotContain("given_name");
        assertThat(json.getString("credential_evidence[0].issuer")).isEqualTo(TestEnvironment.ISSUER_A);

        // retrieved once, then gone
        given().auth()
                .oauth2(token)
                .get("/v1/verification-sessions/" + id + "/result")
                .then()
                .statusCode(404);
        String stored = databaseText();
        assertThat(stored)
                .doesNotContain("Erika-Canary")
                .doesNotContain("age_over_18")
                .doesNotContain(issuerJwt);
        String log = readLog();
        assertThat(log)
                .doesNotContain("Erika-Canary")
                .doesNotContain(token)
                .doesNotContain((String) request.get("nonce"))
                .doesNotContain(issuerJwt);
        for (String disclosure : disclosures) {
            assertThat(stored).doesNotContain(disclosure);
            assertThat(log).doesNotContain(disclosure);
        }
    }

    private static Map<String, Object> payment(String payee) {
        return Map.of(
                "type",
                TestEnvironment.TRANSACTION_TYPE,
                "credential_ids",
                List.of("age"),
                "payee",
                payee,
                "amount",
                "42.00",
                "currency",
                "EUR");
    }

    private io.restassured.response.ValidatableResponse createWithTransactionData(
            String policyId, Object transactionData, String idempotencyKey) {
        return given().auth()
                .oauth2(TestWallet.fullToken("portal-a"))
                .header("Idempotency-Key", idempotencyKey)
                .contentType(ContentType.JSON)
                .body(Map.of("policy_id", policyId, "transaction_data", transactionData))
                .post("/v1/verification-sessions")
                .then();
    }

    @Test
    void transactionDataIsBoundThroughTheKeyBindingJwtAndReturnedOnlyInTheResult() throws Exception {
        JsonPath session = createWithTransactionData(
                        "age-over-18-tx",
                        List.of(payment("Canary-Shop")),
                        UUID.randomUUID().toString())
                .statusCode(201)
                .extract()
                .jsonPath();
        String id = session.getString("id");
        assertThat(session.prettify()).doesNotContain("Canary-Shop");

        Map<String, Object> request = TestWallet.fetchRequest(session.getString("wallet_launch.request_uri"));
        @SuppressWarnings("unchecked")
        List<String> sent = (List<String>) request.get("transaction_data");
        assertThat(sent).hasSize(1);
        assertThat(new String(java.util.Base64.getUrlDecoder().decode(sent.get(0)), StandardCharsets.UTF_8))
                .contains("\"payee\":\"Canary-Shop\"")
                .doesNotContain("transaction_data_hashes_alg");
        assertThat(TestWallet.respond(request, presentAgeOver18(request, 1)).statusCode())
                .isEqualTo(200);

        String token = TestWallet.fullToken("portal-a");
        String status = given().auth()
                .oauth2(token)
                .get("/v1/verification-sessions/" + id)
                .then()
                .statusCode(200)
                .body("status", org.hamcrest.Matchers.equalTo("verified"))
                .extract()
                .asString();
        assertThat(status).doesNotContain("Canary-Shop");
        JsonPath result = given().auth()
                .oauth2(token)
                .get("/v1/verification-sessions/" + id + "/result")
                .then()
                .statusCode(200)
                .extract()
                .jsonPath();
        assertThat(result.getList("transaction_data")).hasSize(1);
        assertThat(result.getString("transaction_data[0].payee")).isEqualTo("Canary-Shop");
        assertThat(result.getString("transaction_data[0].type")).isEqualTo(TestEnvironment.TRANSACTION_TYPE);
        assertThat(databaseText()).doesNotContain("Canary-Shop");
        assertThat(readLog()).doesNotContain("Canary-Shop");
        try (var c = dataSource.getConnection();
                var ps = c.prepareStatement(
                        "SELECT transaction_data_ciphertext FROM verification_session WHERE id = ?")) {
            ps.setString(1, id);
            try (var rs = ps.executeQuery()) {
                assertThat(rs.next()).isTrue();
                assertThat(rs.getBytes(1)).as("cleared once the session ended").isNull();
            }
        }
    }

    @Test
    void aWalletThatIgnoresTransactionDataIsRejected() {
        JsonPath session = createWithTransactionData(
                        "age-over-18-tx",
                        List.of(payment("Shop")),
                        UUID.randomUUID().toString())
                .statusCode(201)
                .extract()
                .jsonPath();
        Map<String, Object> request = TestWallet.fetchRequest(session.getString("wallet_launch.request_uri"));
        Map<String, Object> response = Map.of(
                "vp_token",
                Map.of(
                        "age",
                        List.of(wallet.presentation(
                                request,
                                TestEnvironment.ISSUER_A,
                                "issuer-a-key.pem",
                                "issuer-a.pem",
                                Map.of("age_over_18", true),
                                1,
                                false))));

        assertThat(TestWallet.respond(request, response).statusCode()).isEqualTo(400);
        given().auth()
                .oauth2(TestWallet.fullToken("portal-a"))
                .get("/v1/verification-sessions/" + session.getString("id"))
                .then()
                .body("status", org.hamcrest.Matchers.equalTo("rejected"))
                .body("reason", org.hamcrest.Matchers.equalTo("transaction_data_mismatch"));
    }

    @Test
    void transactionDataIsCheckedAgainstThePolicyWhenTheSessionIsCreated() {
        String key = UUID.randomUUID().toString();
        createWithTransactionData("age-over-18", List.of(payment("Shop")), key)
                .statusCode(400)
                .body("code", org.hamcrest.Matchers.equalTo("transaction_data_not_allowed"));
        Map<String, Object> otherType = new java.util.HashMap<>(payment("Shop"));
        otherType.put("type", "urn:test:not-allowed");
        Map<String, Object> twoCredentials = new java.util.HashMap<>(payment("Shop"));
        twoCredentials.put("credential_ids", List.of("age", "age"));
        Map<String, Object> unknownCredential = new java.util.HashMap<>(payment("Shop"));
        unknownCredential.put("credential_ids", List.of("pid"));
        Map<String, Object> clientAlgorithm = new java.util.HashMap<>(payment("Shop"));
        clientAlgorithm.put("transaction_data_hashes_alg", List.of("sha-256"));
        for (Map<String, Object> invalid : List.of(otherType, twoCredentials, unknownCredential, clientAlgorithm)) {
            createWithTransactionData(
                            "age-over-18-tx",
                            List.of(invalid),
                            UUID.randomUUID().toString())
                    .statusCode(400)
                    .body("code", org.hamcrest.Matchers.equalTo("invalid_transaction_data"));
        }
        createWithTransactionData(
                        "age-over-18-tx", "not-a-list", UUID.randomUUID().toString())
                .statusCode(400);

        // The same Idempotency-Key with other transaction data is another request.
        String reused = UUID.randomUUID().toString();
        createWithTransactionData("age-over-18-tx", List.of(payment("Shop")), reused)
                .statusCode(201);
        createWithTransactionData("age-over-18-tx", List.of(payment("Other shop")), reused)
                .statusCode(422)
                .body("code", org.hamcrest.Matchers.equalTo("idempotency_key_reused"));
    }

    @Test
    void issuerTrustedOnlyThroughASignedTrustedListIsAccepted() {
        // Tenant B's listed policy has no configured anchors: issuer A is trusted only because the signed
        // PID providers list names its root, and the query's etsi_tl names that list.
        assertThat(runtime.policiesWithoutCurrentTrustedLists()).contains("tenant-b/age-over-18-listed");
        runtime.refreshTrustedLists();
        assertThat(runtime.policiesWithoutCurrentTrustedLists()).isEmpty();

        JsonPath session = create("portal-b", "cross_device", "age-over-18-listed");
        Map<String, Object> request = TestWallet.fetchRequest(session.getString("wallet_launch.request_uri"));
        assertThat(TestWallet.respond(request, presentAgeOver18(request, 1)).statusCode())
                .isEqualTo(200);

        given().auth()
                .oauth2(TestWallet.fullToken("portal-b"))
                .get("/v1/verification-sessions/" + session.getString("id"))
                .then()
                .statusCode(200)
                .body("status", org.hamcrest.Matchers.equalTo("verified"));

        // The same credential under tenant B's anchor-file policy is still rejected.
        JsonPath other = create("portal-b", "cross_device");
        Map<String, Object> otherRequest = TestWallet.fetchRequest(other.getString("wallet_launch.request_uri"));
        TestWallet.respond(otherRequest, presentAgeOver18(otherRequest, 1));
        given().auth()
                .oauth2(TestWallet.fullToken("portal-b"))
                .get("/v1/verification-sessions/" + other.getString("id"))
                .then()
                .body("status", org.hamcrest.Matchers.equalTo("rejected"));
    }

    @Test
    void certificateRevocationRejectsAnIssuerListedInItsCaCrl() {
        // The wallet is told at once: 200 for the good presentation, 400 for the rejected one (cross-device).
        String good = presentUnderCrlPolicy(TestEnvironment.ISSUER_C, "issuer-c", 200);
        String revoked = presentUnderCrlPolicy(TestEnvironment.ISSUER_C_REVOKED, "issuer-c-revoked", 400);

        given().auth()
                .oauth2(TestWallet.fullToken("portal-a"))
                .get("/v1/verification-sessions/" + good)
                .then()
                .body("status", org.hamcrest.Matchers.equalTo("verified"));
        given().auth()
                .oauth2(TestWallet.fullToken("portal-a"))
                .get("/v1/verification-sessions/" + revoked)
                .then()
                .body("status", org.hamcrest.Matchers.equalTo("rejected"))
                .body("reason", org.hamcrest.Matchers.equalTo("certificate_revoked"));
    }

    private String presentUnderCrlPolicy(String issuer, String files, int expectedReply) {
        JsonPath session = create("portal-a", "cross_device", "age-over-18-crl");
        Map<String, Object> request = TestWallet.fetchRequest(session.getString("wallet_launch.request_uri"));
        Map<String, Object> response = Map.of(
                "vp_token",
                Map.of(
                        "age",
                        List.of(wallet.presentation(
                                request, issuer, files + "-key.pem", files + ".pem", Map.of("age_over_18", true), 1))));
        assertThat(TestWallet.respond(request, response).statusCode()).isEqualTo(expectedReply);
        return session.getString("id");
    }

    @Test
    void v04OtherTenantsCannotSeeOrTouchSessions() {
        String id = create("portal-a", "cross_device").getString("id");
        String tenantB = TestWallet.fullToken("portal-b");
        String otherAppSameTenant = TestWallet.fullToken("other-app-a");

        for (String token : List.of(tenantB, otherAppSameTenant)) {
            given().auth()
                    .oauth2(token)
                    .get("/v1/verification-sessions/" + id)
                    .then()
                    .statusCode(404);
            given().auth()
                    .oauth2(token)
                    .get("/v1/verification-sessions/" + id + "/result")
                    .then()
                    .statusCode(404);
            given().auth()
                    .oauth2(token)
                    .post("/v1/verification-sessions/" + id + "/cancel")
                    .then()
                    .statusCode(404);
        }
        given().auth()
                .oauth2(TestWallet.fullToken("portal-a"))
                .get("/v1/verification-sessions/" + id)
                .then()
                .statusCode(200)
                .body("status", org.hamcrest.Matchers.equalTo("pending"));
    }

    @Test
    void v04CredentialTrustedByTenantBIsRejectedForTenantA() {
        JsonPath session = create("portal-a", "cross_device");
        Map<String, Object> request = TestWallet.fetchRequest(session.getString("wallet_launch.request_uri"));
        Map<String, Object> response = Map.of(
                "vp_token",
                Map.of(
                        "age",
                        List.of(wallet.presentation(
                                request,
                                TestEnvironment.ISSUER_B,
                                "issuer-b-key.pem",
                                "issuer-b.pem",
                                Map.of("age_over_18", true),
                                1))));

        TestWallet.respond(request, response);

        given().auth()
                .oauth2(TestWallet.fullToken("portal-a"))
                .get("/v1/verification-sessions/" + session.getString("id"))
                .then()
                .body("status", org.hamcrest.Matchers.equalTo("rejected"))
                .body("reason", org.hamcrest.Matchers.equalTo("certificate_untrusted"));
    }

    @Test
    void v06WalletDeclineIsDenied() {
        JsonPath session = create("portal-a", "cross_device");
        Map<String, Object> request = TestWallet.fetchRequest(session.getString("wallet_launch.request_uri"));

        given().contentType("application/x-www-form-urlencoded")
                .formParam("error", "access_denied")
                .formParam("state", request.get("state"))
                .post("/oid4vp/responses")
                .then()
                .statusCode(200);

        given().auth()
                .oauth2(TestWallet.fullToken("portal-a"))
                .get("/v1/verification-sessions/" + session.getString("id"))
                .then()
                .body("status", org.hamcrest.Matchers.equalTo("denied"))
                .body("result_available", org.hamcrest.Matchers.equalTo(false));
    }

    @Test
    void v07ConcurrentResponsesProduceOneResult() throws Exception {
        JsonPath session = create("portal-a", "cross_device");
        String requestUri = session.getString("wallet_launch.request_uri");
        // two separate fetches (two request instances) and repeated posts of each
        Map<String, Object> first = TestWallet.fetchRequest(requestUri);
        Map<String, Object> second = TestWallet.fetchRequest(requestUri);
        Map<String, Object> firstResponse = presentAgeOver18(first, 1);
        Map<String, Object> secondResponse = presentAgeOver18(second, 1);

        ExecutorService pool = Executors.newFixedThreadPool(8);
        List<Callable<Integer>> calls = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            boolean useFirst = i % 2 == 0;
            calls.add(() -> TestWallet.respond(useFirst ? first : second, useFirst ? firstResponse : secondResponse)
                    .statusCode());
        }
        List<Integer> codes = new ArrayList<>();
        for (Future<Integer> f : pool.invokeAll(calls)) {
            codes.add(f.get());
        }
        pool.shutdown();

        assertThat(codes).filteredOn(c -> c == 200).hasSize(1);
        assertThat(codes).filteredOn(c -> c == 400).hasSize(7);
        assertThat(auditCount(session.getString("id"), "verified")).isEqualTo(1);
    }

    @Test
    void requestFetchesPerSessionAreCapped() {
        String path = java.net
                .URI
                .create(create("portal-a", "cross_device").getString("wallet_launch.request_uri"))
                .getPath();
        for (int i = 0; i < 5; i++) {
            given().post(path).then().statusCode(200);
        }
        given().post(path).then().statusCode(404);
        given().get(path).then().statusCode(404);
    }

    @Test
    void theSequenceStoreRefusesAReusedNumberWithOtherContent() throws Exception {
        String id = "https://tl.test.example/digest-" + java.util.UUID.randomUUID();
        assertThat(sequenceStore.advance(id, 3, "aa")).isTrue();
        assertThat(sequenceStore.advance(id, 3, "aa")).isTrue();
        assertThat(sequenceStore.advance(id, 3, "bb")).isFalse();
        assertThat(sequenceStore.advance(id, 2, "aa")).isFalse();
        assertThat(sequenceStore.digest(id)).isEqualTo("aa");
        assertThat(sequenceStore.advance(id, 4, "bb")).isTrue();
        assertThat(sequenceStore.highest(id)).isEqualTo(4);
        assertThat(sequenceStore.digest(id)).isEqualTo("bb");

        // A row written before digests were kept takes the first digest offered under its number.
        String legacy = "https://tl.test.example/legacy-" + java.util.UUID.randomUUID();
        sequenceStore.record(legacy, 9);
        assertThat(sequenceStore.digest(legacy)).isNull();
        assertThat(sequenceStore.advance(legacy, 9, "cc")).isTrue();
        assertThat(sequenceStore.advance(legacy, 9, "dd")).isFalse();

        // A number raised without a digest (as a 0.2.0 node or record() does) unbinds the old digest, so the next
        // list under that number is not refused for the previous number's content.
        String raised = "https://tl.test.example/raised-" + java.util.UUID.randomUUID();
        assertThat(sequenceStore.advance(raised, 5, "v1:aa")).isTrue();
        sequenceStore.record(raised, 6);
        assertThat(sequenceStore.digest(raised)).isNull();
        assertThat(sequenceStore.advance(raised, 6, "v1:bb")).isTrue();
        assertThat(sequenceStore.digest(raised)).isEqualTo("v1:bb");
        assertThat(sequenceStore.advance(raised, 6, "v1:cc")).isFalse();
        assertThat(sequenceStore.advance(raised, 7)).isTrue();
        assertThat(sequenceStore.advance(raised, 7, "v1:dd")).isTrue();

        // A digest of another version is replaced, not compared.
        assertThat(sequenceStore.advance(raised, 7, "v2:ee")).isTrue();
        assertThat(sequenceStore.digest(raised)).isEqualTo("v2:ee");
        assertThat(sequenceStore.advance(raised, 7, "v2:ff")).isFalse();
    }

    @Test
    void concurrentRequestFetchesStayWithinTheCap() throws Exception {
        JsonPath session = create("portal-a", "cross_device");
        String path = java.net
                .URI
                .create(session.getString("wallet_launch.request_uri"))
                .getPath();
        ExecutorService pool = Executors.newFixedThreadPool(16);
        List<Callable<Integer>> calls = new ArrayList<>();
        for (int i = 0; i < 16; i++) {
            calls.add(() -> given().post(path).statusCode());
        }
        List<Integer> codes = new ArrayList<>();
        for (Future<Integer> f : pool.invokeAll(calls)) {
            codes.add(f.get());
        }
        pool.shutdown();
        assertThat(codes).filteredOn(c -> c == 200).hasSize(5);
        try (Connection c = dataSource.getConnection();
                java.sql.PreparedStatement s =
                        c.prepareStatement("SELECT count(*) FROM request_instance WHERE session_id = ?")) {
            s.setString(1, session.getString("id"));
            try (ResultSet rs = s.executeQuery()) {
                rs.next();
                assertThat(rs.getInt(1)).isEqualTo(5);
            }
        }
    }

    @Test
    void sameDeviceRequiresTheResponseCode() {
        JsonPath session = create("portal-a", "same_device");
        Map<String, Object> request = TestWallet.fetchRequest(session.getString("wallet_launch.request_uri"));
        String redirect = TestWallet.respond(request, presentAgeOver18(request, 1))
                .then()
                .statusCode(200)
                .extract()
                .jsonPath()
                .getString("redirect_uri");
        assertThat(redirect).startsWith(TestEnvironment.COMPLETION_URI + "#response_code=");
        String code = redirect.substring(redirect.indexOf('=') + 1);
        String token = TestWallet.fullToken("portal-a");
        String path = "/v1/verification-sessions/" + session.getString("id") + "/result";

        given().auth().oauth2(token).get(path).then().statusCode(400);
        given().auth()
                .oauth2(token)
                .queryParam("response_code", "wrong")
                .get(path)
                .then()
                .statusCode(404);
        given().auth()
                .oauth2(token)
                .queryParam("response_code", code)
                .get(path)
                .then()
                .statusCode(200);
    }

    @Test
    void revokedCredentialIsRejected() {
        JsonPath session = create("portal-a", "cross_device");
        Map<String, Object> request = TestWallet.fetchRequest(session.getString("wallet_launch.request_uri"));
        TestWallet.respond(request, presentAgeOver18(request, 0));

        given().auth()
                .oauth2(TestWallet.fullToken("portal-a"))
                .get("/v1/verification-sessions/" + session.getString("id"))
                .then()
                .body("status", org.hamcrest.Matchers.equalTo("rejected"))
                .body("reason", org.hamcrest.Matchers.equalTo("credential_revoked"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void anMdocPolicyAdvertisesMdocAndVerifiesADeviceSignedPresentation() throws Exception {
        JsonPath session = create("portal-a", "cross_device", "mdl-age");
        Map<String, Object> request = TestWallet.fetchRequest(session.getString("wallet_launch.request_uri"));
        Map<String, Object> formats = (Map<String, Object>)
                ((Map<String, Object>) request.get("client_metadata")).get("vp_formats_supported");
        assertThat(formats).containsKeys("dc+sd-jwt", "mso_mdoc");
        assertThat(request.get("dcql_query").toString()).contains("intent_to_retain");

        TestWallet.respond(request, Map.of("vp_token", Map.of("mdl", List.of(mdl(request, (String)
                request.get("nonce"))))));
        given().auth()
                .oauth2(TestWallet.fullToken("portal-a"))
                .get("/v1/verification-sessions/" + session.getString("id"))
                .then()
                .body("status", org.hamcrest.Matchers.equalTo("verified"));
        // The test signer is long-lived and has no CRL distribution point: accepted, and both recorded as conformance
        // warnings.
        assertThat(auditCodes(session.getString("id"), "conformance_warning"))
                .containsExactly("mdoc_signer_validity_over_457_days", "mdoc_signer_without_crl_distribution_point");
    }

    @Test
    void anMdocStatusIsCheckedAgainstACwtStatusList() throws Exception {
        try {
            for (long idx : new long[] {1, 0}) {
                TestEnvironment.mdocIssuer.status = TestMdocIssuer.statusList(MDOC_STATUS + idx, idx);
                JsonPath session = create("portal-a", "cross_device", "mdl-age");
                Map<String, Object> request = TestWallet.fetchRequest(session.getString("wallet_launch.request_uri"));
                TestWallet.respond(request, Map.of("vp_token", Map.of("mdl", List.of(mdl(request, (String)
                        request.get("nonce"))))));
                given().auth()
                        .oauth2(TestWallet.fullToken("portal-a"))
                        .get("/v1/verification-sessions/" + session.getString("id"))
                        .then()
                        .body("status", org.hamcrest.Matchers.equalTo(idx == 0 ? "rejected" : "verified"))
                        .body(
                                "reason",
                                idx == 0
                                        ? org.hamcrest.Matchers.equalTo("credential_revoked")
                                        : org.hamcrest.Matchers.nullValue());
            }
        } finally {
            TestEnvironment.mdocIssuer.status = null;
        }
    }

    @Test
    void anMdocIssuerIsNamedByItsAnchorNotItsDocumentSigner() throws Exception {
        // The policy lists the document signer's name, which any anchor could put in a certificate it issues.
        JsonPath session = create("portal-a", "cross_device", "mdl-age-signer-name");
        Map<String, Object> request = TestWallet.fetchRequest(session.getString("wallet_launch.request_uri"));
        TestWallet.respond(request, Map.of("vp_token", Map.of("mdl", List.of(mdl(request, (String)
                request.get("nonce"))))));
        given().auth()
                .oauth2(TestWallet.fullToken("portal-a"))
                .get("/v1/verification-sessions/" + session.getString("id"))
                .then()
                .body("status", org.hamcrest.Matchers.equalTo("rejected"))
                .body("reason", org.hamcrest.Matchers.equalTo("issuer_not_allowed"));
    }

    @Test
    void anMdocSignedForAnotherRequestIsRejected() throws Exception {
        JsonPath session = create("portal-a", "cross_device", "mdl-age");
        Map<String, Object> request = TestWallet.fetchRequest(session.getString("wallet_launch.request_uri"));
        TestWallet.respond(request, Map.of("vp_token", Map.of("mdl", List.of(mdl(request, "another-nonce")))));
        given().auth()
                .oauth2(TestWallet.fullToken("portal-a"))
                .get("/v1/verification-sessions/" + session.getString("id"))
                .then()
                .body("status", org.hamcrest.Matchers.equalTo("rejected"))
                .body("reason", org.hamcrest.Matchers.equalTo("holder_binding_invalid"));
    }

    @Test
    void anOlderAgeAttestationAnswersTheRequestedOne() throws Exception {
        JsonPath session = create("portal-a", "cross_device", "mdl-age");
        Map<String, Object> request = TestWallet.fetchRequest(session.getString("wallet_launch.request_uri"));
        TestWallet.respond(
                request,
                Map.of(
                        "vp_token",
                        Map.of(
                                "mdl",
                                List.of(mdl(
                                        request,
                                        (String) request.get("nonce"),
                                        Map.of("age_over_21", CborEncoder.bool(true)))))));
        given().auth()
                .oauth2(TestWallet.fullToken("portal-a"))
                .get("/v1/verification-sessions/" + session.getString("id") + "/result")
                .then()
                .body("status", org.hamcrest.Matchers.equalTo("verified"))
                .body("claims", org.hamcrest.Matchers.equalTo(Map.of("age_over_18", true)));
    }

    /** A device-signed DeviceResponse holding an mDL, its session transcript built for {@code nonce}. */
    @SuppressWarnings("unchecked")
    private static String mdl(Map<String, Object> request, String nonce) throws Exception {
        return mdl(request, nonce, Map.of("age_over_18", CborEncoder.bool(true)));
    }

    @SuppressWarnings("unchecked")
    private static String mdl(Map<String, Object> request, String nonce, Map<String, CborItem> elements)
            throws Exception {
        Map<String, Object> jwk = ((List<Map<String, Object>>)
                        ((Map<String, Object>) ((Map<String, Object>) request.get("client_metadata")).get("jwks"))
                                .get("keys"))
                .get(0);
        CborItem transcript = SessionTranscripts.openId4VpRedirect(
                (String) request.get("client_id"),
                nonce,
                Optional.of(com.nimbusds
                        .jose
                        .jwk
                        .JWK
                        .parse(jwk)
                        .computeThumbprint("SHA-256")
                        .decode()),
                (String) request.get("response_uri"));
        CborItem document = TestEnvironment.mdocIssuer.document(
                TestEnvironment.MDL_DOCTYPE,
                "org.iso.18013.5.1",
                "org.iso.18013.5.1",
                elements,
                Instant.now().minusSeconds(60),
                Instant.now().minusSeconds(60),
                Instant.now().plus(java.time.Duration.ofDays(30)));
        CborItem nameSpaces = CborEncoder.embedded(CborEncoder.map(Map.of()));
        CborItem signature = TestMdocIssuer.deviceSignature(
                TestEnvironment.mdocIssuer.deviceKeys.getPrivate(),
                -7,
                TestMdocIssuer.deviceAuthentication(transcript, TestEnvironment.MDL_DOCTYPE, nameSpaces),
                false);
        document = TestMdocIssuer.withDeviceSigned(
                document, nameSpaces, CborEncoder.map(Map.of(CborEncoder.text("deviceSignature"), signature)));
        Map<CborItem, CborItem> deviceResponse = new java.util.LinkedHashMap<>();
        deviceResponse.put(CborEncoder.text("version"), CborEncoder.text("1.0"));
        deviceResponse.put(CborEncoder.text("documents"), CborEncoder.array(document));
        deviceResponse.put(CborEncoder.text("status"), CborEncoder.integer(0));
        return java.util.Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(CborEncoder.map(deviceResponse).encoded());
    }

    @Test
    void expiredAndCancelledSessionsCannotBeCompleted() {
        JsonPath expiring = create("portal-a", "cross_device");
        Map<String, Object> request = TestWallet.fetchRequest(expiring.getString("wallet_launch.request_uri"));
        Map<String, Object> response = presentAgeOver18(request, 1);
        clock.advance(Duration.ofMinutes(6));
        assertThat(TestWallet.respond(request, response).statusCode()).isEqualTo(400);
        given().auth()
                .oauth2(TestWallet.fullToken("portal-a"))
                .get("/v1/verification-sessions/" + expiring.getString("id"))
                .then()
                .body("status", org.hamcrest.Matchers.equalTo("expired"));
        given().post(java.net
                        .URI
                        .create(expiring.getString("wallet_launch.request_uri"))
                        .getPath())
                .then()
                .statusCode(404);

        clock.set(Instant.now());
        JsonPath cancelled = create("portal-a", "cross_device");
        Map<String, Object> request2 = TestWallet.fetchRequest(cancelled.getString("wallet_launch.request_uri"));
        given().auth()
                .oauth2(TestWallet.fullToken("portal-a"))
                .post("/v1/verification-sessions/" + cancelled.getString("id") + "/cancel")
                .then()
                .statusCode(200)
                .body("status", org.hamcrest.Matchers.equalTo("cancelled"));
        assertThat(TestWallet.respond(request2, presentAgeOver18(request2, 1)).statusCode())
                .isEqualTo(400);
        given().auth()
                .oauth2(TestWallet.fullToken("portal-a"))
                .get("/v1/verification-sessions/" + cancelled.getString("id"))
                .then()
                .body("status", org.hamcrest.Matchers.equalTo("cancelled"));
    }

    @Test
    void idempotencyKeyReturnsTheSameSessionAndRejectsADifferentBody() {
        String key = UUID.randomUUID().toString();
        String token = TestWallet.fullToken("portal-a");
        String first = given().auth()
                .oauth2(token)
                .header("Idempotency-Key", key)
                .contentType(ContentType.JSON)
                .body(Map.of("policy_id", "age-over-18"))
                .post("/v1/verification-sessions")
                .then()
                .statusCode(201)
                .extract()
                .path("id");
        String second = given().auth()
                .oauth2(token)
                .header("Idempotency-Key", key)
                .contentType(ContentType.JSON)
                .body(Map.of("policy_id", "age-over-18"))
                .post("/v1/verification-sessions")
                .then()
                .statusCode(201)
                .extract()
                .path("id");
        assertThat(second).isEqualTo(first);
        given().auth()
                .oauth2(token)
                .header("Idempotency-Key", key)
                .contentType(ContentType.JSON)
                .body(Map.of("policy_id", "age-over-18", "client_reference", "other"))
                .post("/v1/verification-sessions")
                .then()
                .statusCode(422);
    }

    @Test
    void authorizationIsEnforced() {
        given().contentType(ContentType.JSON)
                .body(Map.of("policy_id", "age-over-18"))
                .post("/v1/verification-sessions")
                .then()
                .statusCode(401);
        given().auth()
                .oauth2(TestWallet.token("portal-a", "verification:read"))
                .header("Idempotency-Key", UUID.randomUUID().toString())
                .contentType(ContentType.JSON)
                .body(Map.of("policy_id", "age-over-18"))
                .post("/v1/verification-sessions")
                .then()
                .statusCode(403)
                .body("code", org.hamcrest.Matchers.equalTo("insufficient_scope"));
        given().auth()
                .oauth2(TestWallet.fullToken("other-app-a"))
                .header("Idempotency-Key", UUID.randomUUID().toString())
                .contentType(ContentType.JSON)
                .body(Map.of("policy_id", "age-over-18"))
                .post("/v1/verification-sessions")
                .then()
                .statusCode(403)
                .body("code", org.hamcrest.Matchers.equalTo("policy_not_granted"));
        given().auth()
                .oauth2(TestWallet.fullToken("unknown-client"))
                .get("/v1/verification-sessions/vrs_x")
                .then()
                .statusCode(403);
        // The client id is compared exactly as issued: a quote is not stripped into another client's id.
        given().auth()
                .oauth2(TestWallet.fullToken("portal-a\""))
                .get("/v1/verification-sessions/vrs_x")
                .then()
                .statusCode(403)
                .body("code", org.hamcrest.Matchers.equalTo("unknown_client"));
        // A client id that is not a JSON string is no client id.
        for (Object azp : List.of(42, List.of("portal-a"), Map.of("id", "portal-a"))) {
            given().auth()
                    .oauth2(TestWallet.tokenWith(Map.of("azp", azp)))
                    .get("/v1/verification-sessions/vrs_x")
                    .then()
                    .statusCode(403)
                    .body("code", org.hamcrest.Matchers.equalTo("unknown_client"));
        }
        // Scopes are compared exactly as issued: quotes are not stripped, and a scope that is not a string grants none.
        for (Object scope : List.of("\"verification:read\"", List.of("verification:read"), 1)) {
            given().auth()
                    .oauth2(TestWallet.tokenWith(Map.of("scope", scope)))
                    .get("/v1/verification-sessions/vrs_x")
                    .then()
                    .statusCode(403)
                    .body("code", org.hamcrest.Matchers.equalTo("insufficient_scope"));
        }
        given().auth()
                .oauth2(TestWallet.tokenWith(Map.of("scope", "verification:read")))
                .get("/v1/verification-sessions/vrs_x")
                .then()
                .statusCode(404);
        given().auth()
                .oauth2("not.a.token")
                .get("/v1/verification-sessions/vrs_x")
                .then()
                .statusCode(401);
        assertThat(readLog()).doesNotContain("not.a.token");
        String[] scopes = TestWallet.ALL_SCOPES.split(" ");
        for (String badToken : List.of(
                TestWallet.token(TestEnvironment.TOKEN_ISSUER, "some-other-api", 300, "portal-a", scopes),
                TestWallet.token("https://other-issuer.example", TestEnvironment.AUDIENCE, 300, "portal-a", scopes),
                TestWallet.token(TestEnvironment.TOKEN_ISSUER, TestEnvironment.AUDIENCE, -120, "portal-a", scopes))) {
            given().auth()
                    .oauth2(badToken)
                    .get("/v1/verification-sessions/vrs_x")
                    .then()
                    .statusCode(401);
        }
    }

    @Test
    void aReloadKeepsOpenSessionsOnTheirOwnRulesAndRefusesABrokenFile() throws Exception {
        java.nio.file.Path file = TestEnvironment.DIR.resolve("tenants.json");
        String original = java.nio.file.Files.readString(file);
        String before = runtime.config().revision();
        try {
            JsonPath open = create("portal-a", "cross_device");
            Map<String, Object> request = TestWallet.fetchRequest(open.getString("wallet_launch.request_uri"));

            // A new client is added while the session is open.
            java.nio.file.Files.writeString(
                    file,
                    original.replace(
                            "{\"client_id\":\"other-app-a\",\"policies\":[]}",
                            "{\"client_id\":\"other-app-a\",\"policies\":[]},"
                                    + "{\"client_id\":\"added-a\",\"policies\":[\"age-over-18\"]}"));
            assertThat(runtime.reloadIfChanged()).isTrue();
            assertThat(runtime.config().revision()).isNotEqualTo(before);
            assertThat(create("added-a", "cross_device").getString("status")).isEqualTo("pending");

            // The session that started before the reload completes under the configuration it started with.
            assertThat(TestWallet.respond(request, presentAgeOver18(request, 1)).statusCode())
                    .isEqualTo(200);
            given().auth()
                    .oauth2(TestWallet.fullToken("portal-a"))
                    .get("/v1/verification-sessions/" + open.getString("id"))
                    .then()
                    .body("status", org.hamcrest.Matchers.equalTo("verified"));

            // A file that does not validate is ignored and the running configuration stays.
            String active = runtime.config().revision();
            java.nio.file.Files.writeString(file, original.replace("\"tenant-a\"", "\"Tenant A!\""));
            assertThat(runtime.reloadIfChanged()).isFalse();
            assertThat(runtime.config().revision()).isEqualTo(active);
            assertThat(create("added-a", "cross_device").getString("status")).isEqualTo("pending");
        } finally {
            java.nio.file.Files.writeString(file, original);
            runtime.reloadIfChanged();
            runtime.reconfigureForTests(clock, (uri, accept, max) -> new byte[0]);
            setUp();
        }
        assertThat(runtime.config().revision()).isEqualTo(before);
    }

    @Test
    void aResultSurvivesAFailedAuditWrite() throws Exception {
        JsonPath session = create("portal-a", "cross_device");
        String id = session.getString("id");
        Map<String, Object> request = TestWallet.fetchRequest(session.getString("wallet_launch.request_uri"));
        assertThat(TestWallet.respond(request, presentAgeOver18(request, 1)).statusCode())
                .isEqualTo(200);
        String token = TestWallet.fullToken("portal-a");
        try (Connection c = dataSource.getConnection();
                Statement s = c.createStatement()) {
            s.execute("CREATE FUNCTION refuse_audit() RETURNS trigger LANGUAGE plpgsql AS"
                    + " $$ BEGIN RAISE EXCEPTION 'audit store unavailable'; END $$");
            s.execute("CREATE TRIGGER refuse_audit BEFORE INSERT ON audit_event FOR EACH ROW"
                    + " WHEN (NEW.action = 'result_retrieved') EXECUTE FUNCTION refuse_audit()");
        }
        try {
            assertThat(given().auth()
                            .oauth2(token)
                            .get("/v1/verification-sessions/" + id + "/result")
                            .statusCode())
                    .isGreaterThanOrEqualTo(500);
        } finally {
            try (Connection c = dataSource.getConnection();
                    Statement s = c.createStatement()) {
                s.execute("DROP TRIGGER refuse_audit ON audit_event");
                s.execute("DROP FUNCTION refuse_audit()");
            }
        }
        // Nothing was consumed: the result is still there, once.
        given().auth()
                .oauth2(token)
                .get("/v1/verification-sessions/" + id + "/result")
                .then()
                .statusCode(200)
                .body("claims.age_over_18", org.hamcrest.Matchers.equalTo(true));
        given().auth()
                .oauth2(token)
                .get("/v1/verification-sessions/" + id + "/result")
                .then()
                .statusCode(404);
        assertThat(auditCount(id, "ok")).isGreaterThanOrEqualTo(2); // created and retrieved
    }

    @Test
    void aResponseToAFinishedSessionIsRefusedBeforeVerification() throws Exception {
        JsonPath session = create("portal-a", "cross_device");
        String requestUri = session.getString("wallet_launch.request_uri");
        Map<String, Object> first = TestWallet.fetchRequest(requestUri);
        Map<String, Object> second = TestWallet.fetchRequest(requestUri);
        Map<String, Object> late = presentAgeOver18(second, 1);
        assertThat(TestWallet.respond(first, presentAgeOver18(first, 1)).statusCode())
                .isEqualTo(200);
        long verifications = verificationCount();
        // The second request instance is unused, but the session is finished: no decryption, no verification.
        assertThat(TestWallet.respond(second, late).statusCode()).isEqualTo(400);
        assertThat(verificationCount()).isEqualTo(verifications);
        assertThat(auditCount(session.getString("id"), "ignored")).isEqualTo(1);
        // Repeating it, which needs no authentication, is counted but writes no further audit rows.
        for (int i = 0; i < 3; i++) {
            assertThat(TestWallet.respond(second, late).statusCode()).isEqualTo(400);
        }
        assertThat(auditCount(session.getString("id"), "ignored")).isEqualTo(1);
        assertThat(verificationCount()).isEqualTo(verifications);
    }

    private long verificationCount() {
        return registry.find("eudiw.presentation.verification").timers().stream()
                .mapToLong(io.micrometer.core.instrument.Timer::count)
                .sum();
    }

    @Test
    void walletEndpointsAreRateLimitedPerSourceAddress() {
        clock.set(Instant.parse("2031-06-06T10:00:30Z"));
        engine.limitWalletRequestsForTests(3);
        try {
            String unknown = "/oid4vp/requests/" + "A".repeat(43);
            for (int i = 0; i < 3; i++) {
                given().get(unknown).then().statusCode(404);
            }
            Response limited = given().get(unknown);
            assertThat(limited.statusCode()).isEqualTo(429);
            assertThat(limited.header("Retry-After")).isEqualTo("30");
            given().contentType(ContentType.URLENC)
                    .formParam("response", "x")
                    .post("/oid4vp/responses")
                    .then()
                    .statusCode(429);
            // The next minute starts a new window.
            clock.set(Instant.parse("2031-06-06T10:01:00Z"));
            given().get(unknown).then().statusCode(404);
            // No address, or a forwarded value that is not one, is never a free pass and never a fresh key.
            clock.set(Instant.parse("2031-06-06T10:02:00Z"));
            assertThat(engine.walletRequestRefused(null)).isEmpty();
            assertThat(engine.walletRequestRefused("unknown")).isEmpty();
            assertThat(engine.walletRequestRefused("_hidden-1")).isEmpty();
            assertThat(engine.walletRequestRefused("_hidden-2")).isPresent();
        } finally {
            engine.limitWalletRequestsForTests(0);
            clock.set(Instant.now());
        }
    }

    @Test
    void aRewrittenKeyFileIsReloadedWithoutTouchingTheTenantsFile() throws Exception {
        java.nio.file.Path key = TestEnvironment.DIR.resolve("rp-a-key.pem");
        String original = java.nio.file.Files.readString(key);
        String before = runtime.config().revision();
        try {
            java.nio.file.Files.writeString(key, original + "\n");
            assertThat(runtime.reloadIfChanged()).isTrue();
            assertThat(runtime.config().revision()).isNotEqualTo(before).hasSize(64);
            assertThat(runtime.reloadIfChanged()).isFalse();
        } finally {
            java.nio.file.Files.writeString(key, original);
            runtime.reloadIfChanged();
            runtime.reconfigureForTests(clock, (uri, accept, max) -> new byte[0]);
            setUp();
        }
        assertThat(runtime.config().revision()).isEqualTo(before);
    }

    @Test
    void sessionCreationIsRateLimitedPerClientAcrossNodes() {
        // The window lives in PostgreSQL, so every node counts against the same limit.
        clock.set(Instant.parse("2031-05-05T10:00:10Z"));
        for (int i = 0; i < 2; i++) {
            assertThat(create("limited-a", "cross_device").getString("status")).isEqualTo("pending");
        }
        Response limited = given().auth()
                .oauth2(TestWallet.fullToken("limited-a"))
                .header("Idempotency-Key", UUID.randomUUID().toString())
                .contentType(ContentType.JSON)
                .body(Map.of("policy_id", "age-over-18"))
                .post("/v1/verification-sessions");
        assertThat(limited.statusCode()).isEqualTo(429);
        assertThat(limited.jsonPath().getString("code")).isEqualTo("rate_limited");
        assertThat(limited.header("Retry-After")).isEqualTo("50");

        // Other clients are not affected, and the next minute starts a new window.
        assertThat(create("portal-a", "cross_device").getString("status")).isEqualTo("pending");
        clock.set(Instant.parse("2031-05-05T10:01:00Z"));
        assertThat(create("limited-a", "cross_device").getString("status")).isEqualTo("pending");
    }

    @Test
    void metricsHealthAndAuditStayOnTheManagementPortAndCarryNoSecrets() {
        JsonPath session = create("portal-a", "cross_device");
        String id = session.getString("id");
        String requestUri = session.getString("wallet_launch.request_uri");
        String handle = requestUri.substring(requestUri.lastIndexOf('/') + 1);
        Map<String, Object> request = TestWallet.fetchRequest(requestUri);
        assertThat(TestWallet.respond(request, presentAgeOver18(request, 1)).statusCode())
                .isEqualTo(200);
        String token = TestWallet.fullToken("portal-a");
        given().auth()
                .oauth2(token)
                .get("/v1/verification-sessions/" + id + "/result")
                .then()
                .statusCode(200);

        int management = Integer.getInteger("quarkus.management.test-port", 9001);
        String metrics = given().port(management)
                .get("/metrics")
                .then()
                .statusCode(200)
                .extract()
                .asString();
        assertThat(metrics)
                .contains("eudiw_events_total{action=\"session_created\"")
                .contains("action=\"result_retrieved\"")
                .contains("eudiw_presentation_verification_seconds_count{outcome=\"verified\",policy=\"age-over-18\"")
                .contains("eudiw_registration_certificate_expiry_seconds{policy=\"age-over-18\",tenant=\"tenant-a\"}")
                .contains("eudiw_config_info{revision=")
                .contains("eudiw_trusted_lists_current{policy=\"age-over-18-listed\",tenant=\"tenant-b\"}")
                .doesNotContain(id)
                .doesNotContain(handle)
                .doesNotContain((String) request.get("nonce"))
                .doesNotContain(token)
                .doesNotContain("Erika-Canary");

        given().port(management)
                .get("/health/well")
                .then()
                .statusCode(200)
                .body(
                        "checks.find { it.name == 'registration-certificates' }.status",
                        org.hamcrest.Matchers.equalTo("UP"));

        // Nothing operational on the public port.
        for (String path : List.of("/metrics", "/q/metrics", "/health", "/q/health", "/health/well")) {
            assertThat(given().get(path).statusCode()).as(path).isEqualTo(404);
        }

        String log = readLog();
        assertThat(log)
                .contains(
                        "action=session_created outcome=ok code=none tenant=tenant-a client=portal-a policy=age-over-18 session="
                                + id)
                .contains("action=result_retrieved outcome=ok")
                .doesNotContain(handle);
    }

    private static String readLog() {
        try {
            // The log file rotates; read every generation.
            StringBuilder all = new StringBuilder();
            try (var files = java.nio.file.Files.list(java.nio.file.Path.of("target"))) {
                for (java.nio.file.Path file : files.filter(
                                f -> f.getFileName().toString().startsWith("test-service.log"))
                        .toList()) {
                    all.append(java.nio.file.Files.readString(file, StandardCharsets.ISO_8859_1));
                }
            }
            return all.toString();
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private String databaseText() throws Exception {
        StringBuilder sb = new StringBuilder();
        try (Connection c = dataSource.getConnection();
                Statement s = c.createStatement()) {
            for (String table : List.of(
                    "verification_session",
                    "request_instance",
                    "audit_event",
                    "webhook_delivery",
                    "trusted_list_sequence")) {
                try (ResultSet rs = s.executeQuery("SELECT * FROM " + table)) {
                    int columns = rs.getMetaData().getColumnCount();
                    while (rs.next()) {
                        for (int i = 1; i <= columns; i++) {
                            Object value = rs.getObject(i);
                            if (value instanceof byte[] bytes) {
                                sb.append(new String(bytes, StandardCharsets.ISO_8859_1));
                            } else {
                                sb.append(value);
                            }
                            sb.append('|');
                        }
                    }
                }
            }
        }
        return sb.toString();
    }

    private List<String> auditCodes(String sessionId, String action) throws Exception {
        try (Connection c = dataSource.getConnection();
                var ps = c.prepareStatement(
                        "SELECT code FROM audit_event WHERE session_id = ? AND action = ? ORDER BY code")) {
            ps.setString(1, sessionId);
            ps.setString(2, action);
            List<String> codes = new java.util.ArrayList<>();
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    codes.add(rs.getString(1));
                }
            }
            return codes;
        }
    }

    private int auditCount(String sessionId, String outcome) throws Exception {
        try (Connection c = dataSource.getConnection();
                var ps = c.prepareStatement("SELECT count(*) FROM audit_event WHERE session_id = ? AND outcome = ?")) {
            ps.setString(1, sessionId);
            ps.setString(2, outcome);
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getInt(1);
            }
        }
    }

    public static final class MutableClock extends Clock {
        private volatile Instant now;

        MutableClock(Instant now) {
            this.now = now;
        }

        void advance(Duration d) {
            now = now.plus(d);
        }

        void set(Instant instant) {
            now = instant;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
