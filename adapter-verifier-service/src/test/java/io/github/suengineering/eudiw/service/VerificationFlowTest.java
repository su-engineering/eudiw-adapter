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

    private final TestWallet wallet = new TestWallet();
    private final MutableClock clock = new MutableClock(Instant.now());

    @BeforeEach
    void setUp() {
        HttpFetcher fetcher = (uri, accept, max) -> {
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
