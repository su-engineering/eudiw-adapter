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
import io.github.suengineering.eudiw.service.api.SessionEventStreams;
import io.github.suengineering.eudiw.service.engine.AdapterRuntime;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.path.json.JsonPath;
import jakarta.inject.Inject;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Server-Sent Events of session status (ADR-013): status only, across nodes, scoped, capped and closed when final. */
@QuarkusTest
@QuarkusTestResource(TestEnvironment.class)
class SessionEventsTest {

    private static final String END = "<end of stream>";

    @Inject
    AdapterRuntime runtime;

    @Inject
    AgroalDataSource dataSource;

    @Inject
    SessionEventStreams streams;

    private final TestWallet wallet = new TestWallet();
    private final List<HttpResponse<Stream<String>>> opened = new ArrayList<>();

    @BeforeEach
    void setUp() {
        runtime.reconfigureForTests(
                Clock.systemUTC(),
                (uri, accept, max) -> TestWallet.statusListToken(
                                TestEnvironment.ISSUER_A, "issuer-a-key.pem", "issuer-a.pem")
                        .getBytes(StandardCharsets.US_ASCII));
        streams.limitForTests(1000, 100);
    }

    @AfterEach
    void closeStreams() {
        opened.forEach(r -> r.body().close());
    }

    private JsonPath create(String policyId) {
        return given().auth()
                .oauth2(TestWallet.fullToken("portal-a"))
                .header("Idempotency-Key", UUID.randomUUID().toString())
                .contentType(ContentType.JSON)
                .body(Map.of("policy_id", policyId, "mode", "cross_device"))
                .post("/v1/verification-sessions")
                .then()
                .statusCode(201)
                .extract()
                .jsonPath();
    }

    /** Opens the stream and returns the data lines of its events, then {@link #END} when the server closes it. */
    private BlockingQueue<String> open(String token, String id) throws Exception {
        HttpResponse<Stream<String>> response = HttpClient.newHttpClient()
                .send(
                        HttpRequest.newBuilder(URI.create("http://localhost:" + RestAssured.port
                                        + "/v1/verification-sessions/" + id + "/events"))
                                .header("Authorization", "Bearer " + token)
                                .header("Accept", "text/event-stream")
                                .build(),
                        HttpResponse.BodyHandlers.ofLines());
        opened.add(response);
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.headers().firstValue("Content-Type"))
                .hasValueSatisfying(v -> assertThat(v).startsWith("text/event-stream"));
        BlockingQueue<String> events = new LinkedBlockingQueue<>();
        Thread.ofVirtual().start(() -> {
            try {
                response.body()
                        .filter(l -> l.startsWith("data:"))
                        .forEach(l -> events.add(l.substring(5).strip()));
            } catch (RuntimeException e) {
                // closed by the test
            }
            events.add(END);
        });
        return events;
    }

    private static JsonPath next(BlockingQueue<String> events) throws InterruptedException {
        String data = events.poll(10, TimeUnit.SECONDS);
        assertThat(data).as("an event within 10 seconds").isNotNull().isNotEqualTo(END);
        return new JsonPath(data);
    }

    private static void assertClosed(BlockingQueue<String> events) throws InterruptedException {
        assertThat(events.poll(10, TimeUnit.SECONDS)).isEqualTo(END);
    }

    private void sql(String statement, String id) throws Exception {
        try (Connection c = dataSource.getConnection();
                PreparedStatement ps = c.prepareStatement(statement)) {
            ps.setString(1, id);
            assertThat(ps.executeUpdate()).isEqualTo(1);
        }
    }

    @Test
    void sendsPendingThenTheVerifiedStatusWithoutClaimsAndCloses() throws Exception {
        JsonPath session = create("age-over-18");
        String id = session.getString("id");
        assertThat(session.getString("events_url")).isEqualTo("/v1/verification-sessions/" + id + "/events");
        BlockingQueue<String> events = open(TestWallet.fullToken("portal-a"), id);
        JsonPath first = next(events);
        assertThat(first.getString("status")).isEqualTo("pending");
        assertThat(first.getString("id")).isEqualTo(id);

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
                                Map.of("age_over_18", true, "given_name", "Erika-Canary"),
                                1))));
        assertThat(TestWallet.respond(request, response).statusCode()).isEqualTo(200);

        String raw = events.poll(10, TimeUnit.SECONDS);
        assertThat(raw).isNotNull().doesNotContain("Erika-Canary").doesNotContain("age_over_18");
        JsonPath verified = new JsonPath(raw);
        assertThat(verified.getString("status")).isEqualTo("verified");
        assertThat(verified.getBoolean("result_available")).isTrue();
        assertThat(verified.getMap("$"))
                .containsOnlyKeys(
                        "id",
                        "status",
                        "policy_id",
                        "mode",
                        "created_at",
                        "expires_at",
                        "completed_at",
                        "result_available");
        assertClosed(events);
    }

    @Test
    void aChangeWrittenByAnotherNodeArrives() throws Exception {
        String id = create("age-over-18").getString("id");
        BlockingQueue<String> events = open(TestWallet.fullToken("portal-a"), id);
        assertThat(next(events).getString("status")).isEqualTo("pending");
        // Another replica completing the session only writes the row.
        sql(
                "UPDATE verification_session SET status = 'rejected', failure_code = 'invalid_signature',"
                        + " completed_at = now() WHERE id = ?",
                id);
        JsonPath rejected = next(events);
        assertThat(rejected.getString("status")).isEqualTo("rejected");
        assertThat(rejected.getString("reason")).isEqualTo("invalid_signature");
        assertClosed(events);
    }

    @Test
    void expiryIsSentAtExpiresAtAndCloses() throws Exception {
        String id = create("age-over-18").getString("id");
        BlockingQueue<String> events = open(TestWallet.fullToken("portal-a"), id);
        assertThat(next(events).getString("status")).isEqualTo("pending");
        // Past expires_at, before the sweeper has marked the row.
        sql("UPDATE verification_session SET expires_at = now() - interval '1 second' WHERE id = ?", id);
        assertThat(next(events).getString("status")).isEqualTo("expired");
        assertClosed(events);
    }

    @Test
    void theStreamEndsWhenTheAccessTokenExpires() throws Exception {
        String id = create("age-over-18").getString("id");
        String shortLived = TestWallet.token(
                TestEnvironment.TOKEN_ISSUER, TestEnvironment.AUDIENCE, 3, "portal-a", "verification:read");
        BlockingQueue<String> events = open(shortLived, id);
        assertThat(next(events).getString("status")).isEqualTo("pending");
        assertClosed(events);
    }

    @Test
    void aFinalSessionSendsOneEventAndCloses() throws Exception {
        String id = create("age-over-18").getString("id");
        given().auth()
                .oauth2(TestWallet.fullToken("portal-a"))
                .post("/v1/verification-sessions/" + id + "/cancel")
                .then()
                .statusCode(200);
        BlockingQueue<String> events = open(TestWallet.fullToken("portal-a"), id);
        assertThat(next(events).getString("status")).isEqualTo("cancelled");
        assertClosed(events);
    }

    @Test
    void otherClientsAndTenantsGetNotFound() {
        String id = create("age-over-18").getString("id");
        for (String client : List.of("other-app-a", "portal-b")) {
            given().auth()
                    .oauth2(TestWallet.fullToken(client))
                    .accept("text/event-stream")
                    .get("/v1/verification-sessions/" + id + "/events")
                    .then()
                    .statusCode(404);
        }
    }

    @Test
    void readScopeIsRequired() {
        String id = create("age-over-18").getString("id");
        given().auth()
                .oauth2(TestWallet.token("portal-a", "verification:create", "verification:result"))
                .accept("text/event-stream")
                .get("/v1/verification-sessions/" + id + "/events")
                .then()
                .statusCode(403);
    }

    @Test
    void streamsPerClientAreCapped() throws Exception {
        streams.limitForTests(1000, 1);
        String id = create("age-over-18").getString("id");
        BlockingQueue<String> events = open(TestWallet.fullToken("portal-a"), id);
        assertThat(next(events).getString("status")).isEqualTo("pending");
        given().auth()
                .oauth2(TestWallet.fullToken("portal-a"))
                .accept("text/event-stream")
                .get("/v1/verification-sessions/" + id + "/events")
                .then()
                .statusCode(429)
                .header("Retry-After", "5")
                .body("code", org.hamcrest.Matchers.equalTo("too_many_streams"));
        // Another client is not affected by portal-a's streams.
        String other = given().auth()
                .oauth2(TestWallet.fullToken("portal-b"))
                .header("Idempotency-Key", UUID.randomUUID().toString())
                .contentType(ContentType.JSON)
                .body(Map.of("policy_id", "age-over-18", "mode", "cross_device"))
                .post("/v1/verification-sessions")
                .then()
                .statusCode(201)
                .extract()
                .path("id");
        assertThat(next(open(TestWallet.fullToken("portal-b"), other)).getString("status"))
                .isEqualTo("pending");
    }
}
