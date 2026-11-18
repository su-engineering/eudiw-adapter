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
        streams.configureForTests(1000, 100, java.time.Duration.ofSeconds(15));
    }

    @AfterEach
    void awaitStreamsDropped() throws InterruptedException {
        opened.forEach(r -> r.body().close());
        opened.clear();
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (streams.open() > 0 && System.nanoTime() < deadline) {
            Thread.sleep(100);
        }
        assertThat(streams.open())
                .as("every stream is dropped after the client closes it")
                .isZero();
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

    /** Opens the stream and returns its non-empty lines, then {@link #END} when the server closes it. */
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
        assertThat(response.headers().firstValue("Cache-Control")).hasValue("no-store");
        BlockingQueue<String> lines = new LinkedBlockingQueue<>();
        Thread.ofVirtual().start(() -> {
            try {
                response.body().filter(l -> !l.isBlank()).forEach(lines::add);
            } catch (RuntimeException e) {
                // closed by the test
            }
            lines.add(END);
        });
        return lines;
    }

    /** The data of the next event, skipping comments and the event name and id lines. */
    private static JsonPath next(BlockingQueue<String> lines) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (true) {
            String line = lines.poll(deadline - System.nanoTime(), TimeUnit.NANOSECONDS);
            assertThat(line).as("an event within 10 seconds").isNotNull().isNotEqualTo(END);
            if (line.startsWith("data:")) {
                return new JsonPath(line.substring(5).strip());
            }
        }
    }

    private static void assertClosed(BlockingQueue<String> lines) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (true) {
            String line = lines.poll(deadline - System.nanoTime(), TimeUnit.NANOSECONDS);
            assertThat(line).as("the stream closes within 10 seconds").isNotNull();
            assertThat(line).as("no further event").doesNotStartWith("data:");
            if (line.equals(END)) {
                return;
            }
        }
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

        JsonPath verified = next(events);
        assertThat(verified.prettify()).doesNotContain("Erika-Canary").doesNotContain("age_over_18");
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
                TestEnvironment.TOKEN_ISSUER, TestEnvironment.AUDIENCE, 5, "portal-a", "verification:read");
        BlockingQueue<String> events = open(shortLived, id);
        assertThat(next(events).getString("status")).isEqualTo("pending");
        assertClosed(events);
    }

    @Test
    void aQuietStreamGetsHeartbeatCommentsAndStillDeliversTheChange() throws Exception {
        streams.configureForTests(1000, 100, java.time.Duration.ofSeconds(1));
        String id = create("age-over-18").getString("id");
        BlockingQueue<String> lines = open(TestWallet.fullToken("portal-a"), id);
        assertThat(next(lines).getString("status")).isEqualTo("pending");
        List<String> between = new ArrayList<>();
        String line;
        do {
            line = lines.poll(10, TimeUnit.SECONDS);
            assertThat(line).as("a heartbeat within 10 seconds").isNotNull().isNotEqualTo(END);
            between.add(line);
        } while (!line.startsWith(":"));
        assertThat(line).isEqualTo(":keep-alive");
        assertThat(between).noneMatch(l -> l.startsWith("data:"));
        sql("UPDATE verification_session SET status = 'denied', completed_at = now() WHERE id = ?", id);
        assertThat(next(lines).getString("status")).isEqualTo("denied");
        assertClosed(lines);
    }

    @Test
    void aStreamTheClientClosesIsDropped() throws Exception {
        String id = create("age-over-18").getString("id");
        BlockingQueue<String> lines = open(TestWallet.fullToken("portal-a"), id);
        assertThat(next(lines).getString("status")).isEqualTo("pending");
        assertThat(streams.watching(id)).isTrue();
        opened.remove(opened.size() - 1).body().close();
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (streams.watching(id) && System.nanoTime() < deadline) {
            Thread.sleep(200);
        }
        assertThat(streams.watching(id))
                .as("dropped without waiting for a heartbeat")
                .isFalse();
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
        streams.configureForTests(1000, 1, java.time.Duration.ofSeconds(15));
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
