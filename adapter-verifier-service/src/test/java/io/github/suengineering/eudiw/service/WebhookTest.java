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

import io.github.suengineering.eudiw.core.net.HttpFetcher;
import io.github.suengineering.eudiw.service.engine.AdapterRuntime;
import io.github.suengineering.eudiw.service.engine.WebhookDispatcher;
import io.github.suengineering.eudiw.service.store.SessionStore;
import io.github.suengineering.eudiw.service.store.WebhookOutbox;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import io.restassured.path.json.JsonPath;
import jakarta.inject.Inject;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

@QuarkusTest
@QuarkusTestResource(TestEnvironment.class)
class WebhookTest {

    @Inject
    AdapterRuntime runtime;

    @Inject
    WebhookDispatcher dispatcher;

    @Inject
    WebhookOutbox outbox;

    @Inject
    SessionStore store;

    private final TestWallet wallet = new TestWallet();
    private final VerificationFlowTest.MutableClock clock = new VerificationFlowTest.MutableClock(Instant.now());

    @BeforeEach
    void setUp() {
        HttpFetcher fetcher = (uri, accept, max) -> TestWallet.statusListToken(
                        TestEnvironment.ISSUER_A, "issuer-a-key.pem", "issuer-a.pem")
                .getBytes(StandardCharsets.US_ASCII);
        runtime.reconfigureForTests(clock, fetcher);
        dispatcher.dispatch(); // drain deliveries queued by other test classes
        TestEnvironment.WEBHOOK_CALLS.clear();
        TestEnvironment.WEBHOOK_STATUSES.clear();
    }

    private JsonPath create() {
        return given().auth()
                .oauth2(TestWallet.fullToken("portal-a"))
                .header("Idempotency-Key", UUID.randomUUID().toString())
                .contentType(ContentType.JSON)
                .body(Map.of("policy_id", "age-over-18", "mode", "cross_device", "client_reference", "order-42"))
                .post("/v1/verification-sessions")
                .then()
                .statusCode(201)
                .extract()
                .jsonPath();
    }

    private String verify() {
        JsonPath session = create();
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
                                Map.of("age_over_18", true, "given_name", "Erika-Webhook-Canary"),
                                1))));
        assertThat(TestWallet.respond(request, response).statusCode()).isEqualTo(200);
        return session.getString("id");
    }

    @Test
    void aVerifiedSessionSendsOneSignedNotificationWithoutClaims() throws Exception {
        String id = verify();
        dispatcher.dispatch();

        assertThat(TestEnvironment.WEBHOOK_CALLS).hasSize(1);
        TestEnvironment.WebhookCall call = TestEnvironment.WEBHOOK_CALLS.get(0);
        String webhookId = call.headers().get("webhook-id");
        String timestamp = call.headers().get("webhook-timestamp");
        assertThat(webhookId).startsWith("msg_").doesNotContain(".");
        assertThat(Long.parseLong(timestamp)).isEqualTo(clock.instant().getEpochSecond());

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(TestEnvironment.WEBHOOK_SECRET, "HmacSHA256"));
        String expected = "v1,"
                + Base64.getEncoder()
                        .encodeToString(mac.doFinal(
                                (webhookId + "." + timestamp + "." + call.body()).getBytes(StandardCharsets.UTF_8)));
        assertThat(call.headers().get("webhook-signature")).isEqualTo(expected);

        JsonPath body = new JsonPath(call.body());
        assertThat(body.getString("type")).isEqualTo("verification_session.verified");
        assertThat(body.getString("data.id")).isEqualTo(id);
        assertThat(body.getString("data.status")).isEqualTo("verified");
        assertThat(body.getString("data.client_reference")).isEqualTo("order-42");
        assertThat(call.body()).doesNotContain("Erika-Webhook-Canary").doesNotContain("age_over_18");

        dispatcher.dispatch();
        assertThat(TestEnvironment.WEBHOOK_CALLS).hasSize(1);
        assertThat(outbox.states(id)).containsExactly("delivered");
    }

    @Test
    void aFailedDeliveryIsRetriedWithTheSameId() {
        String id = verify();
        TestEnvironment.WEBHOOK_STATUSES.add(503);
        dispatcher.dispatch();
        assertThat(outbox.states(id)).containsExactly("pending");

        dispatcher.dispatch();
        assertThat(TestEnvironment.WEBHOOK_CALLS).hasSize(1); // not due yet

        clock.advance(Duration.ofSeconds(10));
        dispatcher.dispatch();
        assertThat(TestEnvironment.WEBHOOK_CALLS).hasSize(2);
        assertThat(TestEnvironment.WEBHOOK_CALLS.get(1).headers().get("webhook-id"))
                .isEqualTo(TestEnvironment.WEBHOOK_CALLS.get(0).headers().get("webhook-id"));
        assertThat(outbox.states(id)).containsExactly("delivered");
    }

    @Test
    void twoDispatchersRunningAtOnceSendEachDeliveryOnce() throws Exception {
        List<String> ids = List.of(verify(), verify(), verify());
        TestEnvironment.WEBHOOK_DELAY_MILLIS.set(300);
        try {
            var pool = java.util.concurrent.Executors.newFixedThreadPool(2);
            var first = pool.submit(dispatcher::dispatch);
            var second = pool.submit(dispatcher::dispatch);
            first.get();
            second.get();
            pool.shutdown();
        } finally {
            TestEnvironment.WEBHOOK_DELAY_MILLIS.set(0);
        }
        List<String> sent = TestEnvironment.WEBHOOK_CALLS.stream()
                .map(call -> new JsonPath(call.body()).getString("data.id"))
                .toList();
        assertThat(sent).containsExactlyInAnyOrderElementsOf(ids);
        for (String id : ids) {
            assertThat(outbox.states(id)).containsExactly("delivered");
        }
    }

    @Test
    void goneStopsDelivery() {
        String id = verify();
        TestEnvironment.WEBHOOK_STATUSES.add(410);
        dispatcher.dispatch();
        clock.advance(Duration.ofHours(1));
        dispatcher.dispatch();
        assertThat(TestEnvironment.WEBHOOK_CALLS).hasSize(1);
        assertThat(outbox.states(id)).containsExactly("failed");
    }

    @Test
    void anExpiredSessionIsNotified() {
        String id = create().getString("id");
        clock.advance(Duration.ofMinutes(6));
        store.sweep(clock.instant(), runtime.webhookClients());
        dispatcher.dispatch();

        // Sessions other tests left pending expire in the same sweep; find this one.
        assertThat(TestEnvironment.WEBHOOK_CALLS)
                .map(call -> new JsonPath(call.body()))
                .filteredOn(body -> id.equals(body.getString("data.id")))
                .singleElement()
                .satisfies(body -> assertThat(body.getString("type")).isEqualTo("verification_session.expired"));
        assertThat(outbox.states(id)).containsExactly("delivered");
    }
}
