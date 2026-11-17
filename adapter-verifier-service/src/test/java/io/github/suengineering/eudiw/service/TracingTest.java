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

import io.opentelemetry.sdk.testing.exporter.InMemorySpanExporter;
import io.opentelemetry.sdk.trace.data.SpanData;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.http.ContentType;
import io.restassured.path.json.JsonPath;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/** With tracing on, spans name routes but never carry a request handle or a query string. */
@QuarkusTest
@TestProfile(TracingTest.TracingProfile.class)
@QuarkusTestResource(TestEnvironment.class)
class TracingTest {

    public static class TracingProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of("quarkus.otel.sdk.disabled", "false", "quarkus.otel.bsp.schedule.delay", "50ms");
        }
    }

    @Singleton
    public static class ExporterProducer {
        @Produces
        @Singleton
        InMemorySpanExporter exporter() {
            return InMemorySpanExporter.create();
        }
    }

    @Inject
    InMemorySpanExporter exporter;

    @Test
    void spansCarryNeitherTheRequestHandleNorTheQuery() {
        exporter.reset();
        JsonPath session = given().auth()
                .oauth2(TestWallet.fullToken("portal-a"))
                .header("Idempotency-Key", UUID.randomUUID().toString())
                .contentType(ContentType.JSON)
                .body(Map.of("policy_id", "age-over-18", "mode", "cross_device"))
                .post("/v1/verification-sessions")
                .then()
                .statusCode(201)
                .extract()
                .jsonPath();
        String requestUri = session.getString("wallet_launch.request_uri");
        String handle = requestUri.substring(requestUri.lastIndexOf('/') + 1);
        TestWallet.fetchRequest(requestUri);
        given().auth()
                .oauth2(TestWallet.fullToken("portal-a"))
                .get("/v1/verification-sessions/" + session.getString("id") + "/result?response_code=secret-code-123")
                .then()
                .statusCode(404);

        long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
        while (exporter.getFinishedSpanItems().size() < 3 && System.nanoTime() < deadline) {
            Thread.onSpinWait();
        }
        List<SpanData> spans = exporter.getFinishedSpanItems();
        String dump = spans.toString();
        assertThat(dump).contains("/oid4vp/requests/{handle}").contains("redacted");
        assertThat(dump).doesNotContain(handle).doesNotContain("secret-code-123");
    }
}
