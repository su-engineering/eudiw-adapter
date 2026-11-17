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

import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.context.Context;
import io.opentelemetry.context.propagation.TextMapGetter;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * With tracing off, as it is by default, inbound trace headers still pass through the configured propagators. They
 * must be the bounded ones, so a crafted {@code tracestate} is not parsed (GHSA-ccrj-gw8r-854m).
 */
@QuarkusTest
@QuarkusTestResource(TestEnvironment.class)
class TraceContextTest {

    private static final String TRACEPARENT = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    @Inject
    OpenTelemetry openTelemetry;

    @Test
    void theDisabledSdkStillUsesTheBoundedPropagator() {
        var propagator = openTelemetry.getPropagators().getTextMapPropagator();
        assertThat(propagator.toString()).contains("BoundedTraceContextPropagator");

        String hostile = "a=b" + " ".repeat(16_000) + "x";
        TextMapGetter<Map<String, String>> getter = new TextMapGetter<>() {
            @Override
            public Iterable<String> keys(Map<String, String> carrier) {
                return carrier.keySet();
            }

            @Override
            public String get(Map<String, String> carrier, String key) {
                return carrier.get(key);
            }
        };
        long started = System.nanoTime();
        Context context =
                propagator.extract(Context.root(), Map.of("traceparent", TRACEPARENT, "tracestate", hostile), getter);
        assertThat((System.nanoTime() - started) / 1_000_000).isLessThan(50);
        assertThat(Span.fromContext(context).getSpanContext().getTraceId())
                .isEqualTo("4bf92f3577b34da6a3ce929d0e0e4736");
        assertThat(Span.fromContext(context).getSpanContext().getTraceState().isEmpty())
                .isTrue();
    }

    @Test
    void aRequestWithAHostileTracestateIsServedNormally() {
        String hostile = "a=b" + " ".repeat(16_000) + "x";
        given().header("traceparent", TRACEPARENT)
                .header("tracestate", hostile)
                .get("/oid4vp/requests/unknown-handle")
                .then()
                .statusCode(404);
    }
}
