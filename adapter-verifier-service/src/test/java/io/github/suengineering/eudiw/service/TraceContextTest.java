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

import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

/**
 * With tracing off, as it is by default, the HTTP server must not hand trace headers to the propagator, so a crafted
 * {@code tracestate} is never parsed (GHSA-ccrj-gw8r-854m).
 */
@QuarkusTest
@QuarkusTestResource(TestEnvironment.class)
class TraceContextTest {

    @Test
    void aHostileTracestateIsNotParsedWithTracingOff() {
        String hostile = "a=b" + " ".repeat(18_000) + "x";
        String traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        given().get("/oid4vp/requests/" + "B".repeat(43)).then().statusCode(404); // warm up
        long started = System.nanoTime();
        for (int i = 0; i < 3; i++) {
            given().header("traceparent", traceparent)
                    .header("tracestate", hostile)
                    .get("/oid4vp/requests/" + "B".repeat(43))
                    .then()
                    .statusCode(404);
        }
        // Parsed by opentelemetry-api 1.62.0, each of these costs well over a second of CPU.
        assertThat((System.nanoTime() - started) / 1_000_000).isLessThan(1500);
    }
}
