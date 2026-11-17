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
package io.github.suengineering.eudiw.service.engine;

import static org.assertj.core.api.Assertions.assertThat;

import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanContext;
import io.opentelemetry.context.Context;
import io.opentelemetry.context.propagation.TextMapGetter;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class BoundedTraceContextPropagatorTest {

    private static final String TRACEPARENT = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    private static final TextMapGetter<Map<String, String>> GETTER = new TextMapGetter<>() {
        @Override
        public Iterable<String> keys(Map<String, String> carrier) {
            return carrier.keySet();
        }

        @Override
        public String get(Map<String, String> carrier, String key) {
            return carrier.get(key);
        }
    };

    private static SpanContext extract(String tracestate) {
        Map<String, String> headers = new HashMap<>();
        headers.put("traceparent", TRACEPARENT);
        headers.put("tracestate", tracestate);
        return Span.fromContext(new BoundedTraceContextPropagator().extract(Context.root(), headers, GETTER))
                .getSpanContext();
    }

    @Test
    void aTracestateWithinTheLimitIsKept() {
        SpanContext context = extract("vendor=value,other=1");
        assertThat(context.getTraceId()).isEqualTo("4bf92f3577b34da6a3ce929d0e0e4736");
        assertThat(context.getTraceState().get("vendor")).isEqualTo("value");
    }

    @Test
    void anOversizedTracestateIsDroppedAndTheParentKept() {
        SpanContext context = extract("a=b" + " ".repeat(20_000) + "x");
        assertThat(context.isRemote()).isTrue();
        assertThat(context.getSpanId()).isEqualTo("00f067aa0ba902b7");
        assertThat(context.getTraceState().isEmpty()).isTrue();
    }

    @Test
    void aHostileTracestateCostsNothing() {
        String hostile = "a=b" + " ".repeat(20_000) + "x";
        extract(hostile);
        long started = System.nanoTime();
        for (int i = 0; i < 20; i++) {
            extract(hostile);
        }
        // Unbounded, one of these takes over a second (quadratic regex backtracking in opentelemetry-api < 1.67.0).
        assertThat((System.nanoTime() - started) / 1_000_000).isLessThan(200);
    }

    @Test
    void theProviderRegistersUnderItsName() {
        BoundedTraceContextPropagator.Provider provider = new BoundedTraceContextPropagator.Provider();
        assertThat(provider.getName()).isEqualTo("tracecontext-bounded");
        assertThat(java.util.ServiceLoader.load(
                                io.opentelemetry.sdk.autoconfigure.spi.ConfigurablePropagatorProvider.class)
                        .stream()
                        .map(p -> (Object) p.type()))
                .contains(BoundedTraceContextPropagator.Provider.class);
    }
}
