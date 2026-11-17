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

import io.opentelemetry.api.trace.propagation.W3CTraceContextPropagator;
import io.opentelemetry.context.Context;
import io.opentelemetry.context.propagation.TextMapGetter;
import io.opentelemetry.context.propagation.TextMapPropagator;
import io.opentelemetry.context.propagation.TextMapSetter;
import io.opentelemetry.sdk.autoconfigure.spi.ConfigProperties;
import io.opentelemetry.sdk.autoconfigure.spi.ConfigurablePropagatorProvider;
import java.util.Collection;

/**
 * The W3C trace context propagator, with an oversized {@code tracestate} dropped before it is parsed.
 *
 * <p>opentelemetry-api before 1.67.0 parses {@code tracestate} with a regular expression that takes quadratic time
 * on long runs of spaces or tabs (GHSA-ccrj-gw8r-854m): about 0.6 s of CPU for an 8 KB header. The disabled SDK keeps
 * the configured propagators, so this is treated as reachable whether or not tracing is enabled. W3C Trace Context lets a receiver discard a {@code tracestate} it will not process, and asks
 * vendors to propagate at least 512 characters, so this drops a longer one and keeps {@code traceparent}.
 *
 * <p>Selected by name in {@code quarkus.otel.propagators}. Remove it once Quarkus ships opentelemetry-api 1.67.0
 * or later.
 */
public final class BoundedTraceContextPropagator implements TextMapPropagator {

    /** The propagator's name in {@code quarkus.otel.propagators}. */
    public static final String NAME = "tracecontext-bounded";

    /** The longest {@code tracestate} passed on to the W3C propagator. */
    public static final int MAX_TRACESTATE = 512;

    private static final String TRACESTATE = "tracestate";

    private final TextMapPropagator delegate = W3CTraceContextPropagator.getInstance();

    @Override
    public Collection<String> fields() {
        return delegate.fields();
    }

    @Override
    public <C> void inject(Context context, C carrier, TextMapSetter<C> setter) {
        delegate.inject(context, carrier, setter);
    }

    @Override
    public <C> Context extract(Context context, C carrier, TextMapGetter<C> getter) {
        return delegate.extract(context, carrier, new TextMapGetter<C>() {
            @Override
            public Iterable<String> keys(C c) {
                return getter.keys(c);
            }

            @Override
            public String get(C c, String key) {
                String value = getter.get(c, key);
                if (value != null && TRACESTATE.equalsIgnoreCase(key) && value.length() > MAX_TRACESTATE) {
                    return null;
                }
                return value;
            }
        });
    }

    @Override
    public String toString() {
        return "BoundedTraceContextPropagator";
    }

    /** Registers the propagator with OpenTelemetry autoconfiguration under {@link #NAME}. */
    public static final class Provider implements ConfigurablePropagatorProvider {

        @Override
        public TextMapPropagator getPropagator(ConfigProperties config) {
            return new BoundedTraceContextPropagator();
        }

        @Override
        public String getName() {
            return NAME;
        }
    }
}
