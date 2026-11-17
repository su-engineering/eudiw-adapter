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
import io.quarkus.opentelemetry.runtime.propagation.TextMapPropagatorCustomizer;
import io.quarkus.vertx.http.HttpServerOptionsCustomizer;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.tracing.TracingPolicy;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.Collection;
import org.eclipse.microprofile.config.inject.ConfigProperty;

/**
 * The W3C trace context propagator, with an oversized {@code tracestate} dropped before it is parsed.
 *
 * <p>opentelemetry-api before 1.67.0 parses {@code tracestate} with a regular expression that takes quadratic time
 * on long runs of spaces or tabs (GHSA-ccrj-gw8r-854m): about 0.6 s of CPU for an 8 KB header. W3C Trace Context
 * lets a receiver discard a {@code tracestate} it will not process, and asks vendors to propagate at least 512
 * characters, so this drops a longer one and keeps {@code traceparent}.
 *
 * <p>Two beans put it in place. With tracing on, {@link Customizer} wraps the W3C propagator Quarkus configures.
 * With tracing off ({@code quarkus.otel.sdk.disabled=true}, the default), the SDK is built without customizers but
 * still with the W3C propagator, so {@link TracingOff} sets the HTTP server's tracing policy to {@code IGNORE}:
 * the tracer then returns before it reads any header. Remove all of this once Quarkus ships opentelemetry-api
 * 1.67.0 or later.
 */
public final class BoundedTraceContextPropagator implements TextMapPropagator {

    /** The longest {@code tracestate} passed on to the W3C propagator. */
    public static final int MAX_TRACESTATE = 512;

    private static final String TRACESTATE = "tracestate";

    private final TextMapPropagator delegate;

    public BoundedTraceContextPropagator(TextMapPropagator delegate) {
        this.delegate = delegate;
    }

    public BoundedTraceContextPropagator() {
        this(W3CTraceContextPropagator.getInstance());
    }

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

    /** With tracing on: wraps the W3C trace context propagator. */
    @ApplicationScoped
    public static class Customizer implements TextMapPropagatorCustomizer {

        @Override
        public TextMapPropagator customize(TextMapPropagatorCustomizer.Context context) {
            TextMapPropagator propagator = context.propagator();
            return propagator instanceof W3CTraceContextPropagator
                    ? new BoundedTraceContextPropagator(propagator)
                    : propagator;
        }
    }

    /** With tracing off: the HTTP server does not call the tracer, so no trace header is parsed. */
    @ApplicationScoped
    public static class TracingOff implements HttpServerOptionsCustomizer {

        @ConfigProperty(name = "quarkus.otel.sdk.disabled", defaultValue = "false")
        boolean sdkDisabled;

        @Override
        public void customizeHttpServer(HttpServerOptions options) {
            apply(options);
        }

        @Override
        public void customizeHttpsServer(HttpServerOptions options) {
            apply(options);
        }

        @Override
        public void customizeDomainSocketServer(HttpServerOptions options) {
            apply(options);
        }

        void apply(HttpServerOptions options) {
            if (sdkDisabled) {
                options.setTracingPolicy(TracingPolicy.IGNORE);
            }
        }
    }
}
