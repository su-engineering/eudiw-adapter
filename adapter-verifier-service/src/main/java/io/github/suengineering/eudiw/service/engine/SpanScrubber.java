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

import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.context.Context;
import io.opentelemetry.sdk.trace.ReadWriteSpan;
import io.opentelemetry.sdk.trace.ReadableSpan;
import io.opentelemetry.sdk.trace.SpanProcessor;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Removes values from spans that would let a reader of the traces act on a session: the request handle in {@code
 * /oid4vp/requests/{handle}}, which fetches the signed request, and every query string, which can carry the
 * same-device {@code response_code}. Runs when a span starts, after the HTTP attributes are set.
 */
@ApplicationScoped
public class SpanScrubber implements SpanProcessor {

    static final String REDACTED = "redacted";
    private static final Pattern REQUEST_HANDLE = Pattern.compile("(/oid4vp/requests/)[^/?#]+");
    private static final List<AttributeKey<String>> PATHS = List.of(
            AttributeKey.stringKey("url.path"),
            AttributeKey.stringKey("url.full"),
            AttributeKey.stringKey("http.target"),
            AttributeKey.stringKey("http.url"));
    private static final List<AttributeKey<String>> QUERIES = List.of(AttributeKey.stringKey("url.query"));

    @Override
    public void onStart(Context parentContext, ReadWriteSpan span) {
        for (AttributeKey<String> key : PATHS) {
            String value = span.getAttribute(key);
            if (value != null) {
                span.setAttribute(key, scrub(value));
            }
        }
        for (AttributeKey<String> key : QUERIES) {
            if (span.getAttribute(key) != null) {
                span.setAttribute(key, REDACTED);
            }
        }
    }

    static String scrub(String value) {
        int query = value.indexOf('?');
        String path = query < 0 ? value : value.substring(0, query) + "?" + REDACTED;
        return REQUEST_HANDLE.matcher(path).replaceAll("$1{handle}");
    }

    @Override
    public boolean isStartRequired() {
        return true;
    }

    @Override
    public void onEnd(ReadableSpan span) {}

    @Override
    public boolean isEndRequired() {
        return false;
    }
}
