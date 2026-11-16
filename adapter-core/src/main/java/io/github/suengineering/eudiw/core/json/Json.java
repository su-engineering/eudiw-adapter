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
package io.github.suengineering.eudiw.core.json;

import com.nimbusds.jose.util.JSONArrayUtils;
import com.nimbusds.jose.util.JSONObjectUtils;
import io.github.suengineering.eudiw.core.VerificationFailure;
import java.text.ParseException;
import java.util.List;
import java.util.Map;

/**
 * Bounded JSON parsing for untrusted input. Values are {@code Map<String, Object>}, {@code List<Object>},
 * {@code String}, {@code Boolean}, {@code Number} or {@code null}. Duplicate member names are rejected.
 */
public final class Json {

    /** Maximum nesting depth of objects and arrays accepted from untrusted input. */
    public static final int MAX_DEPTH = 32;

    private Json() {}

    public static Map<String, Object> parseObject(String json, String failureCode) {
        try {
            Map<String, Object> value = JSONObjectUtils.parse(json);
            checkDepth(value, 1, failureCode);
            return value;
        } catch (ParseException | RuntimeException e) {
            if (e instanceof VerificationFailure failure) {
                throw failure;
            }
            throw new VerificationFailure(failureCode, "not a valid JSON object", e);
        }
    }

    public static List<Object> parseArray(String json, String failureCode) {
        try {
            List<Object> value = JSONArrayUtils.parse(json);
            checkDepth(value, 1, failureCode);
            return value;
        } catch (ParseException | RuntimeException e) {
            if (e instanceof VerificationFailure failure) {
                throw failure;
            }
            throw new VerificationFailure(failureCode, "not a valid JSON array", e);
        }
    }

    /** Rejects structures nested deeper than {@link #MAX_DEPTH}. */
    public static void checkDepth(Object value, int depth, String failureCode) {
        if (depth > MAX_DEPTH) {
            throw new VerificationFailure(failureCode, "JSON nested deeper than " + MAX_DEPTH);
        }
        if (value instanceof Map<?, ?> map) {
            for (Object child : map.values()) {
                checkDepth(child, depth + 1, failureCode);
            }
        } else if (value instanceof List<?> list) {
            for (Object child : list) {
                checkDepth(child, depth + 1, failureCode);
            }
        }
    }

    public static String toJson(Map<String, ?> value) {
        return JSONObjectUtils.toJSONString(value);
    }
}
