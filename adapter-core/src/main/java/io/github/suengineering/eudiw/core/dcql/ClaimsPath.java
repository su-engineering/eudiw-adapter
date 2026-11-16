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
package io.github.suengineering.eudiw.core.dcql;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * A claims path pointer (OpenID4VP 1.0 section 7): a non-empty list of strings, {@code null} and non-negative
 * integers.
 */
public record ClaimsPath(List<Object> components) {

    public ClaimsPath {
        if (components == null || components.isEmpty()) {
            throw new IllegalArgumentException("claims path must not be empty");
        }
        List<Object> copy = new ArrayList<>(components.size());
        for (Object component : components) {
            if (component == null || component instanceof String) {
                copy.add(component);
            } else if (component instanceof Number n && isNonNegativeInteger(n)) {
                copy.add(n.longValue());
            } else {
                throw new IllegalArgumentException("claims path component must be a string, null or index");
            }
        }
        components = Collections.unmodifiableList(copy);
    }

    public static ClaimsPath of(Object... components) {
        return new ClaimsPath(java.util.Arrays.asList(components));
    }

    /** Whether the path has the mdoc shape: exactly a namespace and a data element identifier. */
    public boolean isMdocPath() {
        return components.size() == 2 && components.get(0) instanceof String && components.get(1) instanceof String;
    }

    /**
     * Applies the pointer to a JSON-based credential (section 7.1.1).
     *
     * @return the selected elements, or empty when processing aborts with an error (including an empty selection)
     */
    public Optional<List<Object>> select(Map<String, Object> root) {
        List<Object> selection = new ArrayList<>();
        selection.add(root);
        for (Object component : components) {
            List<Object> next = new ArrayList<>();
            for (Object element : selection) {
                if (component instanceof String key) {
                    if (!(element instanceof Map<?, ?> map)) {
                        return Optional.empty();
                    }
                    if (map.containsKey(key)) {
                        next.add(map.get(key));
                    }
                } else if (component == null) {
                    if (!(element instanceof List<?> list)) {
                        return Optional.empty();
                    }
                    next.addAll(list);
                } else {
                    long index = (Long) component;
                    if (!(element instanceof List<?> list)) {
                        return Optional.empty();
                    }
                    if (index < list.size()) {
                        next.add(list.get((int) index));
                    }
                }
            }
            if (next.isEmpty()) {
                return Optional.empty();
            }
            selection = next;
        }
        return Optional.of(selection);
    }

    private static boolean isNonNegativeInteger(Number n) {
        if (n instanceof Double || n instanceof Float) {
            double d = n.doubleValue();
            return d >= 0 && d == Math.rint(d) && d <= Integer.MAX_VALUE;
        }
        return n.longValue() >= 0 && n.longValue() <= Integer.MAX_VALUE;
    }
}
