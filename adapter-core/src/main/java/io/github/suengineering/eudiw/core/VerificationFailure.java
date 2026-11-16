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
package io.github.suengineering.eudiw.core;

import java.util.Objects;

/**
 * A verification step rejected its input. Carries a stable, machine-readable code that is safe to
 * expose to API callers; the message is for operators and must never contain credential content.
 */
public final class VerificationFailure extends RuntimeException {

    private final String code;

    public VerificationFailure(String code, String message) {
        super(message);
        this.code = requireCode(code);
    }

    public VerificationFailure(String code, String message, Throwable cause) {
        super(message, cause);
        this.code = requireCode(code);
    }

    public String code() {
        return code;
    }

    private static String requireCode(String code) {
        Objects.requireNonNull(code, "code");
        if (!code.matches("[a-z][a-z0-9_]*")) {
            throw new IllegalArgumentException("code must be lower snake case: " + code);
        }
        return code;
    }
}
