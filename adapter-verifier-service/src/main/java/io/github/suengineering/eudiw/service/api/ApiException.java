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
package io.github.suengineering.eudiw.service.api;

/** An error returned to API callers as {@code application/problem+json} with a stable code. */
public class ApiException extends RuntimeException {

    private final int status;
    private final String code;
    private final long retryAfterSeconds;

    public ApiException(int status, String code, String message) {
        this(status, code, message, 0);
    }

    /** An error that tells the caller when to retry ({@code Retry-After}, RFC 9110 section 10.2.3). */
    public ApiException(int status, String code, String message, long retryAfterSeconds) {
        super(message);
        this.status = status;
        this.code = code;
        this.retryAfterSeconds = retryAfterSeconds;
    }

    public long retryAfterSeconds() {
        return retryAfterSeconds;
    }

    public int status() {
        return status;
    }

    public String code() {
        return code;
    }

    public static ApiException notFound() {
        return new ApiException(404, "not_found", "no such verification session");
    }
}
