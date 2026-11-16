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
package io.github.suengineering.eudiw.core.net;

import java.net.URI;

/**
 * Fetches documents the verifier needs from the network (status lists, trusted lists). Implementations enforce the
 * deployment's egress policy; verification code never opens connections itself.
 */
@FunctionalInterface
public interface HttpFetcher {

    /**
     * @param accept value for the Accept header
     * @param maxBytes upper bound on the response body
     * @return the response body of a 2xx response
     * @throws FetchException when the document cannot be fetched within the policy
     */
    byte[] get(URI uri, String accept, int maxBytes) throws FetchException;

    /** The document could not be fetched; callers treat this as an indeterminate result. */
    final class FetchException extends Exception {
        public FetchException(String message) {
            super(message);
        }

        public FetchException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
