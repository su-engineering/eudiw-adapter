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

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Objects;

/**
 * {@link HttpFetcher} on the JDK HTTP client. Redirects are never followed (a redirect could lead past the egress
 * check), responses are read up to a size limit, and every request has a timeout.
 */
public final class JdkHttpFetcher implements HttpFetcher {

    private final HttpClient client;
    private final EgressPolicy policy;
    private final Duration timeout;

    public JdkHttpFetcher(EgressPolicy policy, Duration timeout) {
        this.policy = Objects.requireNonNull(policy, "policy");
        this.timeout = Objects.requireNonNull(timeout, "timeout");
        this.client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(timeout)
                .build();
    }

    @Override
    public byte[] get(URI uri, String accept, int maxBytes) throws FetchException {
        policy.check(uri);
        HttpRequest request = HttpRequest.newBuilder(uri)
                .timeout(timeout)
                .header("Accept", accept)
                .GET()
                .build();
        try {
            HttpResponse<InputStream> response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
            try (InputStream body = response.body()) {
                if (response.statusCode() < 200 || response.statusCode() > 299) {
                    throw new FetchException("unexpected HTTP status " + response.statusCode());
                }
                byte[] bytes = body.readNBytes(maxBytes + 1);
                if (bytes.length > maxBytes) {
                    throw new FetchException("response exceeds " + maxBytes + " bytes");
                }
                return bytes;
            }
        } catch (IOException e) {
            throw new FetchException("request failed", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new FetchException("request interrupted", e);
        }
    }
}
