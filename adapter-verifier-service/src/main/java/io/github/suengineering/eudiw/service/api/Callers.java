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

import io.github.suengineering.eudiw.service.config.AdapterConfig.ClientBinding;
import io.github.suengineering.eudiw.service.engine.AdapterRuntime;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.json.JsonString;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import org.eclipse.microprofile.jwt.JsonWebToken;

/**
 * Resolves the authenticated caller to a registered client application and its tenant. The tenant always comes
 * from the access token's client identity, never from the request.
 */
@RequestScoped
public class Callers {

    @Inject
    JsonWebToken token;

    @Inject
    AdapterRuntime runtime;

    /**
     * @param scope the scope the operation requires
     * @throws ApiException 401 when there is no token, 403 when the client is unknown or lacks the scope
     */
    public ClientBinding require(String scope) {
        if (token == null || token.getRawToken() == null) {
            throw new ApiException(401, "unauthorized", "a bearer token is required");
        }
        String clientId = claim("azp");
        if (clientId == null) {
            clientId = claim("client_id");
        }
        if (clientId == null) {
            throw new ApiException(403, "unknown_client", "the token does not identify a client");
        }
        ClientBinding binding = runtime.config()
                .client(clientId)
                .orElseThrow(() -> new ApiException(403, "unknown_client", "the client is not registered"));
        String scopeClaim = claim("scope");
        Set<String> scopes = scopeClaim == null
                ? Set.of()
                : Arrays.stream(scopeClaim.split(" ")).filter(s -> !s.isEmpty()).collect(Collectors.toSet());
        if (!scopes.contains(scope)) {
            throw new ApiException(403, "insufficient_scope", "the token lacks scope " + scope);
        }
        return binding;
    }

    /** When the caller's access token expires; streams opened with it end then. */
    public java.time.Instant tokenExpiry() {
        return java.time.Instant.ofEpochSecond(token.getExpirationTime());
    }

    /**
     * A string claim exactly as issued. Claims outside the MicroProfile JWT set arrive as JSON values; anything
     * other than a string counts as absent.
     */
    private String claim(String name) {
        Object value = token.getClaim(name);
        if (value instanceof String s) {
            return s;
        }
        if (value instanceof JsonString s) {
            return s.getString();
        }
        return null;
    }
}
