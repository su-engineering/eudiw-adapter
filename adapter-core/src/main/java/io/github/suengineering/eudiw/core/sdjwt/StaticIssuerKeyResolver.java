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
package io.github.suengineering.eudiw.core.sdjwt;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import io.github.suengineering.eudiw.core.VerificationFailure;
import java.util.Map;

/**
 * Resolves issuer keys from a fixed, operator-configured map of {@code iss} value to public key. Suitable for
 * closed ecosystems and tests; trust-list based resolution covers open ecosystems.
 */
public final class StaticIssuerKeyResolver implements IssuerKeyResolver {

    private final Map<String, JWK> keysByIssuer;

    public StaticIssuerKeyResolver(Map<String, JWK> keysByIssuer) {
        for (JWK key : keysByIssuer.values()) {
            if (key.isPrivate()) {
                throw new IllegalArgumentException("issuer keys must be public keys");
            }
        }
        this.keysByIssuer = Map.copyOf(keysByIssuer);
    }

    @Override
    public ResolvedIssuerKey resolve(JWSHeader header, Map<String, Object> unverifiedPayload) {
        if (!(unverifiedPayload.get("iss") instanceof String issuer)) {
            throw new VerificationFailure("issuer_untrusted", "credential has no iss claim");
        }
        JWK key = keysByIssuer.get(issuer);
        if (key == null) {
            throw new VerificationFailure("issuer_untrusted", "issuer is not configured");
        }
        return new ResolvedIssuerKey(key, issuer);
    }
}
