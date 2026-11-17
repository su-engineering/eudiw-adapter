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
import java.util.Map;

/**
 * Determines the key that may verify an Issuer-signed JWT and confirms it belongs to the issuer (RFC 9901 section
 * 7.1 step 2c; SD-JWT VC section 3.5). Called before the signature is checked, so the header and payload are
 * untrusted input.
 */
@FunctionalInterface
public interface IssuerKeyResolver {

    /**
     * @param header the Issuer-signed JWT header, not yet verified
     * @param unverifiedPayload the Issuer-signed JWT payload, not yet verified
     * @return the trusted key and the issuer identifier it is bound to
     * @throws io.github.suengineering.eudiw.core.VerificationFailure {@code issuer_untrusted} when no permitted
     *     key can be determined
     */
    ResolvedIssuerKey resolve(JWSHeader header, Map<String, Object> unverifiedPayload);

    /**
     * @param key public key that verifies the issuer signature
     * @param issuer the issuer identifier established by the resolution mechanism
     * @param certificateChain the validated certificate chain, end-entity first; empty for key-based mechanisms
     * @param trustSources where the trusted certificate the chain validated to came from, for example a trusted
     *     list location; empty for key-based mechanisms
     * @param anchor the trust anchor the chain validated to; empty for key-based mechanisms
     */
    record ResolvedIssuerKey(
            JWK key,
            String issuer,
            java.util.List<java.security.cert.X509Certificate> certificateChain,
            java.util.Set<String> trustSources,
            java.util.Optional<java.security.cert.X509Certificate> anchor) {
        public ResolvedIssuerKey {
            java.util.Objects.requireNonNull(key, "key");
            java.util.Objects.requireNonNull(issuer, "issuer");
            certificateChain = java.util.List.copyOf(certificateChain);
            trustSources = java.util.Set.copyOf(trustSources);
            java.util.Objects.requireNonNull(anchor, "anchor");
        }

        public ResolvedIssuerKey(
                JWK key,
                String issuer,
                java.util.List<java.security.cert.X509Certificate> certificateChain,
                java.util.Set<String> trustSources) {
            this(key, issuer, certificateChain, trustSources, java.util.Optional.empty());
        }

        public ResolvedIssuerKey(JWK key, String issuer) {
            this(key, issuer, java.util.List.of(), java.util.Set.of());
        }
    }
}
