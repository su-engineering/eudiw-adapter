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
import java.util.Optional;
import java.util.Set;

/**
 * A verified SD-JWT presentation.
 *
 * @param header the verified Issuer-signed JWT header
 * @param issuer the issuer identifier established by the {@link IssuerKeyResolver}
 * @param payload the Processed SD-JWT Payload (RFC 9901 section 7.1), with all {@code _sd}, {@code ...} and
 *     {@code _sd_alg} entries removed; unmodifiable
 * @param selectivelyDisclosedTopLevelClaims top-level claim names that came from a Disclosure rather than the
 *     signed payload
 * @param holderKey the holder key from {@code cnf.jwk}, if present
 * @param keyBindingVerified whether a Key Binding JWT was verified against the holder key, audience and nonce
 * @param issuerCertificateChain the validated issuer certificate chain, end-entity first; empty when the issuer
 *     key was not resolved from certificates
 * @param trustSources where the trusted certificate that anchored the issuer came from, for example a trusted
 *     list location
 */
public record VerifiedSdJwt(
        JWSHeader header,
        String issuer,
        Map<String, Object> payload,
        Set<String> selectivelyDisclosedTopLevelClaims,
        Optional<JWK> holderKey,
        boolean keyBindingVerified,
        java.util.List<java.security.cert.X509Certificate> issuerCertificateChain,
        Set<String> trustSources) {}
