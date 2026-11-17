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

import java.util.Map;
import java.util.Set;

/**
 * A credential whose presentation has already been cryptographically verified, in a format-neutral form that DCQL
 * can be evaluated against.
 *
 * @param format {@code dc+sd-jwt} or {@code mso_mdoc}
 * @param type {@code vct} or doctype
 * @param issuer issuer identifier established during verification
 * @param claims disclosed claims: the processed SD-JWT payload, or for mdoc a map of namespace to data element
 *     identifier to value (converted to JSON types)
 * @param holderBindingVerified whether a holder binding proof was verified for this presentation
 * @param authorityKeyIds base64url AuthorityKeyIdentifier values of the certificates in the issuer chain
 * @param trustListIds identifiers of the trusted lists that anchored the issuer
 * @param issuerNames further authenticated names of the issuer that an allow list may match, such as the trusted-list
 *     entity name; {@code issuer} itself is not repeated here
 */
public record PresentedCredential(
        String format,
        String type,
        String issuer,
        Map<String, Object> claims,
        boolean holderBindingVerified,
        Set<String> authorityKeyIds,
        Set<String> trustListIds,
        Set<String> issuerNames) {

    public PresentedCredential {
        authorityKeyIds = Set.copyOf(authorityKeyIds);
        trustListIds = Set.copyOf(trustListIds);
        issuerNames = Set.copyOf(issuerNames);
    }

    /** A credential whose issuer is known by {@code issuer} alone. */
    public PresentedCredential(
            String format,
            String type,
            String issuer,
            Map<String, Object> claims,
            boolean holderBindingVerified,
            Set<String> authorityKeyIds,
            Set<String> trustListIds) {
        this(format, type, issuer, claims, holderBindingVerified, authorityKeyIds, trustListIds, Set.of());
    }
}
