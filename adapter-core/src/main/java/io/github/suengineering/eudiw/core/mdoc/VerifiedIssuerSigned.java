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
package io.github.suengineering.eudiw.core.mdoc;

import io.github.suengineering.eudiw.core.cbor.CborItem;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The issuer-authenticated part of an mdoc.
 *
 * @param docType document type
 * @param elements issuer-signed data element values per namespace, all digest-checked
 * @param mso the verified mobile security object
 * @param chain the document signer chain, end-entity first
 * @param trustSources where the trust anchor the chain validated to came from
 */
public record VerifiedIssuerSigned(
        String docType,
        Map<String, Map<String, CborItem>> elements,
        MobileSecurityObject mso,
        List<X509Certificate> chain,
        Set<String> trustSources) {

    public VerifiedIssuerSigned {
        chain = List.copyOf(chain);
        trustSources = Set.copyOf(trustSources);
    }
}
