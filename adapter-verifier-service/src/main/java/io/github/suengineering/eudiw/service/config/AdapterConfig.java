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
package io.github.suengineering.eudiw.service.config;

import io.github.suengineering.eudiw.core.dcql.ClaimsPath;
import io.github.suengineering.eudiw.core.dcql.DcqlQuery;
import io.github.suengineering.eudiw.core.oid4vp.VerifierIdentity;
import io.github.suengineering.eudiw.core.oid4vp.VpTokenVerifier.StatusPolicy;
import java.net.URI;
import java.security.cert.TrustAnchor;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * The validated, immutable deployment configuration: tenants, their client applications, verification policies
 * and key material. Loaded once at startup; {@link #revision()} identifies it in sessions and audit events.
 */
public record AdapterConfig(String revision, Map<String, Tenant> tenants) {

    public Optional<Tenant> tenant(String id) {
        return Optional.ofNullable(tenants.get(id));
    }

    /** Finds the tenant and client application for an OAuth client id. Client ids are unique across tenants. */
    public Optional<ClientBinding> client(String oauthClientId) {
        for (Tenant tenant : tenants.values()) {
            ClientApplication app = tenant.clients().get(oauthClientId);
            if (app != null) {
                return Optional.of(new ClientBinding(tenant, app));
            }
        }
        return Optional.empty();
    }

    public record ClientBinding(Tenant tenant, ClientApplication client) {}

    /**
     * @param id tenant identifier
     * @param verifier request-signing identity ({@code x509_hash})
     * @param walletInvocation base of the wallet invocation URI, for example {@code openid4vp://}
     * @param clients client applications keyed by OAuth client id
     * @param policies verification policies keyed by id
     */
    public record Tenant(
            String id,
            VerifierIdentity verifier,
            String walletInvocation,
            Map<String, ClientApplication> clients,
            Map<String, Policy> policies) {}

    /**
     * @param clientId OAuth client id of the calling backend
     * @param policies policy ids this client may start
     * @param completionUri pre-registered URI the wallet is sent back to in same-device flows
     */
    public record ClientApplication(String clientId, Set<String> policies, Optional<URI> completionUri) {}

    /**
     * @param id policy identifier
     * @param query the approved DCQL query; callers cannot change it
     * @param output result claim names mapped to a credential query id and claims path
     * @param trustAnchors issuer and status list trust anchors for this policy only
     * @param trustedLists signed trusted lists whose approved services add trust anchors
     * @param allowedIssuers if non-empty, only these issuer identifiers are accepted
     * @param checkCertificateRevocation check every issuer chain certificate against its CRL
     * @param statusPolicy how credential status is enforced
     * @param enforceTrustedAuthorities enforce DCQL {@code trusted_authorities} on responses
     * @param sessionTtl lifetime of an uncompleted session
     * @param resultTtl how long a verified result can be retrieved
     */
    public record Policy(
            String id,
            DcqlQuery query,
            Map<String, OutputClaim> output,
            Set<TrustAnchor> trustAnchors,
            java.util.List<io.github.suengineering.eudiw.core.trust.TrustedListSource> trustedLists,
            Set<String> allowedIssuers,
            boolean checkCertificateRevocation,
            StatusPolicy statusPolicy,
            boolean enforceTrustedAuthorities,
            Duration sessionTtl,
            Duration resultTtl) {}

    public record OutputClaim(String credentialId, ClaimsPath path) {}

    /** Hard upper bounds that no configuration may exceed. */
    public static final Duration MAX_SESSION_TTL = Duration.ofMinutes(15);

    public static final Duration MAX_RESULT_TTL = Duration.ofMinutes(60);
}
