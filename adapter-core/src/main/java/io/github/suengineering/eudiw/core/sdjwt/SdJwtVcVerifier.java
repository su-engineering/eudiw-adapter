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

import com.nimbusds.jose.JOSEObjectType;
import io.github.suengineering.eudiw.core.VerificationFailure;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Verifies SD-JWT VC presentations (draft-ietf-oauth-sd-jwt-vc-13, as profiled by HAIP 1.0 section 6.1) on top of
 * {@link SdJwtVerifier}.
 */
public final class SdJwtVcVerifier {

    public static final String MEDIA_TYPE = "dc+sd-jwt";
    private static final String LEGACY_MEDIA_TYPE = "vc+sd-jwt";

    /** Claims that SD-JWT VC section 3.2.2.2 forbids in Disclosures. */
    static final Set<String> NEVER_DISCLOSED = Set.of("iss", "nbf", "exp", "cnf", "vct", "vct#integrity", "status");

    private final SdJwtVerifier sdJwtVerifier;
    private final boolean acceptLegacyType;

    /**
     * @param acceptLegacyType also accept {@code typ: vc+sd-jwt}, which draft 13 recommends during a transition
     */
    public SdJwtVcVerifier(IssuerKeyResolver issuerKeyResolver, boolean acceptLegacyType) {
        this.sdJwtVerifier = new SdJwtVerifier(issuerKeyResolver);
        this.acceptLegacyType = acceptLegacyType;
    }

    /**
     * @param allowedTypes accepted {@code vct} values; must not be empty
     */
    public VerifiedSdJwtVc verify(String presentation, SdJwtVerificationOptions options, Set<String> allowedTypes) {
        Objects.requireNonNull(allowedTypes, "allowedTypes");
        if (allowedTypes.isEmpty()) {
            throw new IllegalArgumentException("at least one credential type must be allowed");
        }
        VerifiedSdJwt verified = sdJwtVerifier.verify(presentation, options);

        JOSEObjectType typ = verified.header().getType();
        String type = typ == null ? null : typ.getType();
        if (!MEDIA_TYPE.equals(type) && !(acceptLegacyType && LEGACY_MEDIA_TYPE.equals(type))) {
            throw new VerificationFailure("wrong_credential_format", "typ must be dc+sd-jwt");
        }
        for (String claim : NEVER_DISCLOSED) {
            if (verified.selectivelyDisclosedTopLevelClaims().contains(claim)) {
                throw new VerificationFailure("invalid_disclosure", claim + " must not be selectively disclosable");
            }
        }
        if (!(verified.payload().get("vct") instanceof String vct)) {
            throw new VerificationFailure("malformed_credential", "vct is required");
        }
        if (!allowedTypes.contains(vct)) {
            throw new VerificationFailure("credential_type_not_allowed", "credential type is not accepted");
        }
        // HAIP 1.0 section 6.1.1.1: a credential with holder binding is always presented with a KB-JWT.
        if (verified.holderKey().isPresent() && !verified.keyBindingVerified()) {
            throw new VerificationFailure(
                    "key_binding_required", "holder-bound credential presented without key binding");
        }

        Object status = verified.payload().get("status");
        if (status != null && !(status instanceof Map<?, ?>)) {
            throw new VerificationFailure("malformed_credential", "status must be an object");
        }
        @SuppressWarnings("unchecked")
        Optional<Map<String, Object>> statusClaim = Optional.ofNullable((Map<String, Object>) status);
        return new VerifiedSdJwtVc(vct, verified, statusClaim);
    }

    /**
     * @param vct the credential type
     * @param sdJwt the underlying verified SD-JWT
     * @param status the {@code status} claim, to be checked by the caller's status policy
     */
    public record VerifiedSdJwtVc(String vct, VerifiedSdJwt sdJwt, Optional<Map<String, Object>> status) {}
}
