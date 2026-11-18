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
package io.github.suengineering.eudiw.core.oid4vp;

import io.github.suengineering.eudiw.core.VerificationFailure;
import io.github.suengineering.eudiw.core.cbor.CborItem;
import io.github.suengineering.eudiw.core.dcql.DcqlEvaluator;
import io.github.suengineering.eudiw.core.dcql.DcqlEvaluator.SelectedCredential;
import io.github.suengineering.eudiw.core.dcql.DcqlQuery;
import io.github.suengineering.eudiw.core.dcql.DcqlQuery.CredentialQuery;
import io.github.suengineering.eudiw.core.dcql.PresentedCredential;
import io.github.suengineering.eudiw.core.jose.AlgorithmPolicy;
import io.github.suengineering.eudiw.core.mdoc.MdocPresentationVerifier;
import io.github.suengineering.eudiw.core.mdoc.MdocPresentationVerifier.VerifiedMdoc;
import io.github.suengineering.eudiw.core.mdoc.MobileSecurityObject;
import io.github.suengineering.eudiw.core.mdoc.SessionTranscripts;
import io.github.suengineering.eudiw.core.sdjwt.SdJwtVcVerifier;
import io.github.suengineering.eudiw.core.sdjwt.SdJwtVcVerifier.VerifiedSdJwtVc;
import io.github.suengineering.eudiw.core.sdjwt.SdJwtVerificationOptions;
import io.github.suengineering.eudiw.core.status.StatusDecision;
import io.github.suengineering.eudiw.core.status.StatusListChecker;
import io.github.suengineering.eudiw.core.x509.CertificateIdentifiers;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Verifies a VP Token against the DCQL query of the request it answers (OpenID4VP 1.0 section 8.6): checks the
 * token structure, verifies each presentation, applies the status policy, and evaluates the query. Presentations
 * that fail their own checks are discarded; if what remains does not satisfy the query, the token is rejected.
 */
public final class VpTokenVerifier {

    /** How credential status is enforced. */
    public enum StatusPolicy {
        /** Status must be checked when present and be VALID; an unavailable or unverifiable list rejects. */
        REQUIRE_VALID,
        /** Status must not be revoked or suspended; an unavailable list is tolerated. */
        REJECT_KNOWN_INVALID,
        /** Status is not checked. Only for closed test environments. */
        IGNORE
    }

    /** Which trust anchors may sign a credential's status list. */
    public enum StatusSigner {
        /** Any status anchor of the policy. */
        ANY_ANCHOR,
        /**
         * Only the trust anchor the credential's issuer chain validated to, so a status provider trusted for one
         * issuer cannot speak for another issuer's credentials. A list signed under another anchor counts as an
         * indeterminate status ({@code status_signer_not_issuer}).
         */
        CREDENTIAL_ISSUER
    }

    /**
     * @param clock time source
     * @param keyBindingMaxAge oldest acceptable Key Binding JWT
     * @param clockSkew tolerance for time checks
     * @param algorithms accepted JWS algorithms
     * @param enforceTrustedAuthorities enforce DCQL {@code trusted_authorities} on responses
     * @param statusPolicy how credential status is enforced
     * @param requireStatus refuse a credential that carries no status reference this verifier can check
     *     ({@code credential_status_missing})
     * @param statusSigner which trust anchors may sign a credential's status list
     */
    public record Settings(
            Clock clock,
            Duration keyBindingMaxAge,
            Duration clockSkew,
            AlgorithmPolicy algorithms,
            boolean enforceTrustedAuthorities,
            StatusPolicy statusPolicy,
            boolean requireStatus,
            StatusSigner statusSigner) {

        public Settings {
            Objects.requireNonNull(statusPolicy, "statusPolicy");
            Objects.requireNonNull(statusSigner, "statusSigner");
            if (requireStatus && statusPolicy == StatusPolicy.IGNORE) {
                throw new IllegalArgumentException("requireStatus needs a status policy other than IGNORE");
            }
        }

        /** Settings that accept credentials without status and any status anchor as list signer. */
        public Settings(
                Clock clock,
                Duration keyBindingMaxAge,
                Duration clockSkew,
                AlgorithmPolicy algorithms,
                boolean enforceTrustedAuthorities,
                StatusPolicy statusPolicy) {
            this(
                    clock,
                    keyBindingMaxAge,
                    clockSkew,
                    algorithms,
                    enforceTrustedAuthorities,
                    statusPolicy,
                    false,
                    StatusSigner.ANY_ANCHOR);
        }

        public static Settings defaults() {
            return new Settings(
                    Clock.systemUTC(),
                    Duration.ofMinutes(5),
                    Duration.ofSeconds(60),
                    AlgorithmPolicy.DEFAULT,
                    true,
                    StatusPolicy.REQUIRE_VALID);
        }
    }

    /**
     * @param audience the Client Identifier the Key Binding JWT must be addressed to
     * @param nonce the nonce of the Authorization Request
     * @param statusCacheScope isolates cached status lists, for example tenant and trust profile revision
     * @param responseUri the request's {@code response_uri}, part of the mdoc session transcript; {@code null}
     *     when the query has no {@code mso_mdoc} credential
     * @param encryptionKeyThumbprint SHA-256 JWK thumbprint of the response encryption key, for the mdoc session
     *     transcript
     */
    public record Context(
            String audience,
            String nonce,
            String statusCacheScope,
            String responseUri,
            Optional<byte[]> encryptionKeyThumbprint,
            Map<String, List<String>> transactionData,
            Optional<String> dcApiOrigin) {
        public Context {
            Objects.requireNonNull(dcApiOrigin, "dcApiOrigin");
            Objects.requireNonNull(audience, "audience");
            Objects.requireNonNull(nonce, "nonce");
            Objects.requireNonNull(statusCacheScope, "statusCacheScope");
            Objects.requireNonNull(encryptionKeyThumbprint, "encryptionKeyThumbprint");
            transactionData = Map.copyOf(transactionData);
        }

        /** Without transaction data. */
        public Context(
                String audience,
                String nonce,
                String statusCacheScope,
                String responseUri,
                Optional<byte[]> encryptionKeyThumbprint) {
            this(audience, nonce, statusCacheScope, responseUri, encryptionKeyThumbprint, Map.of(), Optional.empty());
        }

        /** With transaction data, over a redirect. */
        public Context(
                String audience,
                String nonce,
                String statusCacheScope,
                String responseUri,
                Optional<byte[]> encryptionKeyThumbprint,
                Map<String, List<String>> transactionData) {
            this(
                    audience,
                    nonce,
                    statusCacheScope,
                    responseUri,
                    encryptionKeyThumbprint,
                    transactionData,
                    Optional.empty());
        }

        /**
         * The audience a presentation must name: {@code origin:<origin>} over the Digital Credentials API, signed
         * requests included (OpenID4VP 1.0 appendix A.4), otherwise the Client Identifier.
         */
        public String presentationAudience() {
            return dcApiOrigin.map(origin -> "origin:" + origin).orElse(audience);
        }

        /** A context for SD-JWT VC only; mdoc presentations need the response URI and encryption key. */
        public Context(String audience, String nonce, String statusCacheScope) {
            this(audience, nonce, statusCacheScope, null, Optional.empty());
        }
    }

    /** A presentation that failed its checks, with the reason code. Never contains credential content. */
    public record Discarded(String credentialQueryId, String code) {}

    /**
     * @param credentials accepted credentials and their requested claims, keyed by Credential Query id
     * @param discarded presentations that were dropped and why
     */
    public record Result(Map<String, List<SelectedCredential>> credentials, List<Discarded> discarded) {}

    private final SdJwtVcVerifier sdJwtVcVerifier;
    private final Optional<MdocPresentationVerifier> mdocVerifier;
    private final Optional<StatusListChecker> statusChecker;
    private final Settings settings;

    public VpTokenVerifier(
            SdJwtVcVerifier sdJwtVcVerifier, Optional<StatusListChecker> statusChecker, Settings settings) {
        this(sdJwtVcVerifier, Optional.empty(), statusChecker, settings);
    }

    /**
     * @param mdocVerifier verifies {@code mso_mdoc} presentations; without it they are rejected as unsupported
     */
    public VpTokenVerifier(
            SdJwtVcVerifier sdJwtVcVerifier,
            Optional<MdocPresentationVerifier> mdocVerifier,
            Optional<StatusListChecker> statusChecker,
            Settings settings) {
        this.sdJwtVcVerifier = Objects.requireNonNull(sdJwtVcVerifier, "sdJwtVcVerifier");
        this.mdocVerifier = Objects.requireNonNull(mdocVerifier, "mdocVerifier");
        this.statusChecker = Objects.requireNonNull(statusChecker, "statusChecker");
        this.settings = Objects.requireNonNull(settings, "settings");
        if (settings.statusPolicy() != StatusPolicy.IGNORE && statusChecker.isEmpty()) {
            throw new IllegalArgumentException("a status checker is required unless status is ignored");
        }
    }

    /**
     * @param vpToken the parsed {@code vp_token} JSON object
     * @throws VerificationFailure when the token is malformed or does not satisfy the query
     */
    public Result verify(Object vpToken, DcqlQuery query, Context context) {
        Map<String, List<String>> presentations = parseStructure(vpToken, query);

        Map<String, List<PresentedCredential>> verified = new LinkedHashMap<>();
        List<Discarded> discarded = new ArrayList<>();
        for (Map.Entry<String, List<String>> entry : presentations.entrySet()) {
            CredentialQuery credentialQuery = query.credential(entry.getKey()).orElseThrow();
            for (String presentation : entry.getValue()) {
                try {
                    PresentedCredential credential = verifyPresentation(presentation, credentialQuery, context);
                    verified.computeIfAbsent(entry.getKey(), k -> new ArrayList<>())
                            .add(credential);
                } catch (VerificationFailure failure) {
                    discarded.add(new Discarded(entry.getKey(), failure.code()));
                }
            }
        }
        try {
            Map<String, List<SelectedCredential>> accepted =
                    new DcqlEvaluator(settings.enforceTrustedAuthorities()).evaluate(query, verified);
            return new Result(accepted, List.copyOf(discarded));
        } catch (VerificationFailure failure) {
            if (!discarded.isEmpty() && failure.code().equals("credentials_not_satisfied")) {
                // Report the first underlying reason; the caller sees why the query could not be met.
                throw new VerificationFailure(
                        discarded.get(0).code(), "presentation rejected: " + failure.getMessage(), failure);
            }
            throw failure;
        }
    }

    private static Map<String, List<String>> parseStructure(Object vpToken, DcqlQuery query) {
        if (!(vpToken instanceof Map<?, ?> map) || map.isEmpty()) {
            throw new VerificationFailure("invalid_vp_token", "vp_token must be a non-empty JSON object");
        }
        Map<String, List<String>> out = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            String id = String.valueOf(entry.getKey());
            CredentialQuery credentialQuery = query.credential(id)
                    .orElseThrow(() -> new VerificationFailure(
                            "unexpected_credential", "vp_token contains a credential that was not requested"));
            if (!(entry.getValue() instanceof List<?> list) || list.isEmpty()) {
                throw new VerificationFailure("invalid_vp_token", "each vp_token entry must be a non-empty array");
            }
            if (!credentialQuery.multiple() && list.size() != 1) {
                throw new VerificationFailure(
                        "invalid_vp_token", "multiple presentations for a single credential query");
            }
            List<String> presentations = new ArrayList<>();
            for (Object item : list) {
                if (!(item instanceof String s) || s.isEmpty()) {
                    throw new VerificationFailure("invalid_vp_token", "presentations must be strings");
                }
                presentations.add(s);
            }
            out.put(id, presentations);
        }
        return out;
    }

    private PresentedCredential verifyPresentation(String presentation, CredentialQuery query, Context context) {
        List<String> transactionData = context.transactionData().getOrDefault(query.id(), List.of());
        if (!transactionData.isEmpty() && !DcqlQuery.FORMAT_SD_JWT_VC.equals(query.format())) {
            // OpenID4VP 1.0 binds transaction data to an mdoc through type-specific data elements (appendix B.2.1),
            // which this verifier does not check; refuse rather than accept the presentation without the binding.
            throw new VerificationFailure(
                    "transaction_data_unsupported", "transaction data is supported for SD-JWT VC only");
        }
        if (DcqlQuery.FORMAT_MDOC.equals(query.format()) && mdocVerifier.isPresent()) {
            return verifyMdoc(presentation, query, context);
        }
        if (!DcqlQuery.FORMAT_SD_JWT_VC.equals(query.format())) {
            throw new VerificationFailure("unsupported_format", "credential format not supported: " + query.format());
        }
        SdJwtVerificationOptions options = new SdJwtVerificationOptions(
                settings.algorithms(),
                SdJwtVerificationOptions.DEFAULT_HASH_ALGORITHMS,
                query.requireHolderBinding(),
                query.requireHolderBinding() ? context.presentationAudience() : null,
                query.requireHolderBinding() ? context.nonce() : null,
                settings.keyBindingMaxAge(),
                settings.clockSkew(),
                settings.clock(),
                512 * 1024,
                256,
                transactionData);
        VerifiedSdJwtVc vc = sdJwtVcVerifier.verify(presentation, options, Set.copyOf(query.types()));
        checkStatus(vc, context);
        return new PresentedCredential(
                DcqlQuery.FORMAT_SD_JWT_VC,
                vc.vct(),
                vc.sdJwt().issuer(),
                vc.sdJwt().payload(),
                vc.sdJwt().keyBindingVerified(),
                CertificateIdentifiers.authorityKeyIds(vc.sdJwt().issuerCertificateChain()),
                vc.sdJwt().trustSources());
    }

    private PresentedCredential verifyMdoc(String presentation, CredentialQuery query, Context context) {
        CborItem transcript;
        if (context.dcApiOrigin().isPresent()) {
            transcript = SessionTranscripts.openId4VpDcApi(
                    context.dcApiOrigin().get(), context.nonce(), context.encryptionKeyThumbprint());
        } else {
            if (context.responseUri() == null) {
                throw new IllegalStateException("an mso_mdoc query needs the response URI in the context");
            }
            transcript = SessionTranscripts.openId4VpRedirect(
                    context.audience(), context.nonce(), context.encryptionKeyThumbprint(), context.responseUri());
        }
        VerifiedMdoc mdoc =
                mdocVerifier.orElseThrow().verify(presentation, query.types().get(0), transcript);
        // An MSO status that is a Token Status List reference is checked like an SD-JWT VC's (ADR-012). Any other
        // status mechanism cannot be checked, so it counts as an indeterminate status.
        MobileSecurityObject mso = mdoc.issuerSigned().mso();
        if (mso.statusListReference().isPresent()) {
            if (settings.statusPolicy() != StatusPolicy.IGNORE) {
                enforce(status(
                        mso.statusListReference().get(),
                        context,
                        true,
                        Optional.of(mdoc.issuerSigned().anchor())));
            }
        } else if (mso.statusPresent()
                && (settings.statusPolicy() == StatusPolicy.REQUIRE_VALID || settings.requireStatus())) {
            throw new VerificationFailure("credential_status_unknown", "mdoc status mechanism is not supported");
        } else if (settings.requireStatus()) {
            throw new VerificationFailure("credential_status_missing", "credential has no status");
        }
        List<java.security.cert.X509Certificate> chain = mdoc.issuerSigned().chain();
        // An mdoc has no issuer identifier of its own. It is named by its trust anchor, which outlives document
        // signer rotation and cannot be claimed by a certificate under another anchor, and by the trusted-list
        // entities that publish that anchor (ADR-012).
        return new PresentedCredential(
                DcqlQuery.FORMAT_MDOC,
                mdoc.issuerSigned().docType(),
                mdoc.issuerSigned().anchor().getSubjectX500Principal().getName(),
                mdoc.claims(),
                true,
                CertificateIdentifiers.authorityKeyIds(chain),
                mdoc.issuerSigned().trustSources(),
                mdoc.issuerSigned().trustedEntityNames(),
                mdoc.warnings());
    }

    private void checkStatus(VerifiedSdJwtVc vc, Context context) {
        if (vc.status().isEmpty() && settings.requireStatus()) {
            throw new VerificationFailure("credential_status_missing", "credential has no status");
        }
        if (settings.statusPolicy() == StatusPolicy.IGNORE || vc.status().isEmpty()) {
            return;
        }
        enforce(status(vc.status().get(), context, false, vc.sdJwt().issuerAnchor()));
    }

    /**
     * Checks a status reference. Under {@link StatusSigner#CREDENTIAL_ISSUER} the list must be signed under the
     * issuer's anchor; an issuer without one (a key-based issuer) has no list that can match, so its status is
     * indeterminate.
     */
    private StatusDecision status(
            Map<String, Object> reference,
            Context context,
            boolean preferCwt,
            Optional<java.security.cert.X509Certificate> issuerAnchor) {
        if (settings.statusSigner() == StatusSigner.ANY_ANCHOR) {
            return statusChecker.orElseThrow().check(reference, context.statusCacheScope(), preferCwt);
        }
        if (issuerAnchor.isEmpty()) {
            return StatusDecision.indeterminate("status_signer_not_issuer");
        }
        return statusChecker.orElseThrow().check(reference, context.statusCacheScope(), preferCwt, issuerAnchor);
    }

    private void enforce(StatusDecision decision) {
        switch (decision.result()) {
            case VALID -> {}
            case INVALID -> throw new VerificationFailure("credential_revoked", "credential is revoked");
            case SUSPENDED -> throw new VerificationFailure("credential_suspended", "credential is suspended");
            case OTHER -> throw new VerificationFailure("credential_status_invalid", "credential status is not valid");
            case INDETERMINATE -> {
                if (settings.statusPolicy() == StatusPolicy.REQUIRE_VALID) {
                    throw new VerificationFailure(
                            "credential_status_unknown", "credential status cannot be determined");
                }
            }
        }
    }
}
