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

import io.github.suengineering.eudiw.core.VerificationFailure;
import io.github.suengineering.eudiw.core.dcql.DcqlQuery.ClaimQuery;
import io.github.suengineering.eudiw.core.dcql.DcqlQuery.CredentialQuery;
import io.github.suengineering.eudiw.core.dcql.DcqlQuery.CredentialSetQuery;
import io.github.suengineering.eudiw.core.dcql.DcqlQuery.TrustedAuthority;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Checks verified credentials against the DCQL query they answer (OpenID4VP 1.0 sections 6.4 and 8.6) and returns
 * only the requested claims. The query is the verifier's own, so anything the wallet returns beyond it is dropped,
 * and anything it fails to return makes the response fail.
 */
public final class DcqlEvaluator {

    private final boolean enforceTrustedAuthorities;

    /**
     * @param enforceTrustedAuthorities reject credentials that match none of a query's {@code trusted_authorities}
     */
    public DcqlEvaluator(boolean enforceTrustedAuthorities) {
        this.enforceTrustedAuthorities = enforceTrustedAuthorities;
    }

    /** A requested claim and the values selected for it. */
    public record DisclosedClaim(ClaimsPath path, List<Object> values) {
        public DisclosedClaim {
            values = List.copyOf(values);
        }
    }

    /**
     * One accepted credential, reduced to what the query asked for. The full disclosed payload is deliberately not
     * carried, so nothing unrequested can leave the evaluator.
     *
     * @param format credential format
     * @param type {@code vct} or doctype
     * @param issuer issuer identifier established during verification
     * @param claims the requested claims and their values
     */
    public record SelectedCredential(String format, String type, String issuer, List<DisclosedClaim> claims) {
        public SelectedCredential {
            claims = List.copyOf(claims);
        }

        static SelectedCredential of(PresentedCredential credential, List<DisclosedClaim> claims) {
            return new SelectedCredential(credential.format(), credential.type(), credential.issuer(), claims);
        }
    }

    /**
     * @param presented verified credentials keyed by Credential Query id, as returned in the VP Token
     * @return the accepted credentials keyed by Credential Query id
     * @throws VerificationFailure when the response does not satisfy the query
     */
    public Map<String, List<SelectedCredential>> evaluate(
            DcqlQuery query, Map<String, List<PresentedCredential>> presented) {
        Map<String, List<SelectedCredential>> accepted = new LinkedHashMap<>();
        for (Map.Entry<String, List<PresentedCredential>> entry : presented.entrySet()) {
            CredentialQuery credentialQuery = query.credential(entry.getKey())
                    .orElseThrow(() -> new VerificationFailure(
                            "unexpected_credential", "response contains a credential that was not requested"));
            List<PresentedCredential> credentials = entry.getValue();
            if (credentials == null || credentials.isEmpty()) {
                throw new VerificationFailure("invalid_vp_token", "empty presentation list");
            }
            if (!credentialQuery.multiple() && credentials.size() != 1) {
                throw new VerificationFailure(
                        "invalid_vp_token", "multiple presentations for a single credential query");
            }
            List<SelectedCredential> selected = new ArrayList<>();
            for (PresentedCredential credential : credentials) {
                selected.add(evaluateCredential(credentialQuery, credential));
            }
            accepted.put(entry.getKey(), selected);
        }
        checkCredentialSets(query, accepted);
        return accepted;
    }

    private SelectedCredential evaluateCredential(CredentialQuery query, PresentedCredential credential) {
        if (!query.format().equals(credential.format())) {
            throw new VerificationFailure("credential_mismatch", "credential format does not match the query");
        }
        if (!query.types().contains(credential.type())) {
            throw new VerificationFailure("credential_mismatch", "credential type does not match the query");
        }
        if (query.requireHolderBinding() && !credential.holderBindingVerified()) {
            throw new VerificationFailure("holder_binding_missing", "holder binding proof is required");
        }
        if (enforceTrustedAuthorities
                && !query.trustedAuthorities().isEmpty()
                && !matchesAuthority(query, credential)) {
            throw new VerificationFailure("untrusted_authority", "credential matches none of the trusted authorities");
        }

        if (query.claims().isEmpty()) {
            return SelectedCredential.of(credential, List.of());
        }
        if (query.claimSets().isEmpty()) {
            List<DisclosedClaim> claims = new ArrayList<>();
            for (ClaimQuery claim : query.claims()) {
                claims.add(select(claim, credential)
                        .orElseThrow(() -> new VerificationFailure(
                                "claims_not_satisfied", "a requested claim is missing or has a value not accepted")));
            }
            return SelectedCredential.of(credential, claims);
        }
        for (List<String> option : query.claimSets()) {
            List<DisclosedClaim> claims = new ArrayList<>();
            boolean satisfied = true;
            for (String claimId : option) {
                Optional<DisclosedClaim> disclosed = select(query.claim(claimId).orElseThrow(), credential);
                if (disclosed.isEmpty()) {
                    satisfied = false;
                    break;
                }
                claims.add(disclosed.get());
            }
            if (satisfied) {
                return SelectedCredential.of(credential, claims);
            }
        }
        throw new VerificationFailure("claims_not_satisfied", "no claim set option is satisfied");
    }

    private static Optional<DisclosedClaim> select(ClaimQuery claim, PresentedCredential credential) {
        Optional<List<Object>> selected = claim.path().select(credential.claims());
        if (selected.isEmpty() && DcqlQuery.FORMAT_MDOC.equals(credential.format())) {
            selected = AgeOver.substitute(claim.path(), credential.claims());
        }
        if (selected.isEmpty()) {
            return Optional.empty();
        }
        if (!claim.values().isEmpty()) {
            for (Object value : selected.get()) {
                if (claim.values().stream().noneMatch(expected -> valueEquals(expected, value))) {
                    return Optional.empty();
                }
            }
        }
        return Optional.of(new DisclosedClaim(claim.path(), selected.get()));
    }

    /** Type and value must both match (section 6.3). */
    static boolean valueEquals(Object expected, Object actual) {
        if (expected instanceof String || expected instanceof Boolean) {
            return expected.equals(actual);
        }
        if (expected instanceof Long e && DcqlQuery.isInteger(actual)) {
            return e == ((Number) actual).longValue();
        }
        return false;
    }

    private static boolean matchesAuthority(CredentialQuery query, PresentedCredential credential) {
        for (TrustedAuthority authority : query.trustedAuthorities()) {
            for (String value : authority.values()) {
                switch (authority.type()) {
                    case "aki" -> {
                        if (credential.authorityKeyIds().contains(value)) {
                            return true;
                        }
                    }
                    case "etsi_tl" -> {
                        if (credential.trustListIds().contains(value)) {
                            return true;
                        }
                    }
                    default -> {
                        // openid_federation and unknown types cannot be matched by this verifier
                    }
                }
            }
        }
        return false;
    }

    private static void checkCredentialSets(DcqlQuery query, Map<String, List<SelectedCredential>> accepted) {
        if (query.credentialSets().isEmpty()) {
            for (CredentialQuery credential : query.credentials()) {
                if (!accepted.containsKey(credential.id())) {
                    throw new VerificationFailure("credentials_not_satisfied", "a requested credential is missing");
                }
            }
            return;
        }
        for (CredentialSetQuery set : query.credentialSets()) {
            if (!set.required()) {
                continue;
            }
            boolean satisfied = set.options().stream().anyMatch(accepted.keySet()::containsAll);
            if (!satisfied) {
                throw new VerificationFailure(
                        "credentials_not_satisfied", "a required credential set is not satisfied");
            }
        }
    }

    /**
     * The age attestation rule of ISO/IEC 18013-5:2021 clause 7.2.5. A wallet asked for {@code age_over_NN} may
     * answer with the nearest attestation it holds instead: {@code age_over_MM: true} with MM at least NN proves
     * the holder is over NN, and {@code age_over_MM: false} with MM below NN proves they are not. The answer is
     * reported under the requested element, so nothing unrequested leaves the evaluator. Attestations that
     * contradict each other answer nothing.
     */
    static final class AgeOver {
        private static final java.util.regex.Pattern ELEMENT = java.util.regex.Pattern.compile("age_over_(\\d{2})");

        private AgeOver() {}

        static Optional<List<Object>> substitute(ClaimsPath path, Map<String, Object> claims) {
            if (!path.isMdocPath()) {
                return Optional.empty();
            }
            java.util.regex.Matcher requested =
                    ELEMENT.matcher((String) path.components().get(1));
            if (!requested.matches() || !(claims.get((String) path.components().get(0)) instanceof Map<?, ?> ns)) {
                return Optional.empty();
            }
            int wanted = Integer.parseInt(requested.group(1));
            boolean over = false;
            boolean notOver = false;
            for (Map.Entry<?, ?> e : ns.entrySet()) {
                java.util.regex.Matcher m = ELEMENT.matcher(String.valueOf(e.getKey()));
                if (!m.matches() || !(e.getValue() instanceof Boolean value)) {
                    continue;
                }
                int held = Integer.parseInt(m.group(1));
                over |= value && held >= wanted;
                notOver |= !value && held < wanted;
            }
            if (over == notOver) {
                return Optional.empty();
            }
            return Optional.of(List.of(over));
        }
    }
}
