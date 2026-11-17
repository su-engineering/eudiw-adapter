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

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * A validated DCQL query (OpenID4VP 1.0 section 6) for the formats this project supports: {@code dc+sd-jwt} and
 * {@code mso_mdoc}. Instances are immutable and always satisfy the structural rules of the specification.
 */
public record DcqlQuery(List<CredentialQuery> credentials, List<CredentialSetQuery> credentialSets) {

    public static final String FORMAT_SD_JWT_VC = "dc+sd-jwt";
    public static final String FORMAT_MDOC = "mso_mdoc";

    private static final Pattern ID = Pattern.compile("[A-Za-z0-9_-]+");

    public DcqlQuery {
        credentials = List.copyOf(credentials);
        credentialSets = List.copyOf(credentialSets);
    }

    /**
     * @param id Credential Query identifier
     * @param format credential format identifier
     * @param types accepted {@code vct} values for SD-JWT VC, or the single doctype for mdoc
     * @param multiple whether several presentations may be returned
     * @param requireHolderBinding whether a holder binding proof is required (default true)
     * @param claims requested claims; empty means none are requested
     * @param claimSets alternative combinations of claim ids; empty when absent
     * @param trustedAuthorities trusted authority conditions; empty when absent
     */
    public record CredentialQuery(
            String id,
            String format,
            List<String> types,
            boolean multiple,
            boolean requireHolderBinding,
            List<ClaimQuery> claims,
            List<List<String>> claimSets,
            List<TrustedAuthority> trustedAuthorities) {

        public CredentialQuery {
            types = List.copyOf(types);
            claims = List.copyOf(claims);
            claimSets = claimSets.stream().map(List::copyOf).toList();
            trustedAuthorities = List.copyOf(trustedAuthorities);
        }

        public Optional<ClaimQuery> claim(String claimId) {
            return claims.stream().filter(c -> claimId.equals(c.id())).findFirst();
        }
    }

    /**
     * @param id claim identifier, required when claim sets are used
     * @param path claims path pointer
     * @param values accepted values (strings, integers or booleans); empty means any value
     */
    /**
     * @param intentToRetain for {@code mso_mdoc} only: whether the verifier intends to retain the value
     *     (OpenID4VP 1.0 Appendix B.2.4); {@code null} when not stated
     */
    public record ClaimQuery(String id, ClaimsPath path, List<Object> values, Boolean intentToRetain) {
        public ClaimQuery {
            values = List.copyOf(values);
        }

        public ClaimQuery(String id, ClaimsPath path, List<Object> values) {
            this(id, path, values, null);
        }
    }

    /**
     * @param options alternative sets of Credential Query ids
     * @param required whether one option must be satisfied
     */
    public record CredentialSetQuery(List<List<String>> options, boolean required) {
        public CredentialSetQuery {
            options = options.stream().map(List::copyOf).toList();
        }
    }

    /**
     * @param type {@code aki}, {@code etsi_tl} or {@code openid_federation}
     * @param values identifiers for the type
     */
    public record TrustedAuthority(String type, List<String> values) {
        public TrustedAuthority {
            values = List.copyOf(values);
        }
    }

    public Optional<CredentialQuery> credential(String id) {
        return credentials.stream().filter(c -> c.id().equals(id)).findFirst();
    }

    /**
     * Parses and validates a DCQL query. Unknown properties are ignored, as the specification requires.
     *
     * @throws IllegalArgumentException when the query violates section 6 or uses an unsupported format
     */
    @SuppressWarnings("unchecked")
    public static DcqlQuery parse(Map<String, Object> json) {
        List<Object> credentialsJson = nonEmptyArray(json.get("credentials"), "credentials");
        List<CredentialQuery> credentials = new ArrayList<>();
        Set<String> ids = new HashSet<>();
        for (Object item : credentialsJson) {
            CredentialQuery query = parseCredential(object(item, "credential query"));
            if (!ids.add(query.id())) {
                throw new IllegalArgumentException("duplicate credential query id: " + query.id());
            }
            credentials.add(query);
        }

        List<CredentialSetQuery> sets = new ArrayList<>();
        if (json.containsKey("credential_sets")) {
            for (Object item : nonEmptyArray(json.get("credential_sets"), "credential_sets")) {
                Map<String, Object> set = object(item, "credential set query");
                List<List<String>> options = new ArrayList<>();
                for (Object option : nonEmptyArray(set.get("options"), "options")) {
                    List<String> optionIds = stringList(nonEmptyArray(option, "option"), "option");
                    for (String id : optionIds) {
                        if (!ids.contains(id)) {
                            throw new IllegalArgumentException("credential set references unknown id: " + id);
                        }
                    }
                    options.add(optionIds);
                }
                sets.add(new CredentialSetQuery(options, bool(set.get("required"), true, "required")));
            }
        }
        return new DcqlQuery(credentials, sets);
    }

    private static CredentialQuery parseCredential(Map<String, Object> json) {
        String id = id(json.get("id"), "credential query id");
        if (!(json.get("format") instanceof String format)) {
            throw new IllegalArgumentException("format is required");
        }
        Map<String, Object> meta = object(json.get("meta"), "meta");
        List<String> types;
        switch (format) {
            case FORMAT_SD_JWT_VC ->
                types = stringList(nonEmptyArray(meta.get("vct_values"), "vct_values"), "vct_values");
            case FORMAT_MDOC -> {
                if (!(meta.get("doctype_value") instanceof String doctype) || doctype.isEmpty()) {
                    throw new IllegalArgumentException("doctype_value is required for mso_mdoc");
                }
                types = List.of(doctype);
            }
            default -> throw new IllegalArgumentException("unsupported format: " + format);
        }

        List<ClaimQuery> claims = new ArrayList<>();
        Set<String> claimIds = new HashSet<>();
        Set<List<Object>> paths = new HashSet<>();
        if (json.containsKey("claims")) {
            for (Object item : nonEmptyArray(json.get("claims"), "claims")) {
                Map<String, Object> claim = object(item, "claims query");
                String claimId = claim.containsKey("id") ? id(claim.get("id"), "claim id") : null;
                if (claimId != null && !claimIds.add(claimId)) {
                    throw new IllegalArgumentException("duplicate claim id: " + claimId);
                }
                ClaimsPath path = new ClaimsPath(nonEmptyArray(claim.get("path"), "path"));
                if (FORMAT_MDOC.equals(format) && !path.isMdocPath()) {
                    throw new IllegalArgumentException("mdoc claim paths must be [namespace, element]");
                }
                if (!paths.add(path.components())) {
                    throw new IllegalArgumentException("the same claim is requested twice");
                }
                List<Object> values = new ArrayList<>();
                if (claim.containsKey("values")) {
                    for (Object value : nonEmptyArray(claim.get("values"), "values")) {
                        if (!(value instanceof String || value instanceof Boolean || isInteger(value))) {
                            throw new IllegalArgumentException("values must be strings, integers or booleans");
                        }
                        values.add(value instanceof Number n ? n.longValue() : value);
                    }
                }
                Boolean intentToRetain = null;
                if (claim.containsKey("intent_to_retain")) {
                    if (!FORMAT_MDOC.equals(format)) {
                        throw new IllegalArgumentException("intent_to_retain is only defined for mso_mdoc");
                    }
                    if (!(claim.get("intent_to_retain") instanceof Boolean b)) {
                        throw new IllegalArgumentException("intent_to_retain must be a boolean");
                    }
                    intentToRetain = b;
                }
                claims.add(new ClaimQuery(claimId, path, values, intentToRetain));
            }
        }

        List<List<String>> claimSets = new ArrayList<>();
        if (json.containsKey("claim_sets")) {
            if (claims.isEmpty()) {
                throw new IllegalArgumentException("claim_sets requires claims");
            }
            for (ClaimQuery claim : claims) {
                if (claim.id() == null) {
                    throw new IllegalArgumentException("claim ids are required when claim_sets is present");
                }
            }
            for (Object option : nonEmptyArray(json.get("claim_sets"), "claim_sets")) {
                List<String> optionIds = stringList(nonEmptyArray(option, "claim set"), "claim set");
                for (String claimId : optionIds) {
                    if (!claimIds.contains(claimId)) {
                        throw new IllegalArgumentException("claim set references unknown claim id: " + claimId);
                    }
                }
                claimSets.add(optionIds);
            }
        }

        List<TrustedAuthority> authorities = new ArrayList<>();
        if (json.containsKey("trusted_authorities")) {
            for (Object item : nonEmptyArray(json.get("trusted_authorities"), "trusted_authorities")) {
                Map<String, Object> authority = object(item, "trusted authority");
                if (!(authority.get("type") instanceof String type)) {
                    throw new IllegalArgumentException("trusted authority type is required");
                }
                authorities.add(new TrustedAuthority(
                        type, stringList(nonEmptyArray(authority.get("values"), "values"), "values")));
            }
        }

        return new CredentialQuery(
                id,
                format,
                types,
                bool(json.get("multiple"), false, "multiple"),
                bool(json.get("require_cryptographic_holder_binding"), true, "require_cryptographic_holder_binding"),
                claims,
                claimSets,
                authorities);
    }

    /** Serializes the query for an Authorization Request. */
    public Map<String, Object> toJson() {
        Map<String, Object> json = new LinkedHashMap<>();
        List<Object> creds = new ArrayList<>();
        for (CredentialQuery c : credentials) {
            Map<String, Object> cj = new LinkedHashMap<>();
            cj.put("id", c.id());
            cj.put("format", c.format());
            cj.put(
                    "meta",
                    FORMAT_MDOC.equals(c.format())
                            ? Map.of("doctype_value", c.types().get(0))
                            : Map.of("vct_values", c.types()));
            if (c.multiple()) {
                cj.put("multiple", true);
            }
            if (!c.requireHolderBinding()) {
                cj.put("require_cryptographic_holder_binding", false);
            }
            if (!c.claims().isEmpty()) {
                List<Object> claims = new ArrayList<>();
                for (ClaimQuery q : c.claims()) {
                    Map<String, Object> qj = new LinkedHashMap<>();
                    if (q.id() != null) {
                        qj.put("id", q.id());
                    }
                    qj.put("path", q.path().components());
                    if (!q.values().isEmpty()) {
                        qj.put("values", q.values());
                    }
                    if (q.intentToRetain() != null) {
                        qj.put("intent_to_retain", q.intentToRetain());
                    }
                    claims.add(qj);
                }
                cj.put("claims", claims);
            }
            if (!c.claimSets().isEmpty()) {
                cj.put("claim_sets", c.claimSets());
            }
            if (!c.trustedAuthorities().isEmpty()) {
                List<Object> tas = new ArrayList<>();
                for (TrustedAuthority t : c.trustedAuthorities()) {
                    tas.add(Map.of("type", t.type(), "values", t.values()));
                }
                cj.put("trusted_authorities", tas);
            }
            creds.add(cj);
        }
        json.put("credentials", creds);
        if (!credentialSets.isEmpty()) {
            List<Object> sets = new ArrayList<>();
            for (CredentialSetQuery s : credentialSets) {
                Map<String, Object> sj = new LinkedHashMap<>();
                sj.put("options", s.options());
                if (!s.required()) {
                    sj.put("required", false);
                }
                sets.add(sj);
            }
            json.put("credential_sets", sets);
        }
        return json;
    }

    private static String id(Object value, String what) {
        if (!(value instanceof String s) || !ID.matcher(s).matches()) {
            throw new IllegalArgumentException(what + " must be a non-empty string of [A-Za-z0-9_-]");
        }
        return s;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> object(Object value, String what) {
        if (!(value instanceof Map<?, ?>)) {
            throw new IllegalArgumentException(what + " must be an object");
        }
        return (Map<String, Object>) value;
    }

    @SuppressWarnings("unchecked")
    private static List<Object> nonEmptyArray(Object value, String what) {
        if (!(value instanceof List<?> list) || list.isEmpty()) {
            throw new IllegalArgumentException(what + " must be a non-empty array");
        }
        return (List<Object>) list;
    }

    private static List<String> stringList(List<Object> values, String what) {
        List<String> out = new ArrayList<>(values.size());
        for (Object value : values) {
            if (!(value instanceof String s) || s.isEmpty()) {
                throw new IllegalArgumentException(what + " must contain non-empty strings");
            }
            out.add(s);
        }
        return out;
    }

    private static boolean bool(Object value, boolean defaultValue, String what) {
        if (value == null) {
            return defaultValue;
        }
        if (!(value instanceof Boolean b)) {
            throw new IllegalArgumentException(what + " must be a boolean");
        }
        return b;
    }

    static boolean isInteger(Object value) {
        if (value instanceof Long || value instanceof Integer || value instanceof Short || value instanceof Byte) {
            return true;
        }
        if (value instanceof Double d) {
            return d == Math.rint(d) && !Double.isInfinite(d);
        }
        return false;
    }
}
