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

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSObject;
import io.github.suengineering.eudiw.core.dcql.ClaimsPath;
import io.github.suengineering.eudiw.core.dcql.DcqlQuery;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;

/**
 * What a relying party registered for one intended use, sent to the wallet in the Request Object's {@code
 * verifier_info} parameter (OpenID4VP 1.0 section 5.11) as ETSI TS 119 472-2 V1.3.1 clause 6.3.2.2 profiles it:
 *
 * <ul>
 *   <li>a {@code registrar_dataset} element with the data the registrar holds about the intended use (RO-01 to
 *       RO-12), always;
 *   <li>a {@code registration_cert} element with the base64url encoding of the registration certificate (RO-13 to
 *       RO-16), when the relying party has one and it has not expired.
 * </ul>
 *
 * <p>The registration certificate (ETSI TS 119 475 V1.2.1 clause 5.2) is issued and signed by a third party and is
 * checked by the wallet. Here it is only parsed, so that an obviously wrong file, an expired certificate or a query
 * that asks for more than was registered is caught when the configuration loads.
 */
public final class RelyingPartyRegistration {

    /** {@code format} of the registrar-provided element (TS 119 472-2 RO-04). */
    public static final String FORMAT_REGISTRAR_DATASET = "registrar_dataset";

    /** {@code format} of the registration certificate element (TS 119 472-2 RO-15). */
    public static final String FORMAT_REGISTRATION_CERT = "registration_cert";

    /** JWT {@code typ} of a registration certificate (TS 119 475 clause 5.2.2). */
    public static final String REGISTRATION_CERT_TYPE = "rc-wrp+jwt";

    private static final List<String> REQUIRED_DATASET_STRINGS =
            List.of("registryURI", "intendedUseIdentifier", "policyURI");
    private static final List<String> REQUIRED_DATASET_ARRAYS = List.of("srvDescription", "purpose");

    private final Map<String, Object> registrarDataset;
    private final Optional<RegistrationCertificate> certificate;

    private RelyingPartyRegistration(
            Map<String, Object> registrarDataset, Optional<RegistrationCertificate> certificate) {
        this.registrarDataset = registrarDataset;
        this.certificate = certificate;
    }

    /**
     * Checks the registrar dataset and builds the registration.
     *
     * @param registrarDataset the {@code data} object of the {@code registrar_dataset} element, as the registrar
     *     provided it
     * @param certificate the registration certificate, if the relying party has one
     * @throws IllegalArgumentException if a member TS 119 472-2 requires is missing or malformed
     */
    public static RelyingPartyRegistration of(
            Map<String, Object> registrarDataset, Optional<RegistrationCertificate> certificate) {
        Objects.requireNonNull(registrarDataset, "registrarDataset");
        Objects.requireNonNull(certificate, "certificate");
        if (registrarDataset.isEmpty()) {
            throw new IllegalArgumentException("registrar dataset must not be empty");
        }
        Object identifier = registrarDataset.get("identifier");
        boolean identified = identifier instanceof String s
                ? !s.isEmpty()
                : identifier instanceof Map<?, ?> m ? !m.isEmpty() : identifier instanceof List<?> l && !l.isEmpty();
        if (!identified) {
            throw new IllegalArgumentException("registrar dataset needs identifier (RO-06)");
        }
        for (String key : REQUIRED_DATASET_STRINGS) {
            if (!(registrarDataset.get(key) instanceof String s) || s.isEmpty()) {
                throw new IllegalArgumentException("registrar dataset needs a non-empty string " + key);
            }
        }
        for (String key : REQUIRED_DATASET_ARRAYS) {
            if (!(registrarDataset.get(key) instanceof List<?> l) || l.isEmpty()) {
                throw new IllegalArgumentException("registrar dataset needs a non-empty array " + key);
            }
            for (Object entry : (List<?>) registrarDataset.get(key)) {
                if (!(entry instanceof Map<?, ?> text)
                        || !(text.get("lang") instanceof String)
                        || !(text.get("content") instanceof String)) {
                    throw new IllegalArgumentException(key + " entries need lang and content (TS 119 475 B.2.6)");
                }
            }
        }
        if (registrarDataset.containsKey("credential") && !(registrarDataset.get("credential") instanceof List<?>)) {
            throw new IllegalArgumentException("registrar dataset credential must be an array");
        }
        return new RelyingPartyRegistration(Map.copyOf(registrarDataset), certificate);
    }

    public Map<String, Object> registrarDataset() {
        return registrarDataset;
    }

    public Optional<RegistrationCertificate> certificate() {
        return certificate;
    }

    /**
     * The {@code verifier_info} array for a request signed at {@code now}. An expired certificate is left out: a
     * wallet would reject it, and without it the wallet can still look the registration up through {@code
     * registryURI}.
     */
    public List<Map<String, Object>> verifierInfo(Instant now) {
        List<Map<String, Object>> elements = new ArrayList<>();
        Map<String, Object> dataset = new LinkedHashMap<>();
        dataset.put("format", FORMAT_REGISTRAR_DATASET);
        dataset.put("data", registrarDataset);
        elements.add(dataset);
        certificate.filter(c -> c.isCurrentAt(now)).ifPresent(c -> {
            Map<String, Object> element = new LinkedHashMap<>();
            element.put("format", FORMAT_REGISTRATION_CERT);
            element.put("data", c.base64url());
            elements.add(element);
        });
        return List.copyOf(elements);
    }

    /**
     * Credential and claim requests in {@code query} that the registrar dataset does not declare. Empty when the
     * dataset declares no {@code credential} member, since RO-12 makes it optional.
     */
    public List<String> undeclaredByDataset(DcqlQuery query) {
        if (!(registrarDataset.get("credential") instanceof List<?> declared)) {
            return List.of();
        }
        return undeclared(query, declared);
    }

    /**
     * Compares a DCQL query with the credentials an intended use declares (TS 119 475 B.2.9 and B.2.10, also used by
     * the registration certificate's {@code credentials}), as the wallet's over-asking check would.
     *
     * <p>A credential query is covered by a declared credential with the same {@code format} whose {@code meta}
     * names every type the query names ({@code vct_values} for SD-JWT VC, {@code doctype_value} for mdoc). Each
     * requested claim path must equal a declared {@code claim} path. When a declared credential lists no claims it
     * declares none, so any requested claim is reported.
     *
     * @return one line per problem; empty when everything requested is declared
     */
    public static List<String> undeclared(DcqlQuery query, List<?> declared) {
        List<String> problems = new ArrayList<>();
        for (DcqlQuery.CredentialQuery credential : query.credentials()) {
            List<Map<?, ?>> candidates = new ArrayList<>();
            for (Object entry : declared) {
                if (entry instanceof Map<?, ?> d
                        && credential.format().equals(d.get("format"))
                        && declaresTypes(d.get("meta"), credential)) {
                    candidates.add(d);
                }
            }
            if (candidates.isEmpty()) {
                problems.add("credential " + credential.id() + " (" + credential.format() + " " + credential.types()
                        + ") is not declared");
                continue;
            }
            for (DcqlQuery.ClaimQuery claim : credential.claims()) {
                boolean found = candidates.stream().anyMatch(d -> declaresClaim(d.get("claim"), claim.path()));
                if (!found) {
                    problems.add("claim " + claim.path().components() + " of credential " + credential.id()
                            + " is not declared");
                }
            }
        }
        return List.copyOf(problems);
    }

    private static boolean declaresTypes(Object meta, DcqlQuery.CredentialQuery credential) {
        if (!(meta instanceof Map<?, ?> m)) {
            return false;
        }
        Set<Object> declaredTypes = new LinkedHashSet<>();
        if (m.get("vct_values") instanceof List<?> values) {
            declaredTypes.addAll(values);
        }
        if (m.get("doctype_value") instanceof String doctype) {
            declaredTypes.add(doctype);
        }
        return !credential.types().isEmpty() && declaredTypes.containsAll(credential.types());
    }

    private static boolean declaresClaim(Object claims, ClaimsPath path) {
        if (!(claims instanceof List<?> list)) {
            return false;
        }
        for (Object c : list) {
            if (c instanceof Map<?, ?> claim && claim.get("path") instanceof List<?> p) {
                try {
                    if (new ClaimsPath(new ArrayList<>(p)).equals(path)) {
                        return true;
                    }
                } catch (IllegalArgumentException ignored) {
                    // A malformed declared path declares nothing.
                }
            }
        }
        return false;
    }

    /**
     * A registration certificate in its JWT form (ETSI TS 119 475 V1.2.1 clause 5.2). The signature is not
     * verified here: the wallet does that against the registration certificate providers on its trusted lists.
     *
     * @param serialized the compact JWS exactly as issued
     * @param subject the {@code sub} claim, the registered relying party's identifier
     * @param intermediary the {@code intermediary.sub} or {@code act.sub} claim, when a relying party acts through an
     *     intermediary
     * @param issuedAt the {@code iat} claim
     * @param expiresAt the {@code exp} claim, if present
     * @param credentials the declared {@code credentials}, empty when absent
     * @param missingMembers payload members ETSI TS 119 475 clause 5.2.4 Table 7 lists that are absent
     */
    public record RegistrationCertificate(
            String serialized,
            String subject,
            Optional<String> intermediary,
            Instant issuedAt,
            Optional<Instant> expiresAt,
            List<Object> credentials,
            List<String> missingMembers) {

        /** Payload members TS 119 475 V1.2.1 Table 7 requires of every registration certificate. */
        public static final List<String> TABLE_7_MEMBERS = List.of(
                "name",
                "sub",
                "country",
                "registry_uri",
                "srv_description",
                "entitlements",
                "privacy_policy",
                "info_uri",
                "support_uri",
                "supervisory_authority",
                "policy_id",
                "certificate_policy",
                "iat",
                "status");

        public RegistrationCertificate {
            Objects.requireNonNull(serialized, "serialized");
            Objects.requireNonNull(intermediary, "intermediary");
            Objects.requireNonNull(expiresAt, "expiresAt");
            credentials = List.copyOf(credentials);
            missingMembers = List.copyOf(missingMembers);
        }

        /**
         * Parses a registration certificate.
         *
         * @throws IllegalArgumentException if it is not a compact JWS with {@code typ} {@code rc-wrp+jwt}, an {@code
         *     x5c} header, {@code sub} and {@code iat}
         */
        public static RegistrationCertificate parse(String serialized) {
            String compact = serialized.strip();
            JWSObject jws;
            try {
                jws = JWSObject.parse(compact);
            } catch (ParseException e) {
                throw new IllegalArgumentException("registration certificate is not a compact JWS", e);
            }
            JOSEObjectType type = jws.getHeader().getType();
            if (type == null || !REGISTRATION_CERT_TYPE.equals(type.getType())) {
                throw new IllegalArgumentException("registration certificate typ must be " + REGISTRATION_CERT_TYPE);
            }
            if (jws.getHeader().getX509CertChain() == null
                    || jws.getHeader().getX509CertChain().isEmpty()) {
                throw new IllegalArgumentException("registration certificate has no x5c header");
            }
            Map<String, Object> claims = jws.getPayload().toJSONObject();
            if (claims == null) {
                throw new IllegalArgumentException("registration certificate payload is not a JSON object");
            }
            if (!(claims.get("sub") instanceof String subject) || subject.isEmpty()) {
                throw new IllegalArgumentException("registration certificate has no sub");
            }
            Instant issuedAt = time(claims.get("iat"))
                    .orElseThrow(() -> new IllegalArgumentException("registration certificate has no iat"));
            Optional<Instant> expiresAt = Optional.empty();
            if (claims.containsKey("exp")) {
                expiresAt = Optional.of(time(claims.get("exp"))
                        .orElseThrow(() -> new IllegalArgumentException("registration certificate exp is invalid")));
                if (!expiresAt.get().isAfter(issuedAt)) {
                    throw new IllegalArgumentException("registration certificate expires before it is issued");
                }
            }
            Optional<String> intermediary =
                    nestedSub(claims.get("intermediary")).or(() -> nestedSub(claims.get("act")));
            List<Object> credentials = claims.get("credentials") instanceof List<?> l ? new ArrayList<>(l) : List.of();
            List<String> missing = TABLE_7_MEMBERS.stream()
                    .filter(member -> claims.get(member) == null)
                    .toList();
            return new RegistrationCertificate(
                    compact, subject, intermediary, issuedAt, expiresAt, credentials, missing);
        }

        /** Whether the certificate may be sent at {@code now}: issued and not expired. */
        public boolean isCurrentAt(Instant now) {
            return !now.isBefore(issuedAt) && expiresAt.map(now::isBefore).orElse(true);
        }

        /** The {@code data} value of the {@code registration_cert} element (TS 119 472-2 RO-16). */
        public String base64url() {
            return Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(serialized.getBytes(StandardCharsets.US_ASCII));
        }

        /**
         * Whether the certificate names the holder of this access certificate, either as the relying party ({@code
         * sub}) or as its intermediary. The identifiers compared are the access certificate's {@code
         * organizationIdentifier} or {@code serialNumber} (TS 119 475 clause 5.1, GEN-5.1.1-04).
         */
        public boolean names(X509Certificate accessCertificate) {
            Set<String> ids = subjectIdentifiers(accessCertificate);
            return ids.contains(subject) || intermediary.map(ids::contains).orElse(false);
        }

        private static Optional<String> nestedSub(Object value) {
            return value instanceof Map<?, ?> m && m.get("sub") instanceof String s && !s.isEmpty()
                    ? Optional.of(s)
                    : Optional.empty();
        }

        private static Optional<Instant> time(Object value) {
            return value instanceof Number n && n.longValue() > 0
                    ? Optional.of(Instant.ofEpochSecond(n.longValue()))
                    : Optional.empty();
        }
    }

    /** The {@code organizationIdentifier} (2.5.4.97) and {@code serialNumber} (2.5.4.5) values of a subject. */
    public static Set<String> subjectIdentifiers(X509Certificate certificate) {
        Set<String> out = new LinkedHashSet<>();
        LdapName name;
        try {
            name = new LdapName(certificate.getSubjectX500Principal().getName(X500Principal.RFC2253));
        } catch (InvalidNameException e) {
            return out;
        }
        for (Rdn rdn : name.getRdns()) {
            String type = rdn.getType();
            if (type.equals("2.5.4.97") || type.equals("2.5.4.5") || type.equalsIgnoreCase("SERIALNUMBER")) {
                derString(rdn.getValue()).ifPresent(out::add);
            }
        }
        return out;
    }

    /** RFC 2253 renders attribute types without a keyword as the DER encoding of a string value. */
    private static Optional<String> derString(Object value) {
        if (value instanceof String s) {
            return Optional.of(s);
        }
        if (!(value instanceof byte[] der) || der.length < 2) {
            return Optional.empty();
        }
        int tag = der[0] & 0xff;
        int length = der[1] & 0xff;
        int offset = 2;
        if (length > 0x7f) {
            int bytes = length & 0x7f;
            if (bytes == 0 || bytes > 2 || der.length < 2 + bytes) {
                return Optional.empty();
            }
            length = 0;
            for (int i = 0; i < bytes; i++) {
                length = (length << 8) | (der[2 + i] & 0xff);
            }
            offset += bytes;
        }
        if (offset + length != der.length) {
            return Optional.empty();
        }
        return switch (tag) {
            case 0x0c -> Optional.of(new String(der, offset, length, StandardCharsets.UTF_8));
            case 0x13, 0x16 -> Optional.of(new String(der, offset, length, StandardCharsets.US_ASCII));
            default -> Optional.empty();
        };
    }
}
