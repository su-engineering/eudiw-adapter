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

import io.github.suengineering.eudiw.core.VerificationFailure;
import io.github.suengineering.eudiw.core.cbor.CborDecoder;
import io.github.suengineering.eudiw.core.cbor.CborItem;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * The mobile security object (ISO/IEC 18013-5:2021 clause 9.1.2.4): the issuer-signed digests of an mdoc's data
 * elements, the device key, the document type and the validity period.
 *
 * @param digestAlgorithm JCA name of the digest algorithm
 * @param valueDigests digest per namespace and digest ID
 * @param deviceKey the device key as a COSE_Key
 * @param authorizedNamespaces namespaces the device key may sign in full
 * @param authorizedElements data elements the device key may sign, per namespace
 * @param docType document type
 * @param signed when the MSO was signed
 * @param validFrom start of validity
 * @param validUntil end of validity
 * @param statusListReference the MSO's Token Status List reference as {@code {"status_list": {"idx", "uri"}}}, when
 *     it has one
 * @param statusPresent whether the MSO carries a status reference, which is not interpreted (ADR-012)
 */
public record MobileSecurityObject(
        String digestAlgorithm,
        Map<String, Map<Long, byte[]>> valueDigests,
        CborItem deviceKey,
        Set<String> authorizedNamespaces,
        Map<String, Set<String>> authorizedElements,
        String docType,
        Instant signed,
        Instant validFrom,
        Instant validUntil,
        Optional<Map<String, Object>> statusListReference,
        boolean statusPresent) {

    private static final Map<String, String> DIGESTS = Map.of(
            "SHA-256", "SHA-256",
            "SHA-384", "SHA-384",
            "SHA-512", "SHA-512");

    /**
     * Parses the payload of the issuer's COSE_Sign1: an embedded CBOR byte string (tag 24) holding the MSO.
     *
     * @throws VerificationFailure {@code malformed_credential} for a structure that is not a valid MSO
     */
    public static MobileSecurityObject parse(byte[] payload) {
        CborItem.MapItem mso = MdocCbor.map(MdocCbor.embedded(CborDecoder.decode(payload), "MSO"), "MSO");
        String version = MdocCbor.text(mso, "version");
        if (!version.equals("1") && !version.startsWith("1.")) {
            throw MdocCbor.malformed("unsupported MSO version");
        }
        String algorithm = DIGESTS.get(MdocCbor.text(mso, "digestAlgorithm"));
        if (algorithm == null) {
            throw new VerificationFailure("unsupported_hash_algorithm", "unsupported MSO digest algorithm");
        }

        Map<String, Map<Long, byte[]>> digests = new LinkedHashMap<>();
        for (Map.Entry<CborItem, CborItem> ns : MdocCbor.map(MdocCbor.field(mso, "valueDigests"), "valueDigests")
                .entries()
                .entrySet()) {
            Map<Long, byte[]> ids = new LinkedHashMap<>();
            for (Map.Entry<CborItem, CborItem> d :
                    MdocCbor.map(ns.getValue(), "DigestIDs").entries().entrySet()) {
                long id = MdocCbor.unsigned(d.getKey(), "DigestID");
                if (!(d.getValue() instanceof CborItem.Bytes digest)) {
                    throw MdocCbor.malformed("digest is not a byte string");
                }
                ids.put(id, digest.value());
            }
            digests.put(MdocCbor.text(ns.getKey(), "NameSpace"), Collections.unmodifiableMap(ids));
        }

        CborItem.MapItem keyInfo = MdocCbor.map(MdocCbor.field(mso, "deviceKeyInfo"), "deviceKeyInfo");
        CborItem deviceKey = MdocCbor.field(keyInfo, "deviceKey");
        Set<String> namespaces = new LinkedHashSet<>();
        Map<String, Set<String>> elements = new LinkedHashMap<>();
        Optional<CborItem> authorizations = keyInfo.get("keyAuthorizations");
        if (authorizations.isPresent()) {
            CborItem.MapItem auth = MdocCbor.map(authorizations.get(), "keyAuthorizations");
            auth.get("nameSpaces").ifPresent(list -> MdocCbor.array(list, "AuthorizedNameSpaces")
                    .items()
                    .forEach(n -> namespaces.add(MdocCbor.text(n, "NameSpace"))));
            auth.get("dataElements").ifPresent(map -> MdocCbor.map(map, "AuthorizedDataElements")
                    .entries()
                    .forEach((ns, ids) -> {
                        Set<String> set = new LinkedHashSet<>();
                        MdocCbor.array(ids, "DataElementsArray")
                                .items()
                                .forEach(i -> set.add(MdocCbor.text(i, "DataElementIdentifier")));
                        elements.put(MdocCbor.text(ns, "NameSpace"), Set.copyOf(set));
                    }));
        }

        CborItem.MapItem validity = MdocCbor.map(MdocCbor.field(mso, "validityInfo"), "validityInfo");
        Instant signed = tdate(MdocCbor.field(validity, "signed"));
        Instant validFrom = tdate(MdocCbor.field(validity, "validFrom"));
        Instant validUntil = tdate(MdocCbor.field(validity, "validUntil"));
        // How validFrom and validUntil relate to signed is an issuer rule; the reader checks each against the
        // certificate and the current time (clause 9.3.1 step 5), so an issuer that rounds dates is not refused.
        return new MobileSecurityObject(
                algorithm,
                Collections.unmodifiableMap(digests),
                deviceKey,
                Collections.unmodifiableSet(namespaces),
                Collections.unmodifiableMap(elements),
                MdocCbor.text(mso, "docType"),
                signed,
                validFrom,
                validUntil,
                statusListReference(mso.get("status")),
                mso.get("status").isPresent());
    }

    /**
     * The Token Status List reference of an MSO (Token Status List section 6.3, as carried in the MSO's {@code status}):
     * {@code status_list} with an unsigned {@code idx} and a text {@code uri}. Another status mechanism yields empty;
     * a malformed {@code status_list} is refused.
     */
    private static Optional<Map<String, Object>> statusListReference(Optional<CborItem> status) {
        if (status.isEmpty()) {
            return Optional.empty();
        }
        Optional<CborItem> reference = MdocCbor.map(status.get(), "status").get("status_list");
        if (reference.isEmpty()) {
            return Optional.empty();
        }
        CborItem.MapItem list = MdocCbor.map(reference.get(), "status_list");
        long idx = MdocCbor.unsigned(MdocCbor.field(list, "idx"), "status_list.idx");
        String uri = MdocCbor.text(list, "uri");
        return Optional.of(Map.of("status_list", Map.of("idx", idx, "uri", uri)));
    }

    /** Whether the device key may sign the given data element (clause 9.1.2.4, key authorizations). */
    public boolean deviceKeyAuthorized(String namespace, String element) {
        return authorizedNamespaces.contains(namespace)
                || authorizedElements.getOrDefault(namespace, Set.of()).contains(element);
    }

    /** A {@code tdate}: tag 0 with an RFC 3339 date-time. */
    private static Instant tdate(CborItem item) {
        if (!(item instanceof CborItem.Tag tag) || tag.number() != 0 || !(tag.content() instanceof CborItem.Text t)) {
            throw MdocCbor.malformed("MSO date is not a tdate");
        }
        try {
            return Instant.parse(t.value());
        } catch (DateTimeParseException e) {
            throw MdocCbor.malformed("MSO date cannot be parsed");
        }
    }
}
