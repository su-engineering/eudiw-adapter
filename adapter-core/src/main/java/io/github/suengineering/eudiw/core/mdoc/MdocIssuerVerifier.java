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
import io.github.suengineering.eudiw.core.cbor.CborItem;
import io.github.suengineering.eudiw.core.cose.CoseSign1;
import io.github.suengineering.eudiw.core.x509.CertificateChainValidator;
import io.github.suengineering.eudiw.core.x509.CrlRevocationChecker;
import io.github.suengineering.eudiw.core.x509.TrustStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;
import java.util.function.Supplier;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

/**
 * Issuer data authentication of one mdoc Document, following the reader's inspection procedure of ISO/IEC
 * 18013-5:2021 clause 9.3.1:
 *
 * <ol>
 *   <li>the document signer certificate in the {@code x5chain} validates to a trust anchor (clause 9.3.3);
 *   <li>the issuer's COSE_Sign1 over the MSO verifies with that certificate's key;
 *   <li>every returned issuer-signed item has its digest in the MSO;
 *   <li>the MSO's document type is the document's;
 *   <li>the MSO was signed while the certificate was valid, and is valid now.
 * </ol>
 */
public final class MdocIssuerVerifier {

    /** Extended key usage of an mDL document signer certificate (ISO/IEC 18013-5:2021 Annex B). */
    public static final String MDL_DS_EKU = "1.0.18013.5.1.2";

    /** The mDL document type, to which the IACA certificate profile applies by default (ADR-012). */
    public static final String MDL_DOCTYPE = "org.iso.18013.5.1.mDL";

    private final Supplier<TrustStore> trustStore;
    private final Clock clock;
    private final Duration clockSkew;
    private final CrlRevocationChecker revocation;
    private final Predicate<String> iacaProfile;

    /**
     * @param trustStore current trusted certificates, consulted on every call
     * @param clock time source
     * @param clockSkew tolerance for the MSO validity checks
     * @param revocation CRL checks for the document signer chain, or {@code null} for none
     * @param iacaProfile document types for which the IACA certificate profile is enforced
     */
    public MdocIssuerVerifier(
            Supplier<TrustStore> trustStore,
            Clock clock,
            Duration clockSkew,
            CrlRevocationChecker revocation,
            Predicate<String> iacaProfile) {
        this.trustStore = Objects.requireNonNull(trustStore, "trustStore");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.clockSkew = Objects.requireNonNull(clockSkew, "clockSkew");
        this.revocation = revocation;
        this.iacaProfile = Objects.requireNonNull(iacaProfile, "iacaProfile");
    }

    /** The IACA profile for the mDL document type only. */
    public static Predicate<String> mdlOnly() {
        return MDL_DOCTYPE::equals;
    }

    /**
     * Verifies a Document's {@code issuerSigned} part.
     *
     * @param document a Document of a DeviceResponse (clause 8.3.2.1.2.2)
     * @return the verified issuer-signed elements
     * @throws VerificationFailure with a stable code when any step fails
     */
    public VerifiedIssuerSigned verify(CborItem document) {
        CborItem.MapItem doc = MdocCbor.map(document, "Document");
        String docType = MdocCbor.text(doc, "docType");
        CborItem.MapItem issuerSigned = MdocCbor.map(MdocCbor.field(doc, "issuerSigned"), "issuerSigned");
        CoseSign1 issuerAuth = CoseSign1.parse(MdocCbor.field(issuerSigned, "issuerAuth"));

        // 1. Certificate path.
        List<X509Certificate> chain = CertificateChainValidator.parse(issuerAuth.x5chain());
        Instant now = clock.instant();
        TrustStore store = trustStore.get();
        CertificateChainValidator.ValidatedPath path =
                CertificateChainValidator.validatePath(chain, store.anchors(), now);
        if (revocation != null) {
            revocation.check(chain, path.anchor());
        }

        // 2. Signature over the MSO, then the MSO itself.
        issuerAuth.verify(path.leaf().getPublicKey());
        MobileSecurityObject mso =
                MobileSecurityObject.parse(issuerAuth.payload().orElseThrow());

        // 4. Document type. Checked before the profile, which depends on it.
        if (!mso.docType().equals(docType)) {
            throw new VerificationFailure("credential_mismatch", "MSO docType differs from the document");
        }
        if (iacaProfile.test(docType)) {
            requireIacaProfile(path.leaf(), path.anchor());
        }

        // 3. Digests of the returned elements.
        Map<String, Map<String, CborItem>> elements = issuerSignedElements(issuerSigned, mso);

        // 5. Validity.
        if (mso.signed().isBefore(path.leaf().getNotBefore().toInstant())
                || mso.signed().isAfter(path.leaf().getNotAfter().toInstant())) {
            throw new VerificationFailure(
                    "certificate_chain_invalid", "MSO was signed outside the certificate validity");
        }
        if (now.plus(clockSkew).isBefore(mso.validFrom())) {
            throw new VerificationFailure("credential_not_yet_valid", "MSO is not yet valid");
        }
        if (now.minus(clockSkew).isAfter(mso.validUntil())) {
            throw new VerificationFailure("credential_expired", "MSO has expired");
        }
        return new VerifiedIssuerSigned(docType, elements, mso, chain, store.sourcesOf(path.anchor()));
    }

    private static Map<String, Map<String, CborItem>> issuerSignedElements(
            CborItem.MapItem issuerSigned, MobileSecurityObject mso) {
        Map<String, Map<String, CborItem>> out = new LinkedHashMap<>();
        Optional<CborItem> nameSpaces = issuerSigned.get("nameSpaces");
        if (nameSpaces.isEmpty()) {
            return Map.of();
        }
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance(mso.digestAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        for (Map.Entry<CborItem, CborItem> ns :
                MdocCbor.map(nameSpaces.get(), "IssuerNameSpaces").entries().entrySet()) {
            String namespace = MdocCbor.text(ns.getKey(), "NameSpace");
            Map<Long, byte[]> expected = mso.valueDigests().get(namespace);
            if (expected == null) {
                throw new VerificationFailure("invalid_disclosure", "namespace has no digests in the MSO");
            }
            Map<String, CborItem> values = new LinkedHashMap<>();
            Set<Long> seenIds = new HashSet<>();
            for (CborItem itemBytes :
                    MdocCbor.array(ns.getValue(), "IssuerSignedItems").items()) {
                CborItem.MapItem item = MdocCbor.map(MdocCbor.embedded(itemBytes, "IssuerSignedItemBytes"), "item");
                long digestId = MdocCbor.unsigned(MdocCbor.field(item, "digestID"), "digestID");
                if (!(MdocCbor.field(item, "random") instanceof CborItem.Bytes)) {
                    throw MdocCbor.malformed("random is not a byte string");
                }
                String element = MdocCbor.text(item, "elementIdentifier");
                CborItem value = MdocCbor.field(item, "elementValue");
                byte[] want = expected.get(digestId);
                // The digest covers the tagged byte string exactly as received (clause 9.1.2.5).
                if (want == null || !MessageDigest.isEqual(want, digest.digest(itemBytes.encoded()))) {
                    throw new VerificationFailure("invalid_disclosure", "issuer-signed item digest mismatch");
                }
                if (!seenIds.add(digestId) || values.putIfAbsent(element, value) != null) {
                    throw new VerificationFailure("duplicate_disclosure", "issuer-signed item repeated");
                }
            }
            out.put(namespace, Collections.unmodifiableMap(values));
        }
        return Collections.unmodifiableMap(out);
    }

    /**
     * The IACA rules of clause 9.3.3 and Annex B: same country (and state or province, when both name one) in the
     * anchor and the document signer, and the document signer extended key usage.
     */
    private static void requireIacaProfile(X509Certificate signer, X509Certificate anchor) {
        if (signer.equals(anchor)) {
            throw new VerificationFailure("certificate_chain_invalid", "the document signer must be issued by an IACA");
        }
        try {
            List<String> eku = signer.getExtendedKeyUsage();
            if (eku == null || !eku.contains(MDL_DS_EKU)) {
                throw new VerificationFailure(
                        "certificate_chain_invalid", "document signer lacks the mDL DS extended key usage");
            }
        } catch (CertificateParsingException e) {
            throw new VerificationFailure("certificate_chain_invalid", "extended key usage cannot be read", e);
        }
        Map<String, String> s = names(signer);
        Map<String, String> a = names(anchor);
        if (a.get("C") == null || !a.get("C").equals(s.get("C"))) {
            throw new VerificationFailure("certificate_chain_invalid", "document signer country differs from IACA");
        }
        if (a.containsKey("ST") && s.containsKey("ST") && !a.get("ST").equals(s.get("ST"))) {
            throw new VerificationFailure("certificate_chain_invalid", "document signer state differs from IACA");
        }
    }

    private static Map<String, String> names(X509Certificate certificate) {
        Map<String, String> out = new LinkedHashMap<>();
        try {
            for (Rdn rdn : new LdapName(certificate.getSubjectX500Principal().getName()).getRdns()) {
                out.putIfAbsent(rdn.getType().toUpperCase(java.util.Locale.ROOT), String.valueOf(rdn.getValue()));
            }
        } catch (InvalidNameException e) {
            throw new VerificationFailure("certificate_chain_invalid", "subject cannot be parsed", e);
        }
        return out;
    }
}
