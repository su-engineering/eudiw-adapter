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
package io.github.suengineering.eudiw.core.trust;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import io.github.suengineering.eudiw.core.VerificationFailure;
import io.github.suengineering.eudiw.core.jose.AlgorithmPolicy;
import io.github.suengineering.eudiw.core.jose.JwsSignatureVerifier;
import io.github.suengineering.eudiw.core.json.Json;
import io.github.suengineering.eudiw.core.x509.CertificateKeys;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Verifies and reads an ETSI TS 119 602 V1.1.1 list of trusted entities in the JSON binding (Annex A.1), signed
 * with a compact JAdES baseline B signature (ETSI TS 119 182-1 V1.2.1), as Annex D to I require for the EU lists.
 *
 * <p>The signing certificate is taken from {@code x5c} or matched by {@code x5t#S256} and must be one of the
 * allowed signer certificates. Detached payloads ({@code sigD}) and unencoded payloads ({@code b64}) are rejected;
 * {@code crit} may list only {@code sigT}. A {@code sigT} claimed signing time must be a UTC date-time, not in
 * the future, and inside the signing certificate's validity.
 */
public final class LoteJsonParser {

    /** Maximum accepted size of a list in bytes. */
    public static final int MAX_BYTES = 16 * 1024 * 1024;

    private static final Set<String> UNDERSTOOD_CRITICAL = Set.of("sigT");

    /** Clock difference tolerated between the list signer and this host for {@code sigT}. */
    static final java.time.Duration SIGNING_TIME_SKEW = java.time.Duration.ofMinutes(5);

    private LoteJsonParser() {}

    /**
     * @param signed the compact JWS
     * @param location where the list came from; becomes its identifier
     * @param allowedSigners certificates allowed to sign this list
     * @throws VerificationFailure {@code trusted_list_invalid}, {@code trusted_list_signature_invalid} or {@code
     *     trusted_list_signer_untrusted}
     */
    public static TrustedList verify(byte[] signed, String location, Collection<X509Certificate> allowedSigners) {
        if (signed.length > MAX_BYTES) {
            throw new VerificationFailure(ListRules.INVALID, "trusted list too large");
        }
        JWSObject jws;
        try {
            jws = JWSObject.parse(new String(signed, StandardCharsets.US_ASCII).strip());
        } catch (ParseException e) {
            throw new VerificationFailure(ListRules.INVALID, "trusted list is not a compact JWS", e);
        }
        JWSHeader header = jws.getHeader();
        if (header.getCustomParam("sigD") != null) {
            throw new VerificationFailure(ListRules.INVALID, "detached JAdES signatures are not supported");
        }
        if (!header.isBase64URLEncodePayload()) {
            throw new VerificationFailure(ListRules.INVALID, "unencoded JWS payloads are not supported");
        }
        X509Certificate signer = signer(header, allowedSigners);
        ListRules.checkPinned(signer, allowedSigners);
        checkSigningTime(header.getCustomParam("sigT"), signer);
        try {
            JwsSignatureVerifier.verify(
                    jws, CertificateKeys.publicJwk(signer), AlgorithmPolicy.TRUSTED_LISTS, UNDERSTOOD_CRITICAL);
        } catch (VerificationFailure e) {
            throw new VerificationFailure(ListRules.SIGNATURE_INVALID, "trusted list signature is invalid", e);
        }

        Map<String, Object> root = Json.parseObject(jws.getPayload().toString(), ListRules.INVALID);
        Map<String, Object> lote = object(root, "LoTE");
        Map<String, Object> scheme = object(lote, "ListAndSchemeInformation");
        Instant issued = ListRules.instant(string(scheme, "ListIssueDateTime"));
        Optional<Instant> nextUpdate = scheme.get("NextUpdate") == null
                ? Optional.empty()
                : Optional.of(ListRules.instant(string(scheme, "NextUpdate")));
        ListRules.checkDates(issued, nextUpdate);
        ListRules.checkSignerValidity(signer, issued);

        List<TrustedList.Service> services = new ArrayList<>();
        for (Object entity : optionalArray(lote, "TrustedEntitiesList")) {
            Map<String, Object> trustedEntity = asObject(entity);
            String name = name(array(object(trustedEntity, "TrustedEntityInformation"), "TEName"));
            for (Object service : array(trustedEntity, "TrustedEntityServices")) {
                Map<String, Object> information = object(asObject(service), "ServiceInformation");
                services.add(new TrustedList.Service(
                        name,
                        optionalString(information, "ServiceTypeIdentifier"),
                        optionalString(information, "ServiceStatus"),
                        certificates(object(information, "ServiceDigitalIdentity"))));
            }
        }
        List<TrustedList.Pointer> pointers = new ArrayList<>();
        for (Object pointer : optionalArray(scheme, "PointersToOtherLoTE")) {
            Map<String, Object> other = asObject(pointer);
            List<X509Certificate> signers = new ArrayList<>();
            for (Object identity : array(other, "ServiceDigitalIdentities")) {
                signers.addAll(certificates(asObject(identity)));
            }
            Map<String, Object> qualifier =
                    asObject(array(other, "LoTEQualifiers").get(0));
            pointers.add(new TrustedList.Pointer(
                    string(other, "LoTELocation"),
                    optionalString(qualifier, "LoTEType"),
                    optionalString(qualifier, "SchemeTerritory"),
                    optionalString(qualifier, "MimeType"),
                    signers));
        }
        return new TrustedList(
                location,
                TrustedList.Format.LOTE_JSON,
                optionalString(scheme, "LoTEType"),
                optionalString(scheme, "SchemeTerritory"),
                integer(scheme, "LoTESequenceNumber"),
                issued,
                nextUpdate,
                services,
                pointers,
                signer);
    }

    /** ETSI TS 119 182-1 clause 5.2.1: {@code sigT} is the claimed signing time, a UTC date-time. */
    private static void checkSigningTime(Object sigT, X509Certificate signer) {
        if (sigT == null) {
            return;
        }
        if (!(sigT instanceof String value)) {
            throw new VerificationFailure(ListRules.INVALID, "sigT must be a date-time string");
        }
        Instant signed = ListRules.instant(value);
        if (signed.isAfter(Instant.now().plus(SIGNING_TIME_SKEW))) {
            throw new VerificationFailure(ListRules.INVALID, "sigT is in the future");
        }
        ListRules.checkSignerValidity(signer, signed);
    }

    private static X509Certificate signer(JWSHeader header, Collection<X509Certificate> allowedSigners) {
        List<Base64> x5c = header.getX509CertChain();
        Base64URL thumbprint = header.getX509CertSHA256Thumbprint();
        if (x5c != null && !x5c.isEmpty()) {
            X509Certificate certificate = ListRules.certificate(x5c.get(0).decode());
            if (thumbprint != null && !thumbprint.equals(sha256(certificate))) {
                throw new VerificationFailure(ListRules.INVALID, "x5t#S256 does not match x5c");
            }
            return certificate;
        }
        if (thumbprint != null) {
            for (X509Certificate candidate : allowedSigners) {
                if (thumbprint.equals(sha256(candidate))) {
                    return candidate;
                }
            }
            throw new VerificationFailure(
                    ListRules.SIGNER_UNTRUSTED, "trusted list signed by an unexpected certificate");
        }
        throw new VerificationFailure(ListRules.INVALID, "JAdES signature does not identify its signing certificate");
    }

    private static Base64URL sha256(X509Certificate certificate) {
        try {
            return Base64URL.encode(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()));
        } catch (NoSuchAlgorithmException | CertificateEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    private static List<X509Certificate> certificates(Map<String, Object> identity) {
        List<X509Certificate> result = new ArrayList<>();
        for (Object entry : optionalArray(identity, "X509Certificates")) {
            byte[] der;
            try {
                der = java.util.Base64.getMimeDecoder().decode(string(asObject(entry), "val"));
            } catch (IllegalArgumentException e) {
                throw new VerificationFailure(ListRules.INVALID, "certificate is not base64", e);
            }
            result.add(ListRules.certificate(der));
        }
        return result;
    }

    /** The English value of a multilingual name, or the first one. */
    private static String name(List<Object> values) {
        String first = null;
        for (Object value : values) {
            Map<String, Object> entry = asObject(value);
            String text = string(entry, "value");
            if ("en".equalsIgnoreCase(String.valueOf(entry.get("lang")))) {
                return text;
            }
            if (first == null) {
                first = text;
            }
        }
        if (first == null) {
            throw new VerificationFailure(ListRules.INVALID, "empty name");
        }
        return first;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asObject(Object value) {
        if (value instanceof Map<?, ?> map) {
            return (Map<String, Object>) map;
        }
        throw new VerificationFailure(ListRules.INVALID, "expected a JSON object");
    }

    private static Map<String, Object> object(Map<String, Object> parent, String name) {
        Object value = parent.get(name);
        if (value == null) {
            throw new VerificationFailure(ListRules.INVALID, "missing " + name);
        }
        return asObject(value);
    }

    @SuppressWarnings("unchecked")
    private static List<Object> array(Map<String, Object> parent, String name) {
        Object value = parent.get(name);
        if (value instanceof List<?> list && !list.isEmpty()) {
            return (List<Object>) list;
        }
        throw new VerificationFailure(ListRules.INVALID, "missing or empty " + name);
    }

    private static List<Object> optionalArray(Map<String, Object> parent, String name) {
        return parent.containsKey(name) ? array(parent, name) : List.of();
    }

    private static String string(Map<String, Object> parent, String name) {
        if (parent.get(name) instanceof String s && !s.isEmpty()) {
            return s;
        }
        throw new VerificationFailure(ListRules.INVALID, "missing or non-string " + name);
    }

    private static Optional<String> optionalString(Map<String, Object> parent, String name) {
        return parent.containsKey(name) ? Optional.of(string(parent, name)) : Optional.empty();
    }

    private static long integer(Map<String, Object> parent, String name) {
        if (parent.get(name) instanceof Number n && n.doubleValue() == n.longValue()) {
            return n.longValue();
        }
        throw new VerificationFailure(ListRules.INVALID, "missing or non-integer " + name);
    }
}
