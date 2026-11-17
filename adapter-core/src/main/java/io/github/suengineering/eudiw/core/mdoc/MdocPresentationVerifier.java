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
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Verifies one {@code mso_mdoc} presentation of a VP Token: a base64url DeviceResponse (OpenID4VP 1.0 Appendix
 * B.2.5) holding exactly one document, as HAIP 1.0 section 5.3.1 requires, of the requested doctype. The document
 * passes issuer data authentication and then mdoc authentication over the session transcript.
 */
public final class MdocPresentationVerifier {

    /** Largest DeviceResponse accepted, after base64url decoding. */
    public static final int MAX_BYTES = 512 * 1024;

    private final MdocIssuerVerifier issuerVerifier;
    private final MdocDeviceAuthentication deviceAuthentication;

    public MdocPresentationVerifier(MdocIssuerVerifier issuerVerifier, MdocDeviceAuthentication deviceAuthentication) {
        this.issuerVerifier = Objects.requireNonNull(issuerVerifier, "issuerVerifier");
        this.deviceAuthentication = Objects.requireNonNull(deviceAuthentication, "deviceAuthentication");
    }

    /**
     * @param presentation the base64url DeviceResponse from the VP Token
     * @param doctype the doctype the Credential Query asked for
     * @param sessionTranscript the session transcript of this request
     * @return the verified document, its issuer-signed elements as JSON-compatible values
     * @throws VerificationFailure when any check fails
     */
    public VerifiedMdoc verify(String presentation, String doctype, CborItem sessionTranscript) {
        byte[] bytes;
        try {
            bytes = Base64.getUrlDecoder().decode(presentation);
        } catch (IllegalArgumentException e) {
            throw new VerificationFailure("malformed_credential", "DeviceResponse is not base64url");
        }
        if (bytes.length > MAX_BYTES) {
            throw new VerificationFailure("malformed_credential", "DeviceResponse too large");
        }
        CborItem.MapItem response = MdocCbor.map(CborDecoder.decode(bytes), "DeviceResponse");
        List<CborItem> documents = response.get("documents")
                .map(d -> MdocCbor.array(d, "documents").items())
                .orElseThrow(() -> new VerificationFailure("malformed_credential", "DeviceResponse has no documents"));
        if (documents.size() != 1) {
            throw new VerificationFailure(
                    "malformed_credential", "a DeviceResponse must carry exactly one document (HAIP 1.0)");
        }
        CborItem.MapItem document = MdocCbor.map(documents.get(0), "Document");
        if (!MdocCbor.text(document, "docType").equals(doctype)) {
            throw new VerificationFailure("credential_type_not_allowed", "document is not of the requested doctype");
        }
        VerifiedIssuerSigned issuerSigned = issuerVerifier.verify(document);
        deviceAuthentication.authenticate(document, issuerSigned, sessionTranscript);
        return new VerifiedMdoc(issuerSigned, json(issuerSigned.elements()));
    }

    /**
     * @param issuerSigned the issuer-verified part
     * @param claims issuer-signed elements per namespace, as JSON-compatible values for DCQL and policy output
     */
    public record VerifiedMdoc(VerifiedIssuerSigned issuerSigned, Map<String, Object> claims) {}

    private static Map<String, Object> json(Map<String, Map<String, CborItem>> elements) {
        Map<String, Object> out = new LinkedHashMap<>();
        elements.forEach((ns, values) -> {
            Map<String, Object> m = new LinkedHashMap<>();
            values.forEach((element, value) -> m.put(element, MdocValues.toJson(value)));
            out.put(ns, Collections.unmodifiableMap(m));
        });
        return Collections.unmodifiableMap(out);
    }

    /** Converts element values for DCQL and output: dates to their text, byte strings to base64url. */
    static final class MdocValues {
        private MdocValues() {}

        static Object toJson(CborItem item) {
            return switch (item) {
                case CborItem.Text t -> t.value();
                case CborItem.Int i -> i.asLong().<Object>map(l -> l).orElse(i.value());
                case CborItem.Bytes b -> Base64.getUrlEncoder().withoutPadding().encodeToString(b.value());
                case CborItem.Float f -> f.value();
                case CborItem.Simple s ->
                    switch (s.value()) {
                        case CborItem.Simple.TRUE -> Boolean.TRUE;
                        case CborItem.Simple.FALSE -> Boolean.FALSE;
                        default -> null;
                    };
                // Tagged dates (tag 0 date-time, tag 1004 full-date) and other tags: the content.
                case CborItem.Tag t -> toJson(t.content());
                case CborItem.Array a -> {
                    List<Object> list = new ArrayList<>();
                    a.items().forEach(i -> list.add(toJson(i)));
                    yield Collections.unmodifiableList(list);
                }
                case CborItem.MapItem m -> {
                    Map<String, Object> map = new LinkedHashMap<>();
                    m.entries()
                            .forEach((k, v) -> map.put(
                                    k instanceof CborItem.Text t ? t.value() : String.valueOf(toJson(k)), toJson(v)));
                    yield Collections.unmodifiableMap(map);
                }
            };
        }
    }
}
