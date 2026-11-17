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
import io.github.suengineering.eudiw.core.cbor.CborEncoder;
import io.github.suengineering.eudiw.core.cbor.CborItem;
import io.github.suengineering.eudiw.core.cose.CoseKeys;
import io.github.suengineering.eudiw.core.cose.CoseSign1;
import java.security.PublicKey;
import java.util.Map;

/**
 * mdoc authentication by device signature (ISO/IEC 18013-5:2021 clauses 9.1.3.4 and 9.1.3.6).
 *
 * <p>The device signs, detached, the embedded CBOR of {@code ["DeviceAuthentication", SessionTranscript, DocType,
 * DeviceNameSpacesBytes]} with the key the issuer bound in the MSO. The verifier rebuilds that structure from this
 * request's session transcript and the bytes it received, so a presentation made for another request, another
 * document or other device-signed elements does not verify.
 *
 * <p>Device MAC (clause 9.1.3.5) is refused. Its key comes from ECDH between the device key and the reader's
 * ephemeral key, and an OpenID4VP session transcript carries no reader key, so a MAC cannot be checked in this flow.
 * This is a profile restriction of this verifier, recorded in ADR-012.
 */
public final class DeviceSignatureAuthentication implements MdocDeviceAuthentication {

    /** The context string of the DeviceAuthentication structure (clause 9.1.3.4). */
    static final String CONTEXT = "DeviceAuthentication";

    @Override
    public void authenticate(CborItem.MapItem document, VerifiedIssuerSigned issuerSigned, CborItem sessionTranscript) {
        CborItem.MapItem deviceSigned = MdocCbor.map(MdocCbor.field(document, "deviceSigned"), "deviceSigned");
        // DeviceNameSpacesBytes: mandatory, even when the map inside is empty.
        CborItem nameSpacesBytes = MdocCbor.field(deviceSigned, "nameSpaces");
        CborItem.MapItem nameSpaces =
                MdocCbor.map(MdocCbor.embedded(nameSpacesBytes, "DeviceNameSpacesBytes"), "DeviceNameSpaces");
        CborItem.MapItem deviceAuth = MdocCbor.map(MdocCbor.field(deviceSigned, "deviceAuth"), "deviceAuth");
        boolean signature = deviceAuth.get("deviceSignature").isPresent();
        boolean mac = deviceAuth.get("deviceMac").isPresent();
        if (signature == mac) {
            throw MdocCbor.malformed("deviceAuth must hold exactly one of deviceSignature and deviceMac");
        }
        if (mac) {
            throw new VerificationFailure(
                    "holder_binding_invalid",
                    "device MAC cannot be verified without a reader key; a device signature is required");
        }

        requireAuthorized(nameSpaces, issuerSigned.mso());

        PublicKey deviceKey = CoseKeys.publicKey(issuerSigned.mso().deviceKey());
        CoseSign1 deviceSignature = CoseSign1.parse(MdocCbor.field(deviceAuth, "deviceSignature"));
        // The namespaces go in exactly as received; the structure around them has no maps, so it encodes one way.
        byte[] content = CborEncoder.embedded(CborEncoder.array(
                        CborEncoder.text(CONTEXT),
                        sessionTranscript,
                        CborEncoder.text(issuerSigned.docType()),
                        nameSpacesBytes))
                .encoded();
        try {
            deviceSignature.verifyDetached(deviceKey, content);
        } catch (VerificationFailure e) {
            if (!e.code().equals("invalid_signature")) {
                throw e;
            }
            throw new VerificationFailure("holder_binding_invalid", "device signature does not verify", e);
        }
    }

    /**
     * Every device-signed element must be covered by the key authorizations of the MSO, by namespace or by element
     * (clause 9.1.2.4). Without authorizations no element may be device-signed; an empty map needs none.
     */
    private static void requireAuthorized(CborItem.MapItem nameSpaces, MobileSecurityObject mso) {
        for (Map.Entry<CborItem, CborItem> ns : nameSpaces.entries().entrySet()) {
            String namespace = MdocCbor.text(ns.getKey(), "NameSpace");
            for (CborItem element :
                    MdocCbor.map(ns.getValue(), "DeviceSignedItems").entries().keySet()) {
                if (!mso.deviceKeyAuthorized(namespace, MdocCbor.text(element, "DataElementIdentifier"))) {
                    throw new VerificationFailure(
                            "holder_binding_invalid", "device-signed element not authorized for the device key");
                }
            }
        }
    }
}
