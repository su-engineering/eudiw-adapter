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

import io.github.suengineering.eudiw.core.cbor.CborEncoder;
import io.github.suengineering.eudiw.core.cbor.CborItem;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;
import java.util.Optional;

/** Session transcripts for mdoc presentations over OpenID4VP. */
public final class SessionTranscripts {

    private SessionTranscripts() {}

    /**
     * The session transcript for a request invoked by redirect (OpenID4VP 1.0 Appendix B.2.6.1): device engagement
     * and reader key are null, and the handover is {@code ["OpenID4VPHandover", sha-256(OpenID4VPHandoverInfo)]}
     * with {@code OpenID4VPHandoverInfo = [client_id, nonce, jwk_thumbprint, response_uri]}.
     *
     * @param clientId the {@code client_id} of the request, Client Identifier Prefix included
     * @param nonce the {@code nonce} of the request
     * @param encryptionKeyThumbprint the SHA-256 JWK thumbprint (RFC 7638) of the key the response was encrypted
     *     to, or empty for an unencrypted response
     * @param responseUri the {@code response_uri} (or {@code redirect_uri}) of the request
     */
    public static CborItem openId4VpRedirect(
            String clientId, String nonce, Optional<byte[]> encryptionKeyThumbprint, String responseUri) {
        Objects.requireNonNull(clientId, "clientId");
        Objects.requireNonNull(nonce, "nonce");
        Objects.requireNonNull(responseUri, "responseUri");
        CborItem info = CborEncoder.array(
                CborEncoder.text(clientId),
                CborEncoder.text(nonce),
                encryptionKeyThumbprint.<CborItem>map(CborEncoder::bytes).orElseGet(CborEncoder::nil),
                CborEncoder.text(responseUri));
        CborItem handover =
                CborEncoder.array(CborEncoder.text("OpenID4VPHandover"), CborEncoder.bytes(sha256(info.encoded())));
        return CborEncoder.array(CborEncoder.nil(), CborEncoder.nil(), handover);
    }

    /** The {@code OpenID4VPHandoverInfo} structure alone, exposed for tests against the specification's examples. */
    static CborItem handoverInfo(
            String clientId, String nonce, Optional<byte[]> encryptionKeyThumbprint, String responseUri) {
        return CborEncoder.array(
                CborEncoder.text(clientId),
                CborEncoder.text(nonce),
                encryptionKeyThumbprint.<CborItem>map(CborEncoder::bytes).orElseGet(CborEncoder::nil),
                CborEncoder.text(responseUri));
    }

    private static byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
