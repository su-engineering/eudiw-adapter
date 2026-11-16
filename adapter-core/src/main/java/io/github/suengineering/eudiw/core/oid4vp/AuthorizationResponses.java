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

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.jwk.ECKey;
import io.github.suengineering.eudiw.core.VerificationFailure;
import io.github.suengineering.eudiw.core.json.Json;
import java.text.ParseException;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** Decrypts {@code direct_post.jwt} Authorization Responses (OpenID4VP 1.0 section 8.3, HAIP 1.0 section 5). */
public final class AuthorizationResponses {

    /** Upper bound on the encrypted response; presentations with large images still fit. */
    public static final int MAX_RESPONSE_LENGTH = 1024 * 1024;

    private static final Set<EncryptionMethod> ENC = Set.of(EncryptionMethod.A128GCM, EncryptionMethod.A256GCM);

    private AuthorizationResponses() {}

    /** Reads the {@code kid} of an encrypted response without decrypting it, to find the matching request. */
    public static String keyId(String response) {
        try {
            String kid = JWEObject.parse(checkLength(response)).getHeader().getKeyID();
            if (kid == null || kid.isEmpty()) {
                throw new VerificationFailure("invalid_response", "encrypted response has no kid");
            }
            return kid;
        } catch (ParseException e) {
            throw new VerificationFailure("invalid_response", "response is not a compact JWE", e);
        }
    }

    /**
     * @param response the {@code response} form parameter
     * @param key the private key generated for the request this response answers
     * @return the decrypted Authorization Response parameters
     * @throws VerificationFailure {@code invalid_response}
     */
    public static Map<String, Object> decrypt(String response, ECKey key) {
        Objects.requireNonNull(key, "key");
        JWEObject jwe;
        try {
            jwe = JWEObject.parse(checkLength(response));
        } catch (ParseException e) {
            throw new VerificationFailure("invalid_response", "response is not a compact JWE", e);
        }
        JWEHeader header = jwe.getHeader();
        if (!JWEAlgorithm.ECDH_ES.equals(header.getAlgorithm())) {
            throw new VerificationFailure("invalid_response", "response must use ECDH-ES");
        }
        if (!ENC.contains(header.getEncryptionMethod())) {
            throw new VerificationFailure("invalid_response", "response must use A128GCM or A256GCM");
        }
        if (!Objects.equals(header.getKeyID(), key.getKeyID())) {
            throw new VerificationFailure("invalid_response", "response is encrypted to a different key");
        }
        if (header.getCompressionAlgorithm() != null) {
            throw new VerificationFailure("invalid_response", "compressed responses are not accepted");
        }
        try {
            jwe.decrypt(new ECDHDecrypter(key));
        } catch (JOSEException | IllegalStateException e) {
            throw new VerificationFailure("invalid_response", "response cannot be decrypted", e);
        }
        return Json.parseObject(jwe.getPayload().toString(), "invalid_response");
    }

    private static String checkLength(String response) {
        if (response == null || response.isEmpty() || response.length() > MAX_RESPONSE_LENGTH) {
            throw new VerificationFailure("invalid_response", "response missing or too large");
        }
        return response;
    }
}
