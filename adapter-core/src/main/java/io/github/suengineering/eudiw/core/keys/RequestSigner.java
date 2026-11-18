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
package io.github.suengineering.eudiw.core.keys;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.impl.ECDSA;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.util.Objects;

/**
 * Where the verifier's request-signing key lives: in memory, in a PKCS#11 token, or in a remote key service. The
 * service only ever asks for an ES256 signature, so a key that never leaves its store needs nothing else.
 */
public interface RequestSigner {

    /**
     * ECDSA P-256 over SHA-256 of {@code data}, as the 64 byte JOSE {@code R || S} value.
     *
     * @throws JOSEException when the key cannot sign; the message must not contain secrets
     */
    byte[] signEs256(byte[] data) throws JOSEException;

    /** A key held in memory, signed with the default JCA provider. */
    static RequestSigner of(PrivateKey key) {
        Objects.requireNonNull(key, "key");
        return data -> {
            try {
                Signature signature = Signature.getInstance("SHA256withECDSA");
                signature.initSign(key);
                signature.update(data);
                return ECDSA.transcodeSignatureToConcat(signature.sign(), 64);
            } catch (GeneralSecurityException e) {
                throw new JOSEException("signing with the key failed: " + e.getMessage(), e);
            }
        };
    }

    /** A key handle from a provider such as SunPKCS11 ({@link HsmEs256Signer#signConcat}). */
    static RequestSigner of(PrivateKey key, Provider provider) {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(provider, "provider");
        return data -> HsmEs256Signer.signConcat(key, provider, data);
    }
}
