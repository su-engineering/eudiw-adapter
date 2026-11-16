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
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.util.Base64URL;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.util.Objects;
import java.util.Set;

/**
 * ES256 with a key held by a provider such as SunPKCS11. The SHA-256 digest is computed locally and the token
 * performs plain ECDSA ({@code NONEwithECDSA}, PKCS#11 {@code CKM_ECDSA}), the mechanism every HSM offers; the DER
 * signature is converted to the JOSE {@code R || S} form.
 */
public final class HsmEs256Signer implements JWSSigner {

    private final PrivateKey key;
    private final Provider provider;
    private final JCAContext context = new JCAContext();

    public HsmEs256Signer(PrivateKey key, Provider provider) {
        this.key = Objects.requireNonNull(key, "key");
        this.provider = Objects.requireNonNull(provider, "provider");
    }

    @Override
    public Base64URL sign(JWSHeader header, byte[] signingInput) throws JOSEException {
        if (!JWSAlgorithm.ES256.equals(header.getAlgorithm())) {
            throw new JOSEException("only ES256 is supported");
        }
        return Base64URL.encode(signConcat(key, provider, signingInput));
    }

    /** ECDSA P-256 over SHA-256 of {@code data}, as the 64 byte {@code R || S} value. */
    public static byte[] signConcat(PrivateKey key, Provider provider, byte[] data) throws JOSEException {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
            Signature signature = Signature.getInstance("NONEwithECDSA", provider);
            signature.initSign(key);
            signature.update(digest);
            return ECDSA.transcodeSignatureToConcat(signature.sign(), 64);
        } catch (GeneralSecurityException e) {
            throw new JOSEException("signing with the HSM key failed: " + e.getMessage(), e);
        }
    }

    @Override
    public Set<JWSAlgorithm> supportedJWSAlgorithms() {
        return Set.of(JWSAlgorithm.ES256);
    }

    @Override
    public JCAContext getJCAContext() {
        return context;
    }
}
