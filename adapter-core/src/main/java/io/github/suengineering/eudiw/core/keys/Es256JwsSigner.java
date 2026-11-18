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
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.util.Base64URL;
import java.util.Objects;
import java.util.Set;

/** A Nimbus {@link JWSSigner} for ES256 that delegates to a {@link RequestSigner}. */
public final class Es256JwsSigner implements JWSSigner {

    private final RequestSigner signer;
    private final JCAContext context = new JCAContext();

    public Es256JwsSigner(RequestSigner signer) {
        this.signer = Objects.requireNonNull(signer, "signer");
    }

    @Override
    public Base64URL sign(JWSHeader header, byte[] signingInput) throws JOSEException {
        if (!JWSAlgorithm.ES256.equals(header.getAlgorithm())) {
            throw new JOSEException("only ES256 is supported");
        }
        return Base64URL.encode(signer.signEs256(signingInput));
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
