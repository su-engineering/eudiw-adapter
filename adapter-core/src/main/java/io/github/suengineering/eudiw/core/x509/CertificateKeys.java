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
package io.github.suengineering.eudiw.core.x509;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import io.github.suengineering.eudiw.core.VerificationFailure;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

/** Public keys of certificates as JWKs. */
public final class CertificateKeys {

    private CertificateKeys() {}

    /**
     * @throws VerificationFailure {@code unsupported_key} for key types other than EC and RSA
     */
    public static JWK publicJwk(X509Certificate certificate) {
        // Built from the public key directly: ECKey.parse(X509Certificate) needs BouncyCastle at runtime.
        if (certificate.getPublicKey() instanceof ECPublicKey ec) {
            Curve curve = Curve.forECParameterSpec(ec.getParams());
            if (curve == null) {
                throw new VerificationFailure("unsupported_key", "unsupported certificate curve");
            }
            return new ECKey.Builder(curve, ec).build();
        }
        if (certificate.getPublicKey() instanceof RSAPublicKey rsa) {
            return new RSAKey.Builder(rsa).build();
        }
        throw new VerificationFailure("unsupported_key", "unsupported certificate key type");
    }
}
