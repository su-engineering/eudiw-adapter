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
package io.github.suengineering.eudiw.core.jose;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import io.github.suengineering.eudiw.core.VerificationFailure;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class JwsSignatureVerifierTest {

    @Test
    void acceptsEachEcCurveWithItsAlgorithm() throws Exception {
        List<Curve> curves = List.of(Curve.P_256, Curve.P_384, Curve.P_521);
        List<JWSAlgorithm> algorithms = List.of(JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512);
        for (int i = 0; i < curves.size(); i++) {
            ECKey key = new ECKeyGenerator(curves.get(i)).generate();
            JWSObject jws = sign(algorithms.get(i), new ECDSASigner(key));
            assertThatCode(() -> JwsSignatureVerifier.verify(jws, key.toPublicJWK(), AlgorithmPolicy.DEFAULT))
                    .as("%s", algorithms.get(i))
                    .doesNotThrowAnyException();
        }
    }

    @Test
    void acceptsRsaPssAndRejectsPkcs1() throws Exception {
        RSAKey key = new RSAKeyGenerator(2048).generate();
        for (JWSAlgorithm alg : List.of(JWSAlgorithm.PS256, JWSAlgorithm.PS384, JWSAlgorithm.PS512)) {
            JWSObject jws = sign(alg, new RSASSASigner(key));
            assertThatCode(() -> JwsSignatureVerifier.verify(jws, key.toPublicJWK(), AlgorithmPolicy.DEFAULT))
                    .as("%s", alg)
                    .doesNotThrowAnyException();
        }
        JWSObject rs256 = sign(JWSAlgorithm.RS256, new RSASSASigner(key));
        assertFailure(
                () -> JwsSignatureVerifier.verify(rs256, key.toPublicJWK(), AlgorithmPolicy.DEFAULT),
                "unsupported_algorithm");
    }

    @Test
    void rejectsShortRsaKeys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        KeyPair pair = generator.generateKeyPair();
        JWSObject jws = sign(JWSAlgorithm.PS256, new RSASSASigner(pair.getPrivate(), true));
        RSAKey publicKey = new RSAKey.Builder((RSAPublicKey) pair.getPublic()).build();

        assertFailure(() -> JwsSignatureVerifier.verify(jws, publicKey, AlgorithmPolicy.DEFAULT), "unsupported_key");
    }

    @Test
    void rejectsAlgorithmsOutsideThePolicyAndMismatchedKeys() throws Exception {
        ECKey p384 = new ECKeyGenerator(Curve.P_384).generate();
        JWSObject es384 = sign(JWSAlgorithm.ES384, new ECDSASigner(p384));
        assertFailure(
                () -> JwsSignatureVerifier.verify(es384, p384.toPublicJWK(), AlgorithmPolicy.ES256_ONLY),
                "unsupported_algorithm");

        RSAKey rsa = new RSAKeyGenerator(2048).generate();
        JWSObject ps256 = sign(JWSAlgorithm.PS256, new RSASSASigner(rsa));
        ECKey p256 = new ECKeyGenerator(Curve.P_256).generate();
        assertFailure(
                () -> JwsSignatureVerifier.verify(ps256, p256.toPublicJWK(), AlgorithmPolicy.DEFAULT),
                "unsupported_algorithm");

        JWSObject es256 = sign(JWSAlgorithm.ES256, new ECDSASigner(p256));
        assertFailure(() -> JwsSignatureVerifier.verify(es256, p256, AlgorithmPolicy.DEFAULT), "unsupported_key");
    }

    @Test
    void policyRefusesSymmetricAndWeakSettings() {
        assertThatThrownBy(() -> new AlgorithmPolicy(Set.of(JWSAlgorithm.HS256), 2048))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new AlgorithmPolicy(Set.of(JWSAlgorithm.ES256), 1024))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new AlgorithmPolicy(Set.of(), 2048)).isInstanceOf(IllegalArgumentException.class);
        assertThat(AlgorithmPolicy.DEFAULT.allows(JWSAlgorithm.ES256)).isTrue();
    }

    private static JWSObject sign(JWSAlgorithm alg, JWSSigner signer) throws Exception {
        JWSObject jws = new JWSObject(new JWSHeader(alg), new Payload("{\"a\":1}"));
        jws.sign(signer);
        return JWSObject.parse(jws.serialize());
    }

    private static void assertFailure(org.assertj.core.api.ThrowableAssert.ThrowingCallable call, String code) {
        assertThatThrownBy(call).isInstanceOfSatisfying(VerificationFailure.class, f -> assertThat(f.code())
                .isEqualTo(code));
    }
}
