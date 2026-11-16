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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import io.github.suengineering.eudiw.core.VerificationFailure;
import io.github.suengineering.eudiw.core.dcql.DcqlQuery;
import io.github.suengineering.eudiw.core.json.Json;
import io.github.suengineering.eudiw.core.x509.TestPki;
import io.github.suengineering.eudiw.core.x509.TestPki.Issued;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.interfaces.ECPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.jupiter.api.Test;

class AuthorizationRequestResponseTest {

    private static final Instant NOW = Instant.parse("2027-01-15T10:00:00Z");

    private final Issued root = TestPki.rootCa("CN=RP Root", NOW.minusSeconds(86400), NOW.plusSeconds(86400 * 365));
    private final Issued rp = TestPki.endEntity(
            "CN=Verifier",
            root,
            NOW.minusSeconds(86400),
            NOW.plusSeconds(86400 * 30),
            KeyUsage.digitalSignature,
            List.of(TestPki.dns("verifier.test.example")));
    private final VerifierIdentity identity =
            new VerifierIdentity(rp.keyPair().getPrivate(), List.of(rp.certificate()));
    private final DcqlQuery query = DcqlQuery.parse(Json.parseObject(
            "{\"credentials\":[{\"id\":\"age\",\"format\":\"dc+sd-jwt\",\"meta\":{\"vct_values\":[\"urn:age\"]},"
                    + "\"claims\":[{\"path\":[\"age_over_18\"]}]}]}",
            "test"));

    @Test
    void decryptsTheSpecificationExample() throws Exception {
        String response;
        try (InputStream in = getClass().getResourceAsStream("/openid4vp/section-8.3-response.txt")) {
            response = new String(in.readAllBytes(), StandardCharsets.US_ASCII).strip();
        }
        ECKey key = (ECKey) JWK.parse("""
                {"kty":"EC","kid":"ac","use":"enc","crv":"P-256","alg":"ECDH-ES",
                 "x":"YO4epjifD-KWeq1sL2tNmm36BhXnkJ0He-WqMYrp9Fk",
                 "y":"Hekpm0zfK7C-YccH5iBjcIXgf6YdUvNUac_0At55Okk",
                 "d":"Et-3ce0omz8_TuZ96Df9lp0GAaaDoUnDe6X-CRO7Aww"}""");

        assertThat(AuthorizationResponses.keyId(response)).isEqualTo("ac");
        Map<String, Object> payload = AuthorizationResponses.decrypt(response, key);

        assertThat(payload).containsKey("vp_token");
        assertThat(Json.toJson(payload)).contains("\"vp_token\":{\"example_credential_id\":[");
    }

    @Test
    void roundTripWithA256GcmAndRejections() throws Exception {
        ECKey key = AuthorizationRequests.newResponseEncryptionKey();
        String valid = encrypt(key.toPublicJWK(), JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM, key.getKeyID());

        assertThat(AuthorizationResponses.decrypt(valid, key)).containsEntry("state", "s1");

        ECKey other = AuthorizationRequests.newResponseEncryptionKey();
        assertFailure(() -> AuthorizationResponses.decrypt(valid, other));
        String cbc = encrypt(key.toPublicJWK(), JWEAlgorithm.ECDH_ES, EncryptionMethod.A128CBC_HS256, key.getKeyID());
        assertFailure(() -> AuthorizationResponses.decrypt(cbc, key));
        String keyWrap =
                encrypt(key.toPublicJWK(), JWEAlgorithm.ECDH_ES_A128KW, EncryptionMethod.A128GCM, key.getKeyID());
        assertFailure(() -> AuthorizationResponses.decrypt(keyWrap, key));
        String[] parts = valid.split("\\.");
        String tampered = parts[0] + "." + parts[1] + "." + parts[2] + "." + parts[3].substring(1) + "A." + parts[4];
        assertFailure(() -> AuthorizationResponses.decrypt(tampered, key));
        assertFailure(
                () -> AuthorizationResponses.decrypt("x".repeat(AuthorizationResponses.MAX_RESPONSE_LENGTH + 1), key));
        assertFailure(() -> AuthorizationResponses.decrypt("not-a-jwe", key));
    }

    @Test
    void signedRequestObjectFollowsHaip() throws Exception {
        ECKey encryptionKey = AuthorizationRequests.newResponseEncryptionKey();
        String nonce = AuthorizationRequests.randomValue();
        String jwt = AuthorizationRequests.signRequestObject(
                identity,
                new AuthorizationRequests.Parameters(
                        URI.create("https://verifier.test.example/oid4vp/response"),
                        nonce,
                        "state-1",
                        query,
                        encryptionKey,
                        "wallet-nonce-1",
                        Duration.ofMinutes(5)),
                NOW);

        JWSObject jws = JWSObject.parse(jwt);
        assertThat(jws.getHeader().getType().getType()).isEqualTo("oauth-authz-req+jwt");
        assertThat(jws.getHeader().getX509CertChain()).hasSize(1);
        assertThat(jws.verify(new ECDSAVerifier((ECPublicKey) rp.certificate().getPublicKey())))
                .isTrue();

        byte[] leafHash =
                MessageDigest.getInstance("SHA-256").digest(rp.certificate().getEncoded());
        String expectedClientId =
                "x509_hash:" + Base64.getUrlEncoder().withoutPadding().encodeToString(leafHash);
        Map<String, Object> claims = jws.getPayload().toJSONObject();
        assertThat(claims)
                .containsEntry("client_id", expectedClientId)
                .containsEntry("response_type", "vp_token")
                .containsEntry("response_mode", "direct_post.jwt")
                .containsEntry("response_uri", "https://verifier.test.example/oid4vp/response")
                .containsEntry("nonce", nonce)
                .containsEntry("state", "state-1")
                .containsEntry("wallet_nonce", "wallet-nonce-1")
                .containsKey("dcql_query")
                .doesNotContainKey("redirect_uri");
        @SuppressWarnings("unchecked")
        Map<String, Object> metadata = (Map<String, Object>) claims.get("client_metadata");
        assertThat(metadata.get("encrypted_response_enc_values_supported")).isEqualTo(List.of("A128GCM", "A256GCM"));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> keys =
                (List<Map<String, Object>>) ((Map<String, Object>) metadata.get("jwks")).get("keys");
        assertThat(keys).singleElement().satisfies(k -> {
            assertThat(k)
                    .containsEntry("alg", "ECDH-ES")
                    .containsEntry("kid", encryptionKey.getKeyID())
                    .doesNotContainKey("d");
        });
    }

    @Test
    void selfSignedRequestSigningCertificateIsRefused() {
        Issued selfSigned = TestPki.selfSignedEndEntity("CN=Self", NOW.minusSeconds(60), NOW.plusSeconds(3600));

        assertThatThrownBy(() ->
                        new VerifierIdentity(selfSigned.keyPair().getPrivate(), List.of(selfSigned.certificate())))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void walletInvocationUriEncodesParameters() {
        String uri = AuthorizationRequests.walletInvocationUri(
                "openid4vp://", "x509_hash:abc", URI.create("https://v.example/req/1?x=y"));

        assertThat(uri)
                .isEqualTo(
                        "openid4vp://?client_id=x509_hash%3Aabc&request_uri=https%3A%2F%2Fv.example%2Freq%2F1%3Fx%3Dy"
                                + "&request_uri_method=post");
    }

    private static String encrypt(JWK publicKey, JWEAlgorithm alg, EncryptionMethod enc, String kid) throws Exception {
        JWEObject jwe = new JWEObject(
                new JWEHeader.Builder(alg, enc).keyID(kid).build(),
                new Payload("{\"vp_token\":{\"age\":[\"x\"]},\"state\":\"s1\"}"));
        jwe.encrypt(new ECDHEncrypter((ECKey) publicKey));
        return jwe.serialize();
    }

    private static void assertFailure(org.assertj.core.api.ThrowableAssert.ThrowingCallable call) {
        assertThatThrownBy(call).isInstanceOfSatisfying(VerificationFailure.class, f -> assertThat(f.code())
                .isEqualTo("invalid_response"));
    }
}
