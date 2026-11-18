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
package io.github.suengineering.eudiw.service;

import static io.restassured.RestAssured.given;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.JSONObjectUtils;
import io.restassured.response.Response;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** A minimal synthetic wallet and token issuer for service tests. Not an independent implementation. */
public final class TestWallet {

    public final ECKey holderKey;

    public TestWallet() {
        try {
            holderKey = new ECKeyGenerator(Curve.P_256).generate();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** An OAuth access token as the authorization server would issue it to a backend client. */
    public static String token(String clientId, String... scopes) {
        return token(TestEnvironment.TOKEN_ISSUER, TestEnvironment.AUDIENCE, 300, clientId, scopes);
    }

    /** A token with explicit issuer, audience and lifetime, for negative tests. */
    public static String token(
            String issuer, String audience, long lifetimeSeconds, String clientId, String... scopes) {
        Map<String, Object> claims = new LinkedHashMap<>();
        long now = Instant.now().getEpochSecond();
        claims.put("iss", issuer);
        claims.put("aud", audience);
        claims.put("sub", "service-account-" + clientId);
        claims.put("azp", clientId);
        claims.put("scope", String.join(" ", scopes));
        claims.put("iat", now - 600);
        claims.put("exp", now + lifetimeSeconds);
        claims.put("jti", UUID.randomUUID().toString());
        return signToken(claims);
    }

    /** A valid access token for {@code portal-a} with all scopes, and the given claims replaced or added. */
    public static String tokenWith(Map<String, Object> overrides) {
        Map<String, Object> claims = new LinkedHashMap<>();
        long now = Instant.now().getEpochSecond();
        claims.put("iss", TestEnvironment.TOKEN_ISSUER);
        claims.put("aud", TestEnvironment.AUDIENCE);
        claims.put("sub", "service-account-portal-a");
        claims.put("azp", "portal-a");
        claims.put("scope", ALL_SCOPES);
        claims.put("iat", now - 600);
        claims.put("exp", now + 300);
        claims.put("jti", UUID.randomUUID().toString());
        claims.putAll(overrides);
        return signToken(claims);
    }

    private static String signToken(Map<String, Object> claims) {
        try {
            JWSObject jws = new JWSObject(
                    new JWSHeader.Builder(JWSAlgorithm.RS256)
                            .type(JOSEObjectType.JWT)
                            .build(),
                    new Payload(JSONObjectUtils.toJSONString(claims)));
            jws.sign(new RSASSASigner(TestEnvironment.privateKey("token-key.pem", "RSA")));
            return jws.serialize();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static final String ALL_SCOPES =
            "verification:create verification:read verification:result verification:cancel";

    public static String fullToken(String clientId) {
        return token(clientId, ALL_SCOPES.split(" "));
    }

    /** Fetches and verifies the signed request object, as a wallet would. */
    public static Map<String, Object> fetchRequest(String requestUri) {
        Response response = given().contentType("application/x-www-form-urlencoded")
                .formParam("wallet_nonce", "wn-" + UUID.randomUUID())
                .post(URI.create(requestUri).getPath());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("request object fetch failed: " + response.statusCode());
        }
        try {
            JWSObject jws = JWSObject.parse(response.asString());
            X509Certificate leaf = com.nimbusds.jose.util.X509CertUtils.parse(
                    jws.getHeader().getX509CertChain().get(0).decode());
            if (!jws.verify(new ECDSAVerifier((ECPublicKey) leaf.getPublicKey()))) {
                throw new IllegalStateException("request object signature invalid");
            }
            String expectedClientId = "x509_hash:"
                    + java.util.Base64.getUrlEncoder()
                            .withoutPadding()
                            .encodeToString(MessageDigest.getInstance("SHA-256").digest(leaf.getEncoded()));
            Map<String, Object> claims = jws.getPayload().toJSONObject();
            if (!expectedClientId.equals(claims.get("client_id"))) {
                throw new IllegalStateException("client_id does not match x509_hash");
            }
            return claims;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * An SD-JWT VC presentation for the request, disclosing the given claims. Like a wallet that supports it, it
     * binds any {@code transaction_data} in the request through {@code transaction_data_hashes}.
     */
    public String presentation(
            Map<String, Object> request,
            String issuer,
            String issuerKeyFile,
            String issuerCertFile,
            Map<String, Object> disclosed,
            Integer statusIndex) {
        return presentation(request, issuer, issuerKeyFile, issuerCertFile, disclosed, statusIndex, true);
    }

    /** As above; with {@code bindTransactionData} false, a wallet that ignores {@code transaction_data}. */
    public String presentation(
            Map<String, Object> request,
            String issuer,
            String issuerKeyFile,
            String issuerCertFile,
            Map<String, Object> disclosed,
            Integer statusIndex,
            boolean bindTransactionData) {
        try {
            List<String> disclosures = new ArrayList<>();
            List<String> digests = new ArrayList<>();
            int i = 0;
            for (Map.Entry<String, Object> claim : disclosed.entrySet()) {
                String json = JSONObjectUtils.toJSONString(
                        Map.of("a", List.of("salt-" + i++, claim.getKey(), claim.getValue())));
                String disclosure = b64(json.substring(5, json.length() - 1));
                disclosures.add(disclosure);
                digests.add(sha256(disclosure));
            }
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("iss", issuer);
            payload.put("vct", TestEnvironment.VCT);
            payload.put("iat", Instant.now().getEpochSecond());
            payload.put("exp", Instant.now().getEpochSecond() + 3600);
            payload.put("_sd", digests);
            payload.put("cnf", Map.of("jwk", holderKey.toPublicJWK().toJSONObject()));
            if (statusIndex != null) {
                payload.put("status", Map.of("status_list", Map.of("idx", statusIndex, "uri", statusUri(issuer))));
            }
            String jwt = sign(
                    payload,
                    TestEnvironment.privateKey(issuerKeyFile, "EC"),
                    "dc+sd-jwt",
                    List.of(TestEnvironment.certificate(issuerCertFile)));
            String sdJwt = jwt + "~" + String.join("~", disclosures) + "~";
            Map<String, Object> kb = new LinkedHashMap<>();
            kb.put("aud", request.get("client_id"));
            kb.put("nonce", request.get("nonce"));
            kb.put("iat", Instant.now().getEpochSecond());
            kb.put("sd_hash", sha256(sdJwt));
            if (bindTransactionData && request.get("transaction_data") instanceof List<?> transactionData) {
                List<String> hashes = new ArrayList<>();
                for (Object entry : transactionData) {
                    hashes.add(sha256((String) entry));
                }
                kb.put("transaction_data_hashes", hashes);
            }
            JWSObject kbJws = new JWSObject(
                    new JWSHeader.Builder(JWSAlgorithm.ES256)
                            .type(new JOSEObjectType("kb+jwt"))
                            .build(),
                    new Payload(JSONObjectUtils.toJSONString(kb)));
            kbJws.sign(new ECDSASigner(holderKey));
            return sdJwt + kbJws.serialize();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static String statusUri(String issuer) {
        return issuer + "/status/1";
    }

    /** Posts an encrypted Authorization Response to the request's response_uri. */
    public static Response respond(Map<String, Object> request, Map<String, Object> responsePayload) {
        try {
            Map<String, Object> payload = new LinkedHashMap<>(responsePayload);
            payload.put("state", request.get("state"));
            return given().contentType("application/x-www-form-urlencoded")
                    .formParam("response", encrypt(request, payload))
                    .post(URI.create((String) request.get("response_uri")).getPath());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** The response payload encrypted to the request's key, as {@code dc_api.jwt} and {@code direct_post.jwt} do. */
    public static String encrypt(Map<String, Object> request, Map<String, Object> payload) {
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> metadata = (Map<String, Object>) request.get("client_metadata");
            @SuppressWarnings("unchecked")
            Map<String, Object> jwks = (Map<String, Object>) metadata.get("jwks");
            @SuppressWarnings("unchecked")
            Map<String, Object> jwkJson = ((List<Map<String, Object>>) jwks.get("keys")).get(0);
            ECKey key = (ECKey) JWK.parse(jwkJson);
            JWEObject jwe = new JWEObject(
                    new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM)
                            .keyID(key.getKeyID())
                            .build(),
                    new Payload(JSONObjectUtils.toJSONString(payload)));
            jwe.encrypt(new ECDHEncrypter(key));
            return jwe.serialize();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static String sign(Map<String, Object> payload, PrivateKey key, String typ, List<X509Certificate> x5c)
            throws Exception {
        List<Base64> chain = new ArrayList<>();
        for (X509Certificate c : x5c) {
            chain.add(Base64.encode(c.getEncoded()));
        }
        JWSObject jws = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .type(new JOSEObjectType(typ))
                        .x509CertChain(chain)
                        .build(),
                new Payload(JSONObjectUtils.toJSONString(payload)));
        jws.sign(new ECDSASigner((ECPrivateKey) key));
        return jws.serialize();
    }

    /** A status list token from the issuer: index 0 revoked, every other index valid. */
    public static String statusListToken(String issuer, String issuerKeyFile, String issuerCertFile) {
        try {
            // bits=1, statuses 1,0,0,1,1,1,0,1,... (Token Status List draft 14, section 4.2)
            Map<String, Object> claims = new LinkedHashMap<>();
            claims.put("sub", statusUri(issuer));
            claims.put("iat", Instant.now().getEpochSecond());
            claims.put("ttl", 300);
            claims.put("status_list", Map.of("bits", 1, "lst", "eNrbuRgAAhcBXQ"));
            return sign(
                    claims,
                    TestEnvironment.privateKey(issuerKeyFile, "EC"),
                    "statuslist+jwt",
                    List.of(TestEnvironment.certificate(issuerCertFile)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String b64(String s) {
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    private static String sha256(String ascii) throws Exception {
        return java.util.Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(MessageDigest.getInstance("SHA-256").digest(ascii.getBytes(StandardCharsets.US_ASCII)));
    }
}
