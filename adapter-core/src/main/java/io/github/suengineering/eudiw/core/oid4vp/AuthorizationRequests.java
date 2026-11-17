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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64;
import io.github.suengineering.eudiw.core.dcql.DcqlQuery;
import io.github.suengineering.eudiw.core.json.Json;
import io.github.suengineering.eudiw.core.keys.HsmEs256Signer;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Builds signed Authorization Requests for the HAIP 1.0 redirect flow: a Request Object signed with the {@code
 * x509_hash} identity (JAR, retrieved via {@code request_uri}), response mode {@code direct_post.jwt}, and a fresh
 * ECDH-ES P-256 encryption key per request.
 */
public final class AuthorizationRequests {

    /** ES256, ESP256, ES384, ESP384, ES512, ESP512, EdDSA, Ed25519, Ed448 (IANA COSE Algorithms). */

    /** Content type of the Request URI response (OpenID4VP 1.0 section 5.10.1). */
    public static final String REQUEST_OBJECT_MEDIA_TYPE = "application/oauth-authz-req+jwt";

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final List<String> ENC_VALUES = List.of("A128GCM", "A256GCM");

    private AuthorizationRequests() {}

    /** A fresh random value of 256 bits, base64url-encoded, suitable for nonce, state and handles. */
    public static String randomValue() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /** A new ephemeral key pair for encrypting the response to exactly one request. */
    public static ECKey newResponseEncryptionKey() {
        try {
            return new ECKeyGenerator(Curve.P_256)
                    .keyUse(KeyUse.ENCRYPTION)
                    .algorithm(JWEAlgorithm.ECDH_ES)
                    .keyID(randomValue())
                    .generate();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Parameters of one request.
     *
     * @param responseUri where the wallet posts the encrypted response
     * @param nonce fresh nonce, bound into the Key Binding JWT
     * @param state fresh state, echoed in the response and used to find the request
     * @param query the DCQL query, built by the server from an approved policy
     * @param responseEncryptionKey per-request key; only the public part is published
     * @param walletNonce the wallet's nonce from a POST to the Request URI, or {@code null}
     * @param lifetime validity of the signed Request Object
     * @param verifierInfo the {@code verifier_info} elements (OpenID4VP 1.0 section 5.1); empty to omit the
     *     parameter
     */
    public record Parameters(
            URI responseUri,
            String nonce,
            String state,
            DcqlQuery query,
            ECKey responseEncryptionKey,
            String walletNonce,
            Duration lifetime,
            List<Map<String, Object>> verifierInfo) {

        public Parameters(
                URI responseUri,
                String nonce,
                String state,
                DcqlQuery query,
                ECKey responseEncryptionKey,
                String walletNonce,
                Duration lifetime) {
            this(responseUri, nonce, state, query, responseEncryptionKey, walletNonce, lifetime, List.of());
        }

        public Parameters {
            Objects.requireNonNull(responseUri, "responseUri");
            Objects.requireNonNull(nonce, "nonce");
            Objects.requireNonNull(state, "state");
            Objects.requireNonNull(query, "query");
            Objects.requireNonNull(responseEncryptionKey, "responseEncryptionKey");
            Objects.requireNonNull(lifetime, "lifetime");
            verifierInfo = verifierInfo == null ? List.of() : List.copyOf(verifierInfo);
        }
    }

    /** Signs the Request Object (OpenID4VP 1.0 sections 5, 5.10.1 and 8.3.1; HAIP 1.0 section 5). */
    public static String signRequestObject(VerifierIdentity identity, Parameters parameters, Instant now) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", identity.clientId());
        claims.put("aud", "https://self-issued.me/v2");
        claims.put("client_id", identity.clientId());
        claims.put("response_type", "vp_token");
        claims.put("response_mode", "direct_post.jwt");
        claims.put("response_uri", parameters.responseUri().toString());
        claims.put("nonce", parameters.nonce());
        claims.put("state", parameters.state());
        claims.put("dcql_query", parameters.query().toJson());
        claims.put("client_metadata", clientMetadata(parameters.responseEncryptionKey(), parameters.query()));
        if (!parameters.verifierInfo().isEmpty()) {
            claims.put("verifier_info", parameters.verifierInfo());
        }
        if (parameters.walletNonce() != null) {
            claims.put("wallet_nonce", parameters.walletNonce());
        }
        claims.put("iat", now.getEpochSecond());
        claims.put("exp", now.plus(parameters.lifetime()).getEpochSecond());
        claims.put("jti", randomValue());

        List<Base64> x5c = new ArrayList<>();
        try {
            for (X509Certificate certificate : identity.certificateChain()) {
                x5c.add(Base64.encode(certificate.getEncoded()));
            }
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException(e);
        }
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("oauth-authz-req+jwt"))
                .x509CertChain(x5c)
                .build();
        JWSObject jws = new JWSObject(header, new Payload(Json.toJson(claims)));
        try {
            JWSSigner signer = identity.provider().isPresent()
                    ? new HsmEs256Signer(
                            identity.signingKey(), identity.provider().get())
                    : new ECDSASigner(identity.signingKey(), Curve.P_256);
            jws.sign(signer);
        } catch (JOSEException e) {
            throw new IllegalStateException("request object cannot be signed", e);
        }
        return jws.serialize();
    }

    /**
     * The URI that invokes the wallet: {@code <scheme>?client_id=...&request_uri=...&request_uri_method=post}.
     *
     * @param walletBase for example {@code openid4vp://} or {@code haip-vp://}
     */
    public static String walletInvocationUri(String walletBase, String clientId, URI requestUri) {
        return walletBase
                + "?client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
                + "&request_uri=" + URLEncoder.encode(requestUri.toString(), StandardCharsets.UTF_8)
                + "&request_uri_method=post";
    }

    private static Map<String, Object> clientMetadata(ECKey encryptionKey, DcqlQuery query) {
        if (encryptionKey.getKeyID() == null) {
            throw new IllegalArgumentException("response encryption key needs a kid");
        }
        Map<String, Object> jwk =
                new LinkedHashMap<>(encryptionKey.toPublicJWK().toJSONObject());
        jwk.put("use", "enc");
        jwk.put("alg", "ECDH-ES");
        List<String> algs = List.of("ES256", "ES384", "ES512");
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("jwks", Map.of("keys", List.of(jwk)));
        metadata.put("encrypted_response_enc_values_supported", ENC_VALUES);
        Map<String, Object> formats = new LinkedHashMap<>();
        formats.put(DcqlQuery.FORMAT_SD_JWT_VC, Map.of("sd-jwt_alg_values", algs, "kb-jwt_alg_values", algs));
        if (query.credentials().stream().anyMatch(c -> DcqlQuery.FORMAT_MDOC.equals(c.format()))) {
            // COSE algorithm identifiers accepted for IssuerAuth and DeviceSignature (OpenID4VP 1.0 Appendix B.2.2).
            formats.put(
                    DcqlQuery.FORMAT_MDOC,
                    Map.of("issuerauth_alg_values", mdocAlgorithms(), "deviceauth_alg_values", mdocAlgorithms()));
        }
        metadata.put("vp_formats_supported", formats);
        return metadata;
    }

    /** The COSE algorithms accepted for mdoc signatures; the brainpool-only ones only while brainpool is enabled. */
    static List<Integer> mdocAlgorithms() {
        return java.util.Arrays.stream(io.github.suengineering.eudiw.core.cose.CoseAlgorithm.values())
                .filter(io.github.suengineering.eudiw.core.cose.CoseAlgorithm::available)
                .map(io.github.suengineering.eudiw.core.cose.CoseAlgorithm::id)
                .toList();
    }
}
