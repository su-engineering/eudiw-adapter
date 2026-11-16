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
package io.github.suengineering.eudiw.core.sdjwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.JSONObjectUtils;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/** Builds synthetic SD-JWTs with full control over every part, for rejection tests. */
final class TestSdJwtIssuer {

    static final String ISSUER = "https://issuer.test.example";

    final ECKey issuerKey;
    final ECKey holderKey;

    TestSdJwtIssuer() {
        this.issuerKey = generate(Curve.P_256);
        this.holderKey = generate(Curve.P_256);
    }

    static ECKey generate(Curve curve) {
        try {
            return new ECKeyGenerator(curve).generate();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    static String disclosure(Object... elements) {
        String json = toJsonArray(List.of(elements));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    static String digest(String disclosure) {
        return SdJwtVerifier.digest("sha-256", disclosure);
    }

    String sign(Map<String, Object> payload) {
        return sign(payload, issuerKey, JWSAlgorithm.ES256, "dc+sd-jwt");
    }

    static String sign(Map<String, Object> payload, ECKey key, JWSAlgorithm algorithm, String typ) {
        JWSHeader.Builder header = new JWSHeader.Builder(algorithm);
        if (typ != null) {
            header.type(new JOSEObjectType(typ));
        }
        JWSObject jws = new JWSObject(header.build(), new Payload(JSONObjectUtils.toJSONString(payload)));
        try {
            jws.sign(new ECDSASigner(key));
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
        return jws.serialize();
    }

    /** SD-JWT+KB over the given Issuer-signed JWT and Disclosures. */
    String present(String issuerJwt, List<String> disclosures, String aud, String nonce, long iat) {
        String sdJwt = sdJwt(issuerJwt, disclosures);
        return sdJwt + keyBinding(sdJwt, holderKey, aud, nonce, iat, "kb+jwt");
    }

    static String sdJwt(String issuerJwt, List<String> disclosures) {
        StringBuilder sb = new StringBuilder(issuerJwt).append('~');
        for (String d : disclosures) {
            sb.append(d).append('~');
        }
        return sb.toString();
    }

    static String keyBinding(String sdJwt, ECKey key, String aud, String nonce, long iat, String typ) {
        Map<String, Object> claims = new java.util.LinkedHashMap<>();
        claims.put("aud", aud);
        claims.put("nonce", nonce);
        claims.put("iat", iat);
        claims.put("sd_hash", SdJwtVerifier.digest("sha-256", sdJwt));
        return sign(claims, key, JWSAlgorithm.ES256, typ);
    }

    Map<String, Object> cnf() {
        return Map.of("jwk", holderKey.toPublicJWK().toJSONObject());
    }

    private static String toJsonArray(List<Object> elements) {
        // JSONObjectUtils only serializes objects; wrap and strip.
        String wrapped = JSONObjectUtils.toJSONString(Map.of("a", elements));
        return wrapped.substring("{\"a\":".length(), wrapped.length() - 1);
    }
}
