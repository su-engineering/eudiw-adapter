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

import static org.assertj.core.api.Assertions.assertThat;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;
import com.authlete.sd.SDObjectDecoder;
import com.authlete.sd.SDObjectEncoder;
import com.nimbusds.jose.JWSAlgorithm;
import io.github.suengineering.eudiw.core.json.Json;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Differential test against Authlete's independent SD-JWT implementation: Authlete builds the selectively
 * disclosable payload, Disclosures, decoys and {@code sd_hash}; our verifier must accept every valid
 * presentation and produce the same processed claims as Authlete's decoder.
 */
class AuthleteInteropTest {

    private static final String AUD = "https://verifier.test.example";
    private static final String NONCE = "interop-nonce";
    private static final long NOW = 1_800_000_000L;

    private final TestSdJwtIssuer keys = new TestSdJwtIssuer();
    private final SdJwtVerifier verifier = new SdJwtVerifier(
            new StaticIssuerKeyResolver(Map.of(TestSdJwtIssuer.ISSUER, keys.issuerKey.toPublicJWK())));

    @ParameterizedTest
    @ValueSource(strings = {"sha-256", "sha-384", "sha-512"})
    void randomSubsetsMatchAuthleteDecoder(String hashAlgorithm) {
        Random random = new Random(hashAlgorithm.hashCode());
        for (int round = 0; round < 40; round++) {
            SDObjectEncoder encoder = new SDObjectEncoder(hashAlgorithm, 0.5, 1.5);
            Map<String, Object> encoded = encoder.encode(claims());
            List<Disclosure> all = encoder.getDisclosures();

            Map<String, Object> payload = new LinkedHashMap<>(encoded);
            payload.put("iss", TestSdJwtIssuer.ISSUER);
            payload.put("exp", NOW + 3600);
            payload.put("cnf", keys.cnf());
            String issuerJwt = TestSdJwtIssuer.sign(payload, keys.issuerKey, JWSAlgorithm.ES256, "dc+sd-jwt");

            List<Disclosure> selected = connectedSubset(payload, all, random, hashAlgorithm);
            SDJWT sdJwt = new SDJWT(issuerJwt, selected);
            String kb = keyBinding(sdJwt.getSDHash());
            String presentation = new SDJWT(issuerJwt, selected, kb).toString();

            VerifiedSdJwt verified = verifier.verify(presentation, options());

            Map<String, Object> expected = new LinkedHashMap<>(new SDObjectDecoder().decode(payload, selected));
            expected.remove("_sd_alg");
            assertThat(normalize(verified.payload()))
                    .as("round %d, %d of %d disclosures", round, selected.size(), all.size())
                    .isEqualTo(normalize(expected));
            assertThat(verified.keyBindingVerified()).isTrue();
        }
    }

    private static Map<String, Object> claims() {
        Map<String, Object> address = new LinkedHashMap<>();
        address.put("street_address", "Heidestraße 17");
        address.put("locality", "Köln");
        address.put("country", "DE");
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("given_name", "Erika");
        claims.put("family_name", "Mustermann");
        claims.put("age_over_18", true);
        claims.put("age_in_years", 41);
        claims.put("address", address);
        claims.put("nationalities", List.of("DE", "FR"));
        claims.put(
                "degrees", List.of(Map.of("type", "Bachelor", "year", 2005), Map.of("type", "Master", "year", 2007)));
        return claims;
    }

    /** Picks a random subset, then drops Disclosures whose digest is not reachable from what is kept. */
    private static List<Disclosure> connectedSubset(
            Map<String, Object> payload, List<Disclosure> all, Random random, String hashAlgorithm) {
        List<Disclosure> candidates = new ArrayList<>();
        for (Disclosure d : all) {
            if (random.nextInt(3) != 0) {
                candidates.add(d);
            }
        }
        Set<String> reachable = new HashSet<>();
        collectDigests(payload, reachable);
        List<Disclosure> kept = new ArrayList<>();
        boolean changed = true;
        while (changed) {
            changed = false;
            for (Disclosure d : candidates) {
                if (!kept.contains(d) && reachable.contains(d.digest(hashAlgorithm))) {
                    kept.add(d);
                    collectDigests(d.getClaimValue(), reachable);
                    changed = true;
                }
            }
        }
        return kept;
    }

    private static void collectDigests(Object value, Set<String> out) {
        if (value instanceof Map<?, ?> map) {
            if (map.get("_sd") instanceof List<?> sd) {
                sd.forEach(d -> out.add((String) d));
            }
            if (map.size() == 1 && map.get("...") instanceof String digest) {
                out.add(digest);
            }
            map.values().forEach(v -> collectDigests(v, out));
        } else if (value instanceof List<?> list) {
            list.forEach(v -> collectDigests(v, out));
        }
    }

    private String keyBinding(String sdHash) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("aud", AUD);
        claims.put("nonce", NONCE);
        claims.put("iat", NOW);
        claims.put("sd_hash", sdHash);
        return TestSdJwtIssuer.sign(claims, keys.holderKey, JWSAlgorithm.ES256, "kb+jwt");
    }

    private static SdJwtVerificationOptions options() {
        return SdJwtVerificationOptions.keyBound(AUD, NONCE)
                .withClock(Clock.fixed(Instant.ofEpochSecond(NOW), ZoneOffset.UTC));
    }

    /** Round-trips through JSON so number types and map implementations compare equal. */
    private static Map<String, Object> normalize(Map<String, Object> value) {
        return Json.parseObject(Json.toJson(value), "test");
    }
}
