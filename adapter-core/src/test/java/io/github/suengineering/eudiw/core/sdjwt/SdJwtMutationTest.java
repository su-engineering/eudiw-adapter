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

import static io.github.suengineering.eudiw.core.sdjwt.TestSdJwtIssuer.ISSUER;
import static io.github.suengineering.eudiw.core.sdjwt.TestSdJwtIssuer.digest;
import static io.github.suengineering.eudiw.core.sdjwt.TestSdJwtIssuer.disclosure;
import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.JWSAlgorithm;
import io.github.suengineering.eudiw.core.VerificationFailure;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.junit.jupiter.api.Test;

/**
 * Random mutations of valid presentations. The only acceptable outcomes are success or a {@link
 * VerificationFailure} raised by an explicit check; anything that reaches the catch-all ({@code
 * unprocessable_presentation}) or escapes as another exception is a bug.
 */
class SdJwtMutationTest {

    private static final String AUD = "https://verifier.test.example";
    private static final String NONCE = "fuzz-nonce";
    private static final long NOW = 1_800_000_000L;
    private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~";
    private static final List<Object> ODD_VALUES = List.of(
            1e300,
            -1e300,
            -1,
            0,
            Long.MAX_VALUE,
            1.5,
            "",
            "x".repeat(300),
            true,
            List.of(),
            Map.of(),
            List.of(Map.of("...", "x")),
            Map.of("_sd", List.of(1)),
            Map.of("jwk", Map.of("kty", "EC")));

    private final TestSdJwtIssuer issuer = new TestSdJwtIssuer();
    private final SdJwtVerifier verifier =
            new SdJwtVerifier(new StaticIssuerKeyResolver(Map.of(ISSUER, issuer.issuerKey.toPublicJWK())));
    private final SdJwtVerificationOptions options = SdJwtVerificationOptions.keyBound(AUD, NONCE)
            .withClock(Clock.fixed(Instant.ofEpochSecond(NOW), ZoneOffset.UTC));

    @Test
    void byteLevelMutationsAreRejectedCleanly() {
        Random random = new Random(42);
        String valid = validPresentation(basePayload());
        verifier.verify(valid, options);
        for (int i = 0; i < 3000; i++) {
            check(mutateText(valid, random));
        }
    }

    @Test
    void signedPayloadMutationsAreRejectedCleanly() {
        Random random = new Random(7);
        List<String> keys = List.of("exp", "nbf", "iss", "cnf", "_sd", "_sd_alg", "vct", "status", "nested", "list");
        for (int i = 0; i < 1500; i++) {
            Map<String, Object> payload = basePayload();
            int changes = 1 + random.nextInt(3);
            for (int c = 0; c < changes; c++) {
                payload.put(keys.get(random.nextInt(keys.size())), ODD_VALUES.get(random.nextInt(ODD_VALUES.size())));
            }
            check(validPresentation(payload));
        }
    }

    @Test
    void keyBindingClaimMutationsAreRejectedCleanly() {
        Random random = new Random(11);
        String jwt = issuer.sign(basePayload());
        String sdJwt = TestSdJwtIssuer.sdJwt(jwt, List.of(ageOver18()));
        for (int i = 0; i < 500; i++) {
            Map<String, Object> claims = new LinkedHashMap<>();
            claims.put("aud", random.nextBoolean() ? AUD : ODD_VALUES.get(random.nextInt(ODD_VALUES.size())));
            claims.put("nonce", random.nextBoolean() ? NONCE : ODD_VALUES.get(random.nextInt(ODD_VALUES.size())));
            claims.put("iat", random.nextBoolean() ? NOW : ODD_VALUES.get(random.nextInt(ODD_VALUES.size())));
            claims.put(
                    "sd_hash",
                    random.nextBoolean() ? digest(sdJwt) : ODD_VALUES.get(random.nextInt(ODD_VALUES.size())));
            check(sdJwt + TestSdJwtIssuer.sign(claims, issuer.holderKey, JWSAlgorithm.ES256, "kb+jwt"));
        }
    }

    private void check(String presentation) {
        try {
            verifier.verify(presentation, options);
        } catch (VerificationFailure failure) {
            assertThat(failure.code())
                    .as("unexpected exception for input; cause: %s", failure.getCause())
                    .isNotEqualTo("unprocessable_presentation");
        }
    }

    private String ageOver18() {
        return disclosure("salt-age", "age_over_18", true);
    }

    private Map<String, Object> basePayload() {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", ISSUER);
        payload.put("vct", "https://credentials.test.example/age");
        payload.put("exp", NOW + 3600);
        payload.put("_sd", List.of(digest(ageOver18())));
        payload.put("cnf", issuer.cnf());
        return payload;
    }

    private String validPresentation(Map<String, Object> payload) {
        return issuer.present(issuer.sign(payload), List.of(ageOver18()), AUD, NONCE, NOW);
    }

    private static String mutateText(String input, Random random) {
        StringBuilder sb = new StringBuilder(input);
        int ops = 1 + random.nextInt(4);
        for (int i = 0; i < ops && sb.length() > 0; i++) {
            int pos = random.nextInt(sb.length());
            switch (random.nextInt(5)) {
                case 0 -> sb.setCharAt(pos, ALPHABET.charAt(random.nextInt(ALPHABET.length())));
                case 1 -> sb.deleteCharAt(pos);
                case 2 -> sb.insert(pos, ALPHABET.charAt(random.nextInt(ALPHABET.length())));
                case 3 -> sb.setLength(pos);
                default -> {
                    List<String> parts = new ArrayList<>(List.of(sb.toString().split("~", -1)));
                    if (parts.size() > 2) {
                        parts.add(1, parts.get(random.nextInt(parts.size())));
                    }
                    sb = new StringBuilder(String.join("~", parts));
                }
            }
        }
        return sb.toString();
    }
}
