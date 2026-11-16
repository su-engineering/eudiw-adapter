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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.jwk.JWK;
import io.github.suengineering.eudiw.core.VerificationFailure;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Verifies the worked examples published in RFC 9901, signed by the RFC authors with the key from Appendix A.5.
 * These are fixed vectors produced independently of this implementation.
 */
class Rfc9901ExamplesTest {

    private static final String ISSUER = "https://issuer.example.com";
    private static final String AUDIENCE = "https://verifier.example.org";
    private static final String NONCE = "1234567890";
    // iat of the Key Binding JWTs in the RFC examples
    private static final Instant KB_IAT = Instant.ofEpochSecond(1748537244);

    private static final SdJwtVerifier VERIFIER = new SdJwtVerifier(new StaticIssuerKeyResolver(
            Map.of(ISSUER, rfcIssuerKey(), "https://pid-issuer.bund.de.example", rfcIssuerKey())));

    // Appendix A.4 is a W3C VCDM example without an iss claim; the RFC signs it with the same key.
    private static final SdJwtVerifier ANY_ISSUER_VERIFIER =
            new SdJwtVerifier((header, payload) -> new IssuerKeyResolver.ResolvedIssuerKey(rfcIssuerKey(), "example"));

    @Test
    void section52PresentationWithKeyBinding() {
        VerifiedSdJwt result = VERIFIER.verify(load("section-5.2"), keyBound(KB_IAT.plusSeconds(10)));

        assertThat(result.keyBindingVerified()).isTrue();
        assertThat(result.issuer()).isEqualTo(ISSUER);
        assertThat(result.payload())
                .containsEntry("sub", "user_42")
                .containsEntry("given_name", "John")
                .containsEntry("family_name", "Doe")
                .containsEntry("nationalities", List.of("US"))
                .containsEntry(
                        "address",
                        Map.of(
                                "street_address", "123 Main St",
                                "locality", "Anytown",
                                "region", "Anystate",
                                "country", "US"))
                .doesNotContainKeys("_sd", "_sd_alg", "email", "phone_number", "birthdate");
        assertThat(result.selectivelyDisclosedTopLevelClaims())
                .containsExactlyInAnyOrder("given_name", "family_name", "address");
        assertThat(result.holderKey()).isPresent();
    }

    @Test
    void appendixA1StructuredWithoutKeyBinding() {
        VerifiedSdJwt result = VERIFIER.verify(load("appendix-a.1"), noKeyBinding());

        assertThat(result.keyBindingVerified()).isFalse();
        assertThat(result.payload())
                .containsEntry("address", Map.of("region", "港区", "country", "JP"))
                .containsEntry("iss", ISSUER)
                .doesNotContainKeys("_sd", "_sd_alg");
    }

    @Test
    void appendixA2ComplexStructuredWithoutKeyBinding() {
        VerifiedSdJwt result = VERIFIER.verify(load("appendix-a.2"), noKeyBinding());

        @SuppressWarnings("unchecked")
        Map<String, Object> verifiedClaims =
                (Map<String, Object>) result.payload().get("verified_claims");
        @SuppressWarnings("unchecked")
        Map<String, Object> claims = (Map<String, Object>) verifiedClaims.get("claims");
        assertThat(claims).containsEntry("given_name", "Max").containsEntry("family_name", "Müller");
        @SuppressWarnings("unchecked")
        Map<String, Object> address = (Map<String, Object>) claims.get("address");
        assertThat(address).containsEntry("street_address", "Weidenstraße 22");
    }

    @Test
    void appendixA3SdJwtVcWithKeyBinding() {
        VerifiedSdJwt result = VERIFIER.verify(load("appendix-a.3"), keyBound(KB_IAT));

        assertThat(result.keyBindingVerified()).isTrue();
        assertThat(result.header().getType().getType()).isEqualTo("dc+sd-jwt");
    }

    @Test
    void appendixA4RecursiveDisclosuresWithKeyBinding() {
        VerifiedSdJwt result = ANY_ISSUER_VERIFIER.verify(load("appendix-a.4"), keyBound(KB_IAT));

        assertThat(result.keyBindingVerified()).isTrue();
        assertThat(result.payload()).doesNotContainKey("_sd");
    }

    @Test
    void keyBindingPresentButNotRequiredIsNotReportedAsVerified() {
        VerifiedSdJwt result = VERIFIER.verify(load("section-5.2"), noKeyBinding());

        assertThat(result.keyBindingVerified()).isFalse();
    }

    @Test
    void droppingADisclosureBreaksSdHash() {
        String presentation = load("section-5.2");
        String[] parts = presentation.split("~");
        // remove the second Disclosure (address), keep the Key Binding JWT
        String tampered = parts[0] + "~" + parts[1] + "~" + parts[3] + "~" + parts[4] + "~" + parts[5];

        assertFailure(() -> VERIFIER.verify(tampered, keyBound(KB_IAT)), "sd_hash_mismatch");
    }

    @Test
    void wrongNonceAudienceAndAgeAreRejected() {
        String presentation = load("section-5.2");
        SdJwtVerificationOptions base = keyBound(KB_IAT);

        assertFailure(
                () -> VERIFIER.verify(presentation, withExpectations(base, AUDIENCE, "other-nonce")),
                "key_binding_nonce_mismatch");
        assertFailure(
                () -> VERIFIER.verify(presentation, withExpectations(base, "https://other.example", NONCE)),
                "key_binding_audience_mismatch");
        assertFailure(() -> VERIFIER.verify(presentation, keyBound(KB_IAT.plusSeconds(3600))), "key_binding_stale");
        assertFailure(() -> VERIFIER.verify(presentation, keyBound(KB_IAT.minusSeconds(3600))), "key_binding_stale");
    }

    @Test
    void unknownIssuerIsRejected() {
        SdJwtVerifier verifier = new SdJwtVerifier(new StaticIssuerKeyResolver(Map.of()));

        assertFailure(() -> verifier.verify(load("section-5.2"), keyBound(KB_IAT)), "issuer_untrusted");
    }

    static String load(String name) {
        try (InputStream in = Rfc9901ExamplesTest.class.getResourceAsStream("/rfc9901/" + name + ".txt")) {
            return new String(in.readAllBytes(), StandardCharsets.US_ASCII).strip();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    static JWK rfcIssuerKey() {
        try {
            return JWK.parse("""
                    {"kty":"EC","crv":"P-256",
                     "x":"b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ",
                     "y":"Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8"}""");
        } catch (java.text.ParseException e) {
            throw new IllegalStateException(e);
        }
    }

    private static SdJwtVerificationOptions keyBound(Instant now) {
        return SdJwtVerificationOptions.keyBound(AUDIENCE, NONCE).withClock(Clock.fixed(now, ZoneOffset.UTC));
    }

    private static SdJwtVerificationOptions noKeyBinding() {
        SdJwtVerificationOptions o = keyBound(KB_IAT);
        return new SdJwtVerificationOptions(
                o.algorithms(),
                o.hashAlgorithms(),
                false,
                null,
                null,
                o.keyBindingMaxAge(),
                o.clockSkew(),
                o.clock(),
                o.maxLength(),
                o.maxDisclosures());
    }

    private static SdJwtVerificationOptions withExpectations(SdJwtVerificationOptions o, String aud, String nonce) {
        return new SdJwtVerificationOptions(
                o.algorithms(),
                o.hashAlgorithms(),
                true,
                aud,
                nonce,
                o.keyBindingMaxAge(),
                o.clockSkew(),
                o.clock(),
                o.maxLength(),
                o.maxDisclosures());
    }

    static void assertFailure(org.assertj.core.api.ThrowableAssert.ThrowingCallable call, String code) {
        assertThatThrownBy(call).isInstanceOfSatisfying(VerificationFailure.class, f -> assertThat(f.code())
                .isEqualTo(code));
    }
}
