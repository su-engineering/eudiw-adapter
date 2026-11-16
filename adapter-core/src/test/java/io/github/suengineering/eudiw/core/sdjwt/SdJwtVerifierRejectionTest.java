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

import static io.github.suengineering.eudiw.core.sdjwt.Rfc9901ExamplesTest.assertFailure;
import static io.github.suengineering.eudiw.core.sdjwt.TestSdJwtIssuer.ISSUER;
import static io.github.suengineering.eudiw.core.sdjwt.TestSdJwtIssuer.digest;
import static io.github.suengineering.eudiw.core.sdjwt.TestSdJwtIssuer.disclosure;
import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** One targeted mutation per rejection rule of RFC 9901 sections 4, 7.1 and 7.3. */
class SdJwtVerifierRejectionTest {

    private static final String AUD = "https://verifier.test.example";
    private static final String NONCE = "n-0S6_WzA2Mj";
    private static final long NOW = 1_800_000_000L;

    private final TestSdJwtIssuer issuer = new TestSdJwtIssuer();
    private final SdJwtVerifier verifier =
            new SdJwtVerifier(new StaticIssuerKeyResolver(Map.of(ISSUER, issuer.issuerKey.toPublicJWK())));
    private final SdJwtVerificationOptions options = SdJwtVerificationOptions.keyBound(AUD, NONCE)
            .withClock(Clock.fixed(Instant.ofEpochSecond(NOW), ZoneOffset.UTC));

    private final String givenName = disclosure("salt-given-name-1", "given_name", "Erika");
    private final String ageOver18 = disclosure("salt-age-over-18", "age_over_18", true);

    private Map<String, Object> basePayload() {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", ISSUER);
        payload.put("vct", "https://credentials.test.example/age");
        payload.put("exp", NOW + 3600);
        payload.put("_sd", List.of(digest(givenName), digest(ageOver18)));
        payload.put("cnf", issuer.cnf());
        return payload;
    }

    private String present(Map<String, Object> payload, List<String> disclosures) {
        return issuer.present(issuer.sign(payload), disclosures, AUD, NONCE, NOW);
    }

    @Test
    void validPresentationIsAccepted() {
        VerifiedSdJwt result = verifier.verify(present(basePayload(), List.of(ageOver18)), options);

        assertThat(result.payload()).containsEntry("age_over_18", true).doesNotContainKey("given_name");
        assertThat(result.keyBindingVerified()).isTrue();
    }

    @Test
    void signatureByAnotherKeyIsRejected() {
        String jwt = TestSdJwtIssuer.sign(
                basePayload(), TestSdJwtIssuer.generate(Curve.P_256), JWSAlgorithm.ES256, "dc+sd-jwt");
        String presentation = issuer.present(jwt, List.of(ageOver18), AUD, NONCE, NOW);

        assertFailure(() -> verifier.verify(presentation, options), "invalid_signature");
    }

    @Test
    void modifiedIssuerPayloadIsRejected() {
        String jwt = issuer.sign(basePayload());
        String[] parts = jwt.split("\\.");
        Map<String, Object> changed = basePayload();
        changed.put("exp", NOW + 999_999);
        String forged =
                parts[0] + "." + b64(io.github.suengineering.eudiw.core.json.Json.toJson(changed)) + "." + parts[2];
        String presentation = issuer.present(forged, List.of(ageOver18), AUD, NONCE, NOW);

        assertFailure(() -> verifier.verify(presentation, options), "invalid_signature");
    }

    @Test
    void algNoneIsRejected() {
        String header = b64("{\"alg\":\"none\",\"typ\":\"dc+sd-jwt\"}");
        String unsigned = header + "." + b64(io.github.suengineering.eudiw.core.json.Json.toJson(basePayload())) + ".";
        String presentation = unsigned + "~" + ageOver18 + "~";

        assertFailure(() -> verifier.verify(presentation, withoutKeyBinding()), "malformed_sd_jwt");
    }

    @Test
    void hmacWithAnyKeyIsRejected() {
        String header = b64("{\"alg\":\"HS256\",\"typ\":\"dc+sd-jwt\"}");
        String body = b64(io.github.suengineering.eudiw.core.json.Json.toJson(basePayload()));
        String presentation = header + "." + body + "." + b64("not-a-real-mac") + "~" + ageOver18 + "~";

        assertFailure(() -> verifier.verify(presentation, withoutKeyBinding()), "unsupported_algorithm");
    }

    @Test
    void algorithmNotMatchingKeyCurveIsRejected() {
        ECKey p384 = TestSdJwtIssuer.generate(Curve.P_384);
        SdJwtVerifier p384Verifier =
                new SdJwtVerifier(new StaticIssuerKeyResolver(Map.of(ISSUER, issuer.issuerKey.toPublicJWK())));
        // signed with a P-384 key as ES384, while the trusted key is P-256
        String jwt = TestSdJwtIssuer.sign(basePayload(), p384, JWSAlgorithm.ES384, "dc+sd-jwt");
        String presentation = issuer.present(jwt, List.of(ageOver18), AUD, NONCE, NOW);

        assertFailure(() -> p384Verifier.verify(presentation, options), "unsupported_algorithm");
    }

    @Test
    void modifiedDisclosureIsRejected() {
        String forged = disclosure("salt-age-over-18", "age_over_18", false);

        assertFailure(
                () -> verifier.verify(present(basePayload(), List.of(forged)), options), "unreferenced_disclosure");
    }

    @Test
    void repeatedDisclosureIsRejected() {
        assertFailure(
                () -> verifier.verify(present(basePayload(), List.of(ageOver18, ageOver18)), options),
                "duplicate_disclosure");
    }

    @Test
    void repeatedDigestIsRejected() {
        Map<String, Object> payload = basePayload();
        payload.put("_sd", List.of(digest(ageOver18), digest(ageOver18)));

        assertFailure(() -> verifier.verify(present(payload, List.of(ageOver18)), options), "duplicate_digest");
    }

    @Test
    void digestRepeatedAcrossObjectAndArrayIsRejected() {
        String element = disclosure("salt-element", "DE");
        Map<String, Object> payload = basePayload();
        payload.put("nationalities", List.of(Map.of("...", digest(element)), Map.of("...", digest(element))));

        assertFailure(() -> verifier.verify(present(payload, List.of(element)), options), "duplicate_digest");
    }

    @Test
    void disclosedClaimMayNotOverwritePlaintextClaim() {
        String fakeIssuer = disclosure("salt-iss", "iss", "https://attacker.example");
        Map<String, Object> payload = basePayload();
        payload.put("_sd", List.of(digest(fakeIssuer)));

        assertFailure(() -> verifier.verify(present(payload, List.of(fakeIssuer)), options), "claim_name_conflict");
    }

    @Test
    void reservedClaimNamesInDisclosuresAreRejected() {
        String sd = disclosure("salt-sd", "_sd", List.of());
        Map<String, Object> payload = basePayload();
        payload.put("_sd", List.of(digest(sd)));

        assertFailure(() -> verifier.verify(present(payload, List.of(sd)), options), "invalid_disclosure");
    }

    @Test
    void arrayElementDisclosureReferencedFromObjectIsRejected() {
        String element = disclosure("salt-element", "DE");
        Map<String, Object> payload = basePayload();
        payload.put("_sd", List.of(digest(element)));

        assertFailure(() -> verifier.verify(present(payload, List.of(element)), options), "invalid_disclosure");
    }

    @Test
    void objectDisclosureReferencedFromArrayIsRejected() {
        Map<String, Object> payload = basePayload();
        payload.put("nationalities", List.of(Map.of("...", digest(ageOver18))));
        payload.put("_sd", List.of());

        assertFailure(() -> verifier.verify(present(payload, List.of(ageOver18)), options), "invalid_disclosure");
    }

    @Test
    void arrayDigestObjectWithExtraKeysIsRejected() {
        String element = disclosure("salt-element", "DE");
        Map<String, Object> payload = basePayload();
        payload.put("nationalities", List.of(Map.of("...", digest(element), "x", 1)));

        assertFailure(() -> verifier.verify(present(payload, List.of(element)), options), "malformed_sd_jwt");
    }

    @Test
    void nestedSdAlgIsRejected() {
        Map<String, Object> payload = basePayload();
        payload.put("address", Map.of("_sd_alg", "sha-256", "country", "DE"));

        assertFailure(() -> verifier.verify(present(payload, List.of(ageOver18)), options), "malformed_sd_jwt");
    }

    @Test
    void unsupportedHashAlgorithmIsRejected() {
        Map<String, Object> payload = basePayload();
        payload.put("_sd_alg", "md5");

        assertFailure(
                () -> verifier.verify(present(payload, List.of(ageOver18)), options), "unsupported_hash_algorithm");
    }

    @Test
    void malformedDisclosuresAreRejected() {
        String oneElement = disclosure("only-salt");
        String numericSalt = disclosure(42, "age_over_18", true);
        String notJson =
                Base64.getUrlEncoder().withoutPadding().encodeToString("not json".getBytes(StandardCharsets.UTF_8));
        for (String bad : List.of(oneElement, numericSalt, notJson)) {
            Map<String, Object> payload = basePayload();
            payload.put("_sd", List.of(digest(bad)));
            assertFailure(() -> verifier.verify(present(payload, List.of(bad)), options), "invalid_disclosure");
        }
    }

    @Test
    void expiredAndNotYetValidCredentialsAreRejected() {
        Map<String, Object> expired = basePayload();
        expired.put("exp", NOW - 3600);
        assertFailure(() -> verifier.verify(present(expired, List.of(ageOver18)), options), "credential_expired");

        Map<String, Object> future = basePayload();
        future.put("nbf", NOW + 3600);
        assertFailure(() -> verifier.verify(present(future, List.of(ageOver18)), options), "credential_not_yet_valid");
    }

    @Test
    void missingKeyBindingIsRejectedWhenRequired() {
        String sdJwt = TestSdJwtIssuer.sdJwt(issuer.sign(basePayload()), List.of(ageOver18));

        assertFailure(() -> verifier.verify(sdJwt, options), "key_binding_required");
    }

    @Test
    void keyBindingSignedByAnotherKeyIsRejected() {
        String sdJwt = TestSdJwtIssuer.sdJwt(issuer.sign(basePayload()), List.of(ageOver18));
        String kb = TestSdJwtIssuer.keyBinding(sdJwt, TestSdJwtIssuer.generate(Curve.P_256), AUD, NONCE, NOW, "kb+jwt");

        assertFailure(() -> verifier.verify(sdJwt + kb, options), "invalid_key_binding");
    }

    @Test
    void keyBindingWithWrongTypIsRejected() {
        String sdJwt = TestSdJwtIssuer.sdJwt(issuer.sign(basePayload()), List.of(ageOver18));
        String kb = TestSdJwtIssuer.keyBinding(sdJwt, issuer.holderKey, AUD, NONCE, NOW, "JWT");

        assertFailure(() -> verifier.verify(sdJwt + kb, options), "invalid_key_binding");
    }

    @Test
    void keyBindingFromAnotherPresentationIsRejected() {
        String jwt = issuer.sign(basePayload());
        String otherSdJwt = TestSdJwtIssuer.sdJwt(jwt, List.of(givenName));
        String kb = TestSdJwtIssuer.keyBinding(otherSdJwt, issuer.holderKey, AUD, NONCE, NOW, "kb+jwt");
        String spliced = TestSdJwtIssuer.sdJwt(jwt, List.of(ageOver18)) + kb;

        assertFailure(() -> verifier.verify(spliced, options), "sd_hash_mismatch");
    }

    @Test
    void keyBindingRequiredButCredentialHasNoHolderKey() {
        Map<String, Object> payload = basePayload();
        payload.remove("cnf");

        assertFailure(() -> verifier.verify(present(payload, List.of(ageOver18)), options), "holder_key_missing");
    }

    @Test
    void privateKeyInCnfIsRejected() {
        Map<String, Object> payload = basePayload();
        payload.put("cnf", Map.of("jwk", issuer.holderKey.toJSONObject()));

        assertFailure(() -> verifier.verify(present(payload, List.of(ageOver18)), options), "malformed_sd_jwt");
    }

    @Test
    void structurallyInvalidSerializationsAreRejected() {
        String jwt = issuer.sign(basePayload());
        for (String bad : List.of(jwt, jwt + "~~", jwt + "~" + ageOver18 + "~~", jwt + "~not a jwt", "")) {
            assertFailure(() -> verifier.verify(bad, withoutKeyBinding()), "malformed_sd_jwt");
        }
    }

    @Test
    void deeplyNestedPayloadIsRejected() {
        Object nested = "leaf";
        for (int i = 0; i < 40; i++) {
            nested = Map.of("n", nested);
        }
        Map<String, Object> payload = basePayload();
        payload.put("deep", nested);

        assertFailure(() -> verifier.verify(present(payload, List.of(ageOver18)), options), "malformed_sd_jwt");
    }

    @Test
    void oversizedPresentationIsRejected() {
        String huge = "a".repeat(600 * 1024);

        assertFailure(() -> verifier.verify(huge, options), "malformed_sd_jwt");
    }

    private SdJwtVerificationOptions withoutKeyBinding() {
        return new SdJwtVerificationOptions(
                options.algorithms(),
                options.hashAlgorithms(),
                false,
                null,
                null,
                options.keyBindingMaxAge(),
                options.clockSkew(),
                options.clock(),
                options.maxLength(),
                options.maxDisclosures());
    }

    private static String b64(String s) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }
}
