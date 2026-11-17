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
package io.github.suengineering.eudiw.core.dcql;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.suengineering.eudiw.core.VerificationFailure;
import io.github.suengineering.eudiw.core.dcql.DcqlEvaluator.SelectedCredential;
import io.github.suengineering.eudiw.core.json.Json;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class DcqlTest {

    private static final String VCT = "https://credentials.example.com/identity_credential";

    private static final Map<String, Object> SECTION_7_3_CREDENTIAL = Json.parseObject("""
            {"name":"Arthur Dent",
             "address":{"street_address":"42 Market Street","locality":"Milliways","postal_code":"12345"},
             "degrees":[{"type":"Bachelor of Science","university":"University of Betelgeuse"},
                        {"type":"Master of Science","university":"University of Betelgeuse"}],
             "nationalities":["British","Betelgeusian"]}""", "test");

    @ParameterizedTest
    @ValueSource(ints = {1, 2, 3, 4, 5, 6, 7})
    void specificationExamplesParseAndRoundTrip(int n) {
        DcqlQuery query = DcqlQuery.parse(load("dcql-example-" + n));

        assertThat(DcqlQuery.parse(Json.parseObject(Json.toJson(query.toJson()), "test")))
                .isEqualTo(query);
    }

    @Test
    void intentToRetainIsAnMdocClaimMember() {
        DcqlQuery mdoc = DcqlQuery.parse(Json.parseObject("""
                {"credentials":[{"id":"a","format":"mso_mdoc","meta":{"doctype_value":"d"},
                  "claims":[{"path":["ns","x"],"intent_to_retain":true},{"path":["ns","y"]}]}]}""", "test"));
        assertThat(mdoc.credentials().get(0).claims().get(0).intentToRetain()).isTrue();
        assertThat(mdoc.credentials().get(0).claims().get(1).intentToRetain()).isNull();
        assertThat(Json.toJson(mdoc.toJson()))
                .contains("\"intent_to_retain\":true")
                .doesNotContain("false");
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> DcqlQuery.parse(Json.parseObject("""
                        {"credentials":[{"id":"a","format":"dc+sd-jwt","meta":{"vct_values":["v"]},
                          "claims":[{"path":["x"],"intent_to_retain":true}]}]}""", "test")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void claimsPathPointerExamplesFromSection73() {
        assertThat(ClaimsPath.of("name").select(SECTION_7_3_CREDENTIAL)).contains(List.of("Arthur Dent"));
        assertThat(ClaimsPath.of("address", "street_address").select(SECTION_7_3_CREDENTIAL))
                .contains(List.of("42 Market Street"));
        assertThat(ClaimsPath.of("degrees", null, "type").select(SECTION_7_3_CREDENTIAL))
                .contains(List.of("Bachelor of Science", "Master of Science"));
        assertThat(ClaimsPath.of("nationalities", 1).select(SECTION_7_3_CREDENTIAL))
                .contains(List.of("Betelgeusian"));
        assertThat(ClaimsPath.of("address")
                        .select(SECTION_7_3_CREDENTIAL)
                        .orElseThrow()
                        .get(0))
                .isInstanceOf(Map.class);
    }

    @Test
    void claimsPathPointerErrors() {
        assertThat(ClaimsPath.of("missing").select(SECTION_7_3_CREDENTIAL)).isEmpty();
        assertThat(ClaimsPath.of("name", "x").select(SECTION_7_3_CREDENTIAL)).isEmpty();
        assertThat(ClaimsPath.of("address", null).select(SECTION_7_3_CREDENTIAL))
                .isEmpty();
        assertThat(ClaimsPath.of("nationalities", 5).select(SECTION_7_3_CREDENTIAL))
                .isEmpty();
        assertThatThrownBy(() -> ClaimsPath.of("a", -1)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ClaimsPath.of("a", 1.5)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new ClaimsPath(List.of())).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void invalidQueriesAreRejected() {
        List<String> invalid = List.of(
                "{}",
                "{\"credentials\":[]}",
                "{\"credentials\":[{\"id\":\"a b\",\"format\":\"dc+sd-jwt\",\"meta\":{\"vct_values\":[\"x\"]}}]}",
                "{\"credentials\":[{\"id\":\"a\",\"format\":\"jwt_vc_json\",\"meta\":{}}]}",
                "{\"credentials\":[{\"id\":\"a\",\"format\":\"dc+sd-jwt\",\"meta\":{}}]}",
                "{\"credentials\":[{\"id\":\"a\",\"format\":\"mso_mdoc\",\"meta\":{}}]}",
                "{\"credentials\":[{\"id\":\"a\",\"format\":\"dc+sd-jwt\",\"meta\":{\"vct_values\":[\"x\"]}},"
                        + "{\"id\":\"a\",\"format\":\"dc+sd-jwt\",\"meta\":{\"vct_values\":[\"x\"]}}]}",
                "{\"credentials\":[{\"id\":\"a\",\"format\":\"mso_mdoc\",\"meta\":{\"doctype_value\":\"d\"},"
                        + "\"claims\":[{\"path\":[\"only-one\"]}]}]}",
                "{\"credentials\":[{\"id\":\"a\",\"format\":\"dc+sd-jwt\",\"meta\":{\"vct_values\":[\"x\"]},"
                        + "\"claims\":[{\"path\":[\"n\"]}],\"claim_sets\":[[\"n\"]]}]}",
                "{\"credentials\":[{\"id\":\"a\",\"format\":\"dc+sd-jwt\",\"meta\":{\"vct_values\":[\"x\"]},"
                        + "\"claims\":[{\"path\":[\"n\"]},{\"path\":[\"n\"]}]}]}",
                "{\"credentials\":[{\"id\":\"a\",\"format\":\"dc+sd-jwt\",\"meta\":{\"vct_values\":[\"x\"]}}],"
                        + "\"credential_sets\":[{\"options\":[[\"b\"]]}]}",
                "{\"credentials\":[{\"id\":\"a\",\"format\":\"dc+sd-jwt\",\"meta\":{\"vct_values\":[\"x\"]},"
                        + "\"claims\":[{\"path\":[\"n\"],\"values\":[{\"o\":1}]}]}]}");
        for (String json : invalid) {
            assertThatThrownBy(() -> DcqlQuery.parse(Json.parseObject(json, "test")))
                    .as(json)
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    void returnsOnlyRequestedClaims() {
        DcqlQuery query = DcqlQuery.parse(load("dcql-example-7"));
        Map<String, Object> claims = Json.parseObject("""
                {"vct":"%s","last_name":"Dent","first_name":"Arthur",
                 "address":{"street_address":"42 Market Street","locality":"Milliways"},
                 "birthdate":"1952-03-11"}""".formatted(VCT), "test");

        Map<String, List<SelectedCredential>> result =
                new DcqlEvaluator(true).evaluate(query, Map.of("my_credential", List.of(sdJwt(claims))));

        List<DcqlEvaluator.DisclosedClaim> disclosed =
                result.get("my_credential").get(0).claims();
        assertThat(disclosed).extracting(c -> c.values().get(0)).containsExactly("Dent", "Arthur", "42 Market Street");
    }

    @Test
    void missingClaimFailsTheCredential() {
        DcqlQuery query = DcqlQuery.parse(load("dcql-example-7"));
        Map<String, Object> claims = Map.of("last_name", "Dent", "first_name", "Arthur");

        assertFailure(
                () -> new DcqlEvaluator(true).evaluate(query, Map.of("my_credential", List.of(sdJwt(claims)))),
                "claims_not_satisfied");
    }

    @Test
    void claimSetsPickTheFirstSatisfiedOption() {
        DcqlQuery query = DcqlQuery.parse(Json.parseObject("""
                {"credentials":[{"id":"age","format":"dc+sd-jwt","meta":{"vct_values":["%s"]},
                  "claims":[{"id":"over18","path":["age_over_18"],"values":[true]},
                            {"id":"birthdate","path":["birthdate"]}],
                  "claim_sets":[["over18"],["birthdate"]]}]}""".formatted(VCT), "test"));

        SelectedCredential over18 = new DcqlEvaluator(true)
                .evaluate(query, Map.of("age", List.of(sdJwt(Map.of("age_over_18", true, "birthdate", "2000-01-01")))))
                .get("age")
                .get(0);
        assertThat(over18.claims()).singleElement().satisfies(c -> assertThat(c.path())
                .isEqualTo(ClaimsPath.of("age_over_18")));

        SelectedCredential fallback = new DcqlEvaluator(true)
                .evaluate(query, Map.of("age", List.of(sdJwt(Map.of("age_over_18", false, "birthdate", "2000-01-01")))))
                .get("age")
                .get(0);
        assertThat(fallback.claims()).singleElement().satisfies(c -> assertThat(c.values())
                .containsExactly("2000-01-01"));

        assertFailure(
                () -> new DcqlEvaluator(true)
                        .evaluate(query, Map.of("age", List.of(sdJwt(Map.of("age_over_18", false))))),
                "claims_not_satisfied");
    }

    @Test
    void valueMatchingRequiresTypeAndValue() {
        assertThat(DcqlEvaluator.valueEquals(18L, 18L)).isTrue();
        assertThat(DcqlEvaluator.valueEquals(18L, 18.0d)).isTrue();
        assertThat(DcqlEvaluator.valueEquals(18L, "18")).isFalse();
        assertThat(DcqlEvaluator.valueEquals("true", true)).isFalse();
        assertThat(DcqlEvaluator.valueEquals(true, true)).isTrue();
    }

    @Test
    void credentialSetsFromAppendixD() {
        DcqlQuery query = DcqlQuery.parse(load("dcql-example-3"));
        PresentedCredential reduced1 = sdJwt(
                "https://credentials.example.com/reduced_identity_credential",
                Map.of("family_name", "D", "given_name", "A"));
        PresentedCredential reduced2 = sdJwt(
                "https://cred.example/residence_credential",
                Map.of("postal_code", "1", "locality", "L", "region", "R"));

        assertThat(new DcqlEvaluator(true)
                        .evaluate(
                                query,
                                Map.of(
                                        "pid_reduced_cred_1",
                                        List.of(reduced1),
                                        "pid_reduced_cred_2",
                                        List.of(reduced2)))
                        .keySet())
                .containsExactlyInAnyOrder("pid_reduced_cred_1", "pid_reduced_cred_2");

        assertFailure(
                () -> new DcqlEvaluator(true).evaluate(query, Map.of("pid_reduced_cred_1", List.of(reduced1))),
                "credentials_not_satisfied");
    }

    @Test
    void responseStructureIsChecked() {
        DcqlQuery query = DcqlQuery.parse(load("dcql-example-7"));
        Map<String, Object> claims =
                Map.of("last_name", "D", "first_name", "A", "address", Map.of("street_address", "S"));

        assertFailure(
                () -> new DcqlEvaluator(true).evaluate(query, Map.of("other", List.of(sdJwt(claims)))),
                "unexpected_credential");
        assertFailure(
                () -> new DcqlEvaluator(true)
                        .evaluate(query, Map.of("my_credential", List.of(sdJwt(claims), sdJwt(claims)))),
                "invalid_vp_token");
        assertFailure(() -> new DcqlEvaluator(true).evaluate(query, Map.of()), "credentials_not_satisfied");
        assertFailure(
                () -> new DcqlEvaluator(true)
                        .evaluate(query, Map.of("my_credential", List.of(sdJwt("https://other.example", claims)))),
                "credential_mismatch");
        PresentedCredential unbound =
                new PresentedCredential("dc+sd-jwt", VCT, "iss", claims, false, Set.of(), Set.of());
        assertFailure(
                () -> new DcqlEvaluator(true).evaluate(query, Map.of("my_credential", List.of(unbound))),
                "holder_binding_missing");
    }

    @Test
    void anMdocAgeAttestationAnswersANearbyAgeRequest() {
        String ns = "eu.europa.ec.eudi.pid.1";
        DcqlQuery query = DcqlQuery.parse(Json.parseObject("""
                {"credentials":[{"id":"pid","format":"mso_mdoc","meta":{"doctype_value":"%s"},
                  "claims":[{"path":["%s","age_over_18"],"values":[true]}]}]}""".formatted(ns, ns), "test"));
        java.util.function.Function<Map<String, Object>, Map<String, List<SelectedCredential>>> evaluate =
                elements -> new DcqlEvaluator(true)
                        .evaluate(
                                query,
                                Map.of(
                                        "pid",
                                        List.of(new PresentedCredential(
                                                "mso_mdoc",
                                                ns,
                                                "iss",
                                                Map.of(ns, elements),
                                                true,
                                                Set.of(),
                                                Set.of()))));

        // Over 21 proves over 18; the answer is reported under the requested element only.
        DcqlEvaluator.DisclosedClaim claim = evaluate.apply(Map.of("age_over_21", true))
                .get("pid")
                .get(0)
                .claims()
                .get(0);
        assertThat(claim.path().components()).containsExactly(ns, "age_over_18");
        assertThat(claim.values()).containsExactly(true);
        // The exact element wins.
        assertThat(evaluate.apply(Map.of("age_over_18", true, "age_over_16", false)))
                .containsKey("pid");
        // Not over 16 proves not over 18, which fails values:[true].
        assertFailure(() -> evaluate.apply(Map.of("age_over_16", false)), "claims_not_satisfied");
        // Over 16 says nothing about 18, and contradicting attestations answer nothing.
        assertFailure(() -> evaluate.apply(Map.of("age_over_16", true)), "claims_not_satisfied");
        assertFailure(() -> evaluate.apply(Map.of("age_over_21", true, "age_over_16", false)), "claims_not_satisfied");
        // Only for mdoc.
        assertFailure(
                () -> new DcqlEvaluator(true)
                        .evaluate(
                                DcqlQuery.parse(Json.parseObject("""
                        {"credentials":[{"id":"c","format":"dc+sd-jwt","meta":{"vct_values":["%s"]},
                          "claims":[{"path":["age_over_18"]}]}]}""".formatted(VCT), "test")),
                                Map.of(
                                        "c",
                                        List.of(new PresentedCredential(
                                                "dc+sd-jwt",
                                                VCT,
                                                "iss",
                                                Map.of("age_over_21", true),
                                                true,
                                                Set.of(),
                                                Set.of())))),
                "claims_not_satisfied");
    }

    @Test
    void trustedAuthoritiesAreEnforcedWhenConfigured() {
        DcqlQuery query = DcqlQuery.parse(Json.parseObject("""
                {"credentials":[{"id":"c","format":"dc+sd-jwt","meta":{"vct_values":["%s"]},
                  "trusted_authorities":[{"type":"aki","values":["s9tIpPmhxdiuNkHMEWNpYim8S8Y"]},
                                         {"type":"etsi_tl","values":["https://lotl.example.com"]}]}]}""".formatted(VCT), "test"));
        PresentedCredential byAki = new PresentedCredential(
                "dc+sd-jwt", VCT, "iss", Map.of(), true, Set.of("s9tIpPmhxdiuNkHMEWNpYim8S8Y"), Set.of());
        PresentedCredential byList = new PresentedCredential(
                "dc+sd-jwt", VCT, "iss", Map.of(), true, Set.of(), Set.of("https://lotl.example.com"));
        PresentedCredential neither =
                new PresentedCredential("dc+sd-jwt", VCT, "iss", Map.of(), true, Set.of("other"), Set.of());

        DcqlEvaluator enforcing = new DcqlEvaluator(true);
        assertThat(enforcing.evaluate(query, Map.of("c", List.of(byAki)))).containsKey("c");
        assertThat(enforcing.evaluate(query, Map.of("c", List.of(byList)))).containsKey("c");
        assertFailure(() -> enforcing.evaluate(query, Map.of("c", List.of(neither))), "untrusted_authority");
        assertThat(new DcqlEvaluator(false).evaluate(query, Map.of("c", List.of(neither))))
                .containsKey("c");
    }

    private static PresentedCredential sdJwt(Map<String, Object> claims) {
        return sdJwt(VCT, claims);
    }

    private static PresentedCredential sdJwt(String vct, Map<String, Object> claims) {
        return new PresentedCredential("dc+sd-jwt", vct, "https://issuer.example", claims, true, Set.of(), Set.of());
    }

    private static Map<String, Object> load(String name) {
        try (InputStream in = DcqlTest.class.getResourceAsStream("/openid4vp/" + name + ".json")) {
            return Json.parseObject(new String(in.readAllBytes(), StandardCharsets.UTF_8), "test");
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static void assertFailure(org.assertj.core.api.ThrowableAssert.ThrowingCallable call, String code) {
        assertThatThrownBy(call).isInstanceOfSatisfying(VerificationFailure.class, f -> assertThat(f.code())
                .isEqualTo(code));
    }
}
