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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.JWSAlgorithm;
import io.github.suengineering.eudiw.core.VerificationFailure;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;

/**
 * {@code transaction_data_hashes} in the Key Binding JWT (OpenID4VP 1.0 appendix B.3.3.1): sha-256 over each
 * {@code transaction_data} string exactly as sent, in any order, none missing and none extra.
 */
class TransactionDataBindingTest {

    private static final String AUD = "x509_hash:verifier";
    private static final String NONCE = "n-0S6_WzA2Mj";
    private static final long NOW = 1_800_000_000L;

    private static final String PAYMENT = b64(
            "{\"type\":\"urn:test:payment\",\"credential_ids\":[\"pid\"],\"amount\":\"42.00\",\"currency\":\"EUR\"}");
    private static final String LOGIN = b64("{\"type\":\"urn:test:login\",\"credential_ids\":[\"pid\"]}");

    private final TestSdJwtIssuer issuer = new TestSdJwtIssuer();
    private final SdJwtVerifier verifier =
            new SdJwtVerifier(new StaticIssuerKeyResolver(Map.of(ISSUER, issuer.issuerKey.toPublicJWK())));
    private final String ageOver18 = disclosure("salt-age-over-18", "age_over_18", true);

    private SdJwtVerificationOptions options(List<String> transactionData) {
        return SdJwtVerificationOptions.keyBound(AUD, NONCE)
                .withClock(Clock.fixed(Instant.ofEpochSecond(NOW), ZoneOffset.UTC))
                .withTransactionData(transactionData);
    }

    /** A presentation whose Key Binding JWT has the usual claims plus whatever {@code extra} adds. */
    private String present(Consumer<Map<String, Object>> extra) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", ISSUER);
        payload.put("vct", "https://credentials.test.example/age");
        payload.put("exp", NOW + 3600);
        payload.put("_sd", List.of(digest(ageOver18)));
        payload.put("cnf", issuer.cnf());
        String sdJwt = TestSdJwtIssuer.sdJwt(issuer.sign(payload), List.of(ageOver18));
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("aud", AUD);
        claims.put("nonce", NONCE);
        claims.put("iat", NOW);
        claims.put("sd_hash", SdJwtVerifier.digest("sha-256", sdJwt));
        extra.accept(claims);
        return sdJwt + TestSdJwtIssuer.sign(claims, issuer.holderKey, JWSAlgorithm.ES256, "kb+jwt");
    }

    @Test
    void hashesOfEachStringAsSentAreAcceptedInAnyOrder() {
        String presentation = present(c -> c.put("transaction_data_hashes", List.of(hash(LOGIN), hash(PAYMENT))));

        assertThat(verifier.verify(presentation, options(List.of(PAYMENT, LOGIN)))
                        .keyBindingVerified())
                .isTrue();
    }

    @Test
    void anExplicitSha256IsAccepted() {
        String presentation = present(c -> {
            c.put("transaction_data_hashes", List.of(hash(PAYMENT)));
            c.put("transaction_data_hashes_alg", "sha-256");
        });

        assertThat(verifier.verify(presentation, options(List.of(PAYMENT))).keyBindingVerified())
                .isTrue();
    }

    @Test
    void missingHashesAreRejected() {
        assertRejected(present(c -> {}), List.of(PAYMENT));
        assertRejected(present(c -> c.put("transaction_data_hashes", List.of())), List.of(PAYMENT));
    }

    @Test
    void aMissingEntryIsRejected() {
        assertRejected(present(c -> c.put("transaction_data_hashes", List.of(hash(PAYMENT)))), List.of(PAYMENT, LOGIN));
    }

    @Test
    void aWrongOrExtraHashIsRejected() {
        String other = b64("{\"type\":\"urn:test:payment\",\"credential_ids\":[\"pid\"],\"amount\":\"9999.00\"}");
        assertRejected(present(c -> c.put("transaction_data_hashes", List.of(hash(other)))), List.of(PAYMENT));
        assertRejected(
                present(c -> c.put("transaction_data_hashes", List.of(hash(PAYMENT), hash(other)))), List.of(PAYMENT));
        assertRejected(
                present(c -> c.put("transaction_data_hashes", List.of(hash(PAYMENT), hash(PAYMENT)))),
                List.of(PAYMENT));
    }

    @Test
    void aHashOverTheDecodedJsonIsRejected() {
        String decoded = new String(Base64.getUrlDecoder().decode(PAYMENT), StandardCharsets.UTF_8);
        assertRejected(present(c -> c.put("transaction_data_hashes", List.of(hash(decoded)))), List.of(PAYMENT));
    }

    @Test
    void anotherAlgorithmIsRejected() {
        assertRejected(
                present(c -> {
                    c.put("transaction_data_hashes", List.of(hash(PAYMENT)));
                    c.put("transaction_data_hashes_alg", "sha-512");
                }),
                List.of(PAYMENT));
    }

    @Test
    void hashesNobodyAskedForAreRejected() {
        assertRejected(present(c -> c.put("transaction_data_hashes", List.of(hash(PAYMENT)))), List.of());
    }

    private void assertRejected(String presentation, List<String> transactionData) {
        assertThatThrownBy(() -> verifier.verify(presentation, options(transactionData)))
                .isInstanceOf(VerificationFailure.class)
                .extracting(f -> ((VerificationFailure) f).code())
                .isEqualTo("transaction_data_mismatch");
    }

    private static String b64(String json) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    private static String hash(String value) {
        return SdJwtVerifier.digest("sha-256", value);
    }
}
