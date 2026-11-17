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
package io.github.suengineering.eudiw.core.status;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.JSONObjectUtils;
import io.github.suengineering.eudiw.core.VerificationFailure;
import io.github.suengineering.eudiw.core.jose.AlgorithmPolicy;
import io.github.suengineering.eudiw.core.net.HttpFetcher;
import io.github.suengineering.eudiw.core.status.StatusDecision.Result;
import io.github.suengineering.eudiw.core.x509.TestPki;
import io.github.suengineering.eudiw.core.x509.TestPki.Issued;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.jupiter.api.Test;

class StatusListCheckerTest {

    private static final String URI = "https://status.test.example/lists/1";
    // section 4 example: statuses 1,0,0,1,1,1,0,1,1,1,0,0,0,1,0,1
    private static final String ONE_BIT = "eNrbuRgAAhcBXQ";
    // section 4 example: statuses 1,2,0,3,0,1,0,1,1,2,3,3
    private static final String TWO_BIT = "eNo76fITAAPfAgc";

    private final Instant now = Instant.parse("2027-01-15T10:00:00Z");
    private final Clock clock = Clock.fixed(now, ZoneOffset.UTC);
    private final Issued root = TestPki.rootCa("CN=Status Root", now.minusSeconds(86400), now.plusSeconds(86400 * 365));
    private final Issued signer = TestPki.endEntity(
            "CN=Status Signer",
            root,
            now.minusSeconds(86400),
            now.plusSeconds(86400 * 30),
            KeyUsage.digitalSignature,
            List.of());

    private final AtomicReference<String> served = new AtomicReference<>();
    private final AtomicInteger fetches = new AtomicInteger();
    private final HttpFetcher fetcher = (uri, accept, maxBytes) -> {
        fetches.incrementAndGet();
        assertThat(accept).isEqualTo("application/statuslist+jwt");
        if (served.get() == null) {
            throw new HttpFetcher.FetchException("not found");
        }
        return served.get().getBytes(StandardCharsets.US_ASCII);
    };

    private StatusListChecker checker() {
        return new StatusListChecker(
                fetcher,
                () -> Set.of(new TrustAnchor(root.certificate(), null)),
                AlgorithmPolicy.DEFAULT,
                clock,
                Duration.ofSeconds(60),
                Duration.ofHours(1),
                100);
    }

    private Map<String, Object> claims(String lst, int bits) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("sub", URI);
        claims.put("iat", now.minusSeconds(60).getEpochSecond());
        claims.put("exp", now.plusSeconds(3600).getEpochSecond());
        claims.put("ttl", 600);
        claims.put("status_list", Map.of("bits", bits, "lst", lst));
        return claims;
    }

    private String token(Map<String, Object> claims) {
        return token(claims, signer.keyPair().getPrivate(), "statuslist+jwt", TestPki.chain(signer));
    }

    private static String token(Map<String, Object> claims, PrivateKey key, String typ, List<X509Certificate> x5c) {
        try {
            JWSHeader.Builder header = new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType(typ));
            if (x5c != null) {
                List<Base64> chain = new ArrayList<>();
                for (X509Certificate c : x5c) {
                    chain.add(Base64.encode(c.getEncoded()));
                }
                header.x509CertChain(chain);
            }
            JWSObject jws = new JWSObject(header.build(), new Payload(JSONObjectUtils.toJSONString(claims)));
            jws.sign(new ECDSASigner((ECPrivateKey) key));
            return jws.serialize();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static Map<String, Object> status(Object idx) {
        Map<String, Object> ref = new LinkedHashMap<>();
        ref.put("idx", idx);
        ref.put("uri", URI);
        return Map.of("status_list", ref);
    }

    @Test
    void validRevokedAndSuspendedStatuses() {
        served.set(token(claims(TWO_BIT, 2)));
        StatusListChecker checker = checker();

        assertThat(checker.check(status(2), "t1").result()).isEqualTo(Result.VALID);
        assertThat(checker.check(status(0), "t1").result()).isEqualTo(Result.INVALID);
        assertThat(checker.check(status(1), "t1").result()).isEqualTo(Result.SUSPENDED);
        assertThat(checker.check(status(3), "t1")).satisfies(d -> {
            assertThat(d.result()).isEqualTo(Result.OTHER);
            assertThat(d.value()).isEqualTo(3);
        });
    }

    @Test
    void listsAreCachedPerScopeAndBoundedByTtl() {
        served.set(token(claims(ONE_BIT, 1)));
        StatusListChecker checker = checker();

        checker.check(status(1), "tenant-a");
        checker.check(status(2), "tenant-a");
        assertThat(fetches).hasValue(1);
        checker.check(status(1), "tenant-b");
        assertThat(fetches).hasValue(2);
    }

    @Test
    void aCachedListIsDroppedWhenItsAnchorIsNoLongerTrusted() {
        served.set(token(claims(ONE_BIT, 1)));
        AtomicReference<Set<TrustAnchor>> anchors =
                new AtomicReference<>(Set.of(new TrustAnchor(root.certificate(), null)));
        StatusListChecker checker = new StatusListChecker(
                fetcher,
                anchors::get,
                AlgorithmPolicy.DEFAULT,
                clock,
                Duration.ofSeconds(60),
                Duration.ofHours(1),
                100);

        assertThat(checker.check(status(1), "t1").result()).isEqualTo(Result.VALID);
        // A trusted list update withdraws the status provider; the configuration revision, and so the scope, stay.
        anchors.set(Set.of());
        assertThat(checker.check(status(1), "t1")).satisfies(d -> {
            assertThat(d.result()).isEqualTo(Result.INDETERMINATE);
            assertThat(d.reason()).contains("certificate_untrusted");
        });
        assertThat(fetches).hasValue(2);
    }

    @Test
    void concurrentChecksShareOneFetch() throws Exception {
        String body = token(claims(ONE_BIT, 1));
        CountDownLatch release = new CountDownLatch(1);
        AtomicInteger calls = new AtomicInteger();
        HttpFetcher slow = (uri, accept, maxBytes) -> {
            calls.incrementAndGet();
            try {
                release.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return body.getBytes(StandardCharsets.US_ASCII);
        };
        StatusListChecker checker = new StatusListChecker(
                slow,
                () -> Set.of(new TrustAnchor(root.certificate(), null)),
                AlgorithmPolicy.DEFAULT,
                clock,
                Duration.ofSeconds(60),
                Duration.ofHours(1),
                100);
        ExecutorService pool = Executors.newFixedThreadPool(8);
        try {
            List<Future<StatusDecision>> results = new ArrayList<>();
            for (int i = 0; i < 8; i++) {
                results.add(pool.submit(() -> checker.check(status(1), "t1")));
            }
            Thread.sleep(200);
            release.countDown();
            for (Future<StatusDecision> result : results) {
                assertThat(result.get(5, TimeUnit.SECONDS).result()).isEqualTo(Result.VALID);
            }
        } finally {
            pool.shutdownNow();
        }
        assertThat(calls).hasValue(1);
    }

    @Test
    void aFailedListIsNotFetchedAgainDuringTheHold() {
        AtomicReference<Instant> time = new AtomicReference<>(now);
        Clock moving = new Clock() {
            @Override
            public java.time.ZoneId getZone() {
                return ZoneOffset.UTC;
            }

            @Override
            public Clock withZone(java.time.ZoneId zone) {
                return this;
            }

            @Override
            public Instant instant() {
                return time.get();
            }
        };
        StatusListChecker checker = new StatusListChecker(
                fetcher,
                () -> Set.of(new TrustAnchor(root.certificate(), null)),
                AlgorithmPolicy.DEFAULT,
                moving,
                Duration.ofSeconds(60),
                Duration.ofHours(1),
                100,
                Duration.ofSeconds(30));

        served.set(null);
        assertThat(checker.check(status(1), "t1").reason()).isEqualTo("status_list_unavailable");
        assertThat(fetches).hasValue(1);
        // The host recovers, but within the hold the failure is remembered and the host is left alone.
        served.set(token(claims(ONE_BIT, 1)));
        time.set(now.plusSeconds(29));
        assertThat(checker.check(status(1), "t1").reason()).isEqualTo("status_list_unavailable");
        assertThat(fetches).hasValue(1);
        // Another scope has its own entry.
        assertThat(checker.check(status(1), "t2").result()).isEqualTo(Result.VALID);
        assertThat(fetches).hasValue(2);
        time.set(now.plusSeconds(31));
        assertThat(checker.check(status(1), "t1").result()).isEqualTo(Result.VALID);
        assertThat(fetches).hasValue(3);
    }

    @Test
    void anUnverifiableListIsAlsoHeld() {
        served.set("garbage");
        StatusListChecker checker = checker();

        assertThat(checker.check(status(1), "t1").reason()).isEqualTo("status_list_invalid");
        assertThat(checker.check(status(1), "t1").reason()).isEqualTo("status_list_invalid");
        assertThat(fetches).hasValue(1);
    }

    @Test
    void aListMustBeSignedUnderTheIssuerAnchorWhenOneIsGiven() {
        Issued otherRoot = TestPki.rootCa("CN=Issuer Root", now.minusSeconds(86400), now.plusSeconds(86400));
        served.set(token(claims(ONE_BIT, 1)));
        StatusListChecker checker = checker();

        assertThat(checker.check(status(1), "t1", false, Optional.of(root.certificate()))
                        .result())
                .isEqualTo(Result.VALID);
        assertThat(checker.check(status(1), "t1", false, Optional.of(otherRoot.certificate())))
                .satisfies(d -> {
                    assertThat(d.result()).isEqualTo(Result.INDETERMINATE);
                    assertThat(d.reason()).isEqualTo("status_signer_not_issuer");
                });
        // The cached list keeps its anchor, so the binding holds on a cache hit too.
        assertThat(fetches).hasValue(1);
    }

    @Test
    void untrustworthyListsAreIndeterminate() {
        Issued otherRoot = TestPki.rootCa("CN=Other", now.minusSeconds(86400), now.plusSeconds(86400));
        Issued otherSigner = TestPki.endEntity(
                "CN=Other Signer",
                otherRoot,
                now.minusSeconds(86400),
                now.plusSeconds(86400),
                KeyUsage.digitalSignature,
                List.of());

        Map<String, String> cases = new LinkedHashMap<>();
        Map<String, Object> wrongSub = claims(ONE_BIT, 1);
        wrongSub.put("sub", "https://status.test.example/lists/2");
        cases.put("wrong sub", token(wrongSub));
        Map<String, Object> expired = claims(ONE_BIT, 1);
        expired.put("exp", now.minusSeconds(3600).getEpochSecond());
        cases.put("expired", token(expired));
        Map<String, Object> noIat = claims(ONE_BIT, 1);
        noIat.remove("iat");
        cases.put("no iat", token(noIat));
        cases.put("wrong typ", token(claims(ONE_BIT, 1), signer.keyPair().getPrivate(), "JWT", TestPki.chain(signer)));
        cases.put("no x5c", token(claims(ONE_BIT, 1), signer.keyPair().getPrivate(), "statuslist+jwt", null));
        cases.put(
                "untrusted chain",
                token(
                        claims(ONE_BIT, 1),
                        otherSigner.keyPair().getPrivate(),
                        "statuslist+jwt",
                        TestPki.chain(otherSigner)));
        cases.put(
                "signed by other key",
                token(claims(ONE_BIT, 1), TestPki.ecKeyPair().getPrivate(), "statuslist+jwt", TestPki.chain(signer)));
        cases.put("bad bits", token(claims(ONE_BIT, 3)));
        cases.put("not a jws", "garbage");

        for (Map.Entry<String, String> c : cases.entrySet()) {
            served.set(c.getValue());
            StatusDecision decision = checker().check(status(0), "t");
            assertThat(decision.result()).as(c.getKey()).isEqualTo(Result.INDETERMINATE);
        }
    }

    @Test
    void unavailableListAndOutOfRangeIndexAreIndeterminate() {
        served.set(null);
        assertThat(checker().check(status(0), "t").reason()).isEqualTo("status_list_unavailable");

        served.set(token(claims(ONE_BIT, 1)));
        assertThat(checker().check(status(16), "t").reason()).isEqualTo("status_index_out_of_range");
    }

    @Test
    void malformedStatusClaimIsRejected() {
        for (Map<String, Object> bad : List.<Map<String, Object>>of(
                Map.of(), status(-1), status(1.5), status("1"), Map.of("status_list", Map.of("idx", 1)))) {
            assertThatThrownBy(() -> checker().check(bad, "t"))
                    .isInstanceOfSatisfying(
                            VerificationFailure.class, f -> assertThat(f.code()).isEqualTo("malformed_credential"));
        }
    }
}
