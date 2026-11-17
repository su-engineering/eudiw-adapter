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
package io.github.suengineering.eudiw.core.x509;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.suengineering.eudiw.core.VerificationFailure;
import io.github.suengineering.eudiw.core.net.HttpFetcher;
import java.security.cert.TrustAnchor;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.jupiter.api.Test;

class CrlRevocationCheckerTest {

    private static final Instant NOW = Instant.parse("2026-11-17T10:00:00Z");
    private static final Instant FROM = NOW.minus(Duration.ofDays(10));
    private static final Instant UNTIL = NOW.plus(Duration.ofDays(400));
    private static final String ROOT_CRL = "http://crl.example/root.crl";
    private static final String CA_CRL = "http://crl.example/ca.crl";

    private final TestPki.Issued root = TestPki.rootCa("CN=Root", FROM, UNTIL);
    private final TestPki.Issued ca = TestPki.withCrl(
            "CN=Issuing CA", root, true, KeyUsage.keyCertSign | KeyUsage.cRLSign, FROM, UNTIL, ROOT_CRL);
    private final TestPki.Issued leaf =
            TestPki.withCrl("CN=Issuer", ca, false, KeyUsage.digitalSignature, FROM, UNTIL, CA_CRL);
    private final List<java.security.cert.X509Certificate> chain = List.of(leaf.certificate(), ca.certificate());

    private final Map<String, byte[]> served = new HashMap<>();
    private final List<String> fetched = new ArrayList<>();
    private final HttpFetcher fetcher = (uri, accept, max) -> {
        fetched.add(uri.toString());
        byte[] body = served.get(uri.toString());
        if (body == null) {
            throw new HttpFetcher.FetchException("not found");
        }
        return body;
    };
    private final CrlRevocationChecker checker =
            new CrlRevocationChecker(fetcher, Clock.fixed(NOW, ZoneOffset.UTC), 16);

    private void serveCurrentCrls(java.security.cert.X509Certificate... revokedByCa) {
        served.put(ROOT_CRL, TestPki.crl(root, NOW.minus(Duration.ofHours(1)), NOW.plus(Duration.ofDays(1))));
        served.put(CA_CRL, TestPki.crl(ca, NOW.minus(Duration.ofHours(1)), NOW.plus(Duration.ofDays(1)), revokedByCa));
    }

    @Test
    void readsTheDistributionPoint() {
        assertThat(CertificateIdentifiers.crlDistributionPoints(leaf.certificate()))
                .containsExactly(CA_CRL);
        assertThat(CertificateIdentifiers.crlDistributionPoints(root.certificate()))
                .isEmpty();
    }

    @Test
    void acceptsAChainWhoseCrlsDoNotListIt() {
        serveCurrentCrls();
        assertThatCode(() -> checker.check(chain, root.certificate())).doesNotThrowAnyException();
    }

    @Test
    void rejectsARevokedEndEntity() {
        serveCurrentCrls(leaf.certificate());
        assertFailure(() -> checker.check(chain, root.certificate()), "certificate_revoked");
    }

    @Test
    void rejectsARevokedIntermediate() {
        serveCurrentCrls();
        served.put(
                ROOT_CRL,
                TestPki.crl(root, NOW.minus(Duration.ofHours(1)), NOW.plus(Duration.ofDays(1)), ca.certificate()));
        assertFailure(() -> checker.check(chain, root.certificate()), "certificate_revoked");
    }

    @Test
    void failsClosedWhenACrlIsUnavailableStaleOrForged() {
        serveCurrentCrls();
        served.remove(CA_CRL);
        assertFailure(() -> checker.check(chain, root.certificate()), "certificate_status_unknown");

        served.put(CA_CRL, TestPki.crl(ca, NOW.minus(Duration.ofDays(3)), NOW.minus(Duration.ofDays(1))));
        assertFailure(() -> checker.check(chain, root.certificate()), "certificate_status_unknown");

        served.put(CA_CRL, TestPki.crl(ca, NOW.minus(Duration.ofHours(1)), null));
        assertFailure(() -> checker.check(chain, root.certificate()), "certificate_status_unknown");

        TestPki.Issued impostor = TestPki.rootCa("CN=Issuing CA", FROM, UNTIL);
        served.put(CA_CRL, TestPki.crl(impostor, NOW.minus(Duration.ofHours(1)), NOW.plus(Duration.ofDays(1))));
        assertFailure(() -> checker.check(chain, root.certificate()), "certificate_status_unknown");

        served.put(CA_CRL, "not a crl".getBytes());
        assertFailure(() -> checker.check(chain, root.certificate()), "certificate_status_unknown");
    }

    @Test
    void aFailedFetchIsNotRetriedOnEveryCheck() {
        java.util.concurrent.atomic.AtomicReference<Instant> now =
                new java.util.concurrent.atomic.AtomicReference<>(NOW);
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
                return now.get();
            }
        };
        CrlRevocationChecker remembering = new CrlRevocationChecker(fetcher, moving, 16);
        assertFailure(() -> remembering.check(chain, root.certificate()), "certificate_status_unknown");
        assertFailure(() -> remembering.check(chain, root.certificate()), "certificate_status_unknown");
        assertThat(fetched).containsExactly(CA_CRL);

        serveCurrentCrls();
        now.set(NOW.plus(CrlRevocationChecker.FAILURE_MEMORY).plusSeconds(1));
        assertThatCode(() -> remembering.check(chain, root.certificate())).doesNotThrowAnyException();
    }

    @Test
    void concurrentChecksShareOneFetchPerCrl() throws Exception {
        serveCurrentCrls();
        java.util.concurrent.CountDownLatch release = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.atomic.AtomicInteger fetches = new java.util.concurrent.atomic.AtomicInteger();
        HttpFetcher slow = (uri, accept, max) -> {
            fetches.incrementAndGet();
            try {
                release.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return served.get(uri.toString());
        };
        CrlRevocationChecker shared = new CrlRevocationChecker(slow, Clock.fixed(NOW, ZoneOffset.UTC), 16);
        int threads = 8;
        java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(threads);
        try {
            List<java.util.concurrent.Future<?>> checks = new ArrayList<>();
            for (int i = 0; i < threads; i++) {
                checks.add(pool.submit(() -> shared.check(chain, root.certificate())));
            }
            long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
            while (fetches.get() < 1 && System.nanoTime() < deadline) {
                Thread.onSpinWait();
            }
            Thread.sleep(200);
            release.countDown();
            for (java.util.concurrent.Future<?> check : checks) {
                check.get(10, java.util.concurrent.TimeUnit.SECONDS);
            }
        } finally {
            pool.shutdownNow();
        }
        // One fetch for the issuing CA's CRL and one for the root's, however many checks ran at once.
        assertThat(fetches.get()).isEqualTo(2);
    }

    @Test
    void aCertificateWithoutDistributionPointCannotBeChecked() {
        TestPki.Issued plain = TestPki.endEntity("CN=Plain", ca, FROM, UNTIL, KeyUsage.digitalSignature, List.of());
        serveCurrentCrls();
        assertFailure(
                () -> checker.check(List.of(plain.certificate(), ca.certificate()), root.certificate()),
                "certificate_status_unknown");
    }

    @Test
    void cachesCrlsUntilTheirNextUpdate() {
        serveCurrentCrls();
        checker.check(chain, root.certificate());
        checker.check(chain, root.certificate());
        assertThat(fetched).containsExactly(CA_CRL, ROOT_CRL);
    }

    @Test
    void aDirectlyTrustedCertificateNeedsNoCrl() {
        assertThatCode(() -> checker.check(List.of(leaf.certificate()), leaf.certificate()))
                .doesNotThrowAnyException();
        assertThat(fetched).isEmpty();
    }

    @Test
    void theResolverChecksRevocationAfterTheChainValidates() throws Exception {
        serveCurrentCrls(leaf.certificate());
        TrustStore store = TrustStore.ofAnchors(Set.of(new TrustAnchor(root.certificate(), null)));
        var resolver = io.github.suengineering.eudiw.core.sdjwt.X5cIssuerKeyResolver.withTrustStore(
                () -> store, Clock.fixed(NOW, ZoneOffset.UTC), checker);
        var header = new com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.ES256)
                .x509CertChain(List.of(
                        com.nimbusds.jose.util.Base64.encode(leaf.certificate().getEncoded()),
                        com.nimbusds.jose.util.Base64.encode(ca.certificate().getEncoded())))
                .build();
        assertFailure(() -> resolver.resolve(header, Map.of()), "certificate_revoked");

        // An untrusted chain is refused before any CRL is fetched.
        fetched.clear();
        TrustStore other = TrustStore.ofAnchors(
                Set.of(new TrustAnchor(TestPki.rootCa("CN=Other", FROM, UNTIL).certificate(), null)));
        var strict = io.github.suengineering.eudiw.core.sdjwt.X5cIssuerKeyResolver.withTrustStore(
                () -> other, Clock.fixed(NOW, ZoneOffset.UTC), checker);
        assertFailure(() -> strict.resolve(header, Map.of()), "certificate_untrusted");
        assertThat(fetched).isEmpty();
    }

    private static void assertFailure(org.assertj.core.api.ThrowableAssert.ThrowingCallable call, String code) {
        assertThatThrownBy(call).isInstanceOfSatisfying(VerificationFailure.class, f -> assertThat(f.code())
                .isEqualTo(code));
    }
}
