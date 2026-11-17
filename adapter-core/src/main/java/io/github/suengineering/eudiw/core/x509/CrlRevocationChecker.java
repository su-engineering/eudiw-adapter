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

import io.github.suengineering.eudiw.core.VerificationFailure;
import io.github.suengineering.eudiw.core.crypto.Brainpool;
import io.github.suengineering.eudiw.core.net.HttpFetcher;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.PKIXReason;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Checks that no certificate of an already validated chain is revoked, using CRLs (RFC 5280 section 6.3).
 *
 * <p>Every certificate in the chain, apart from the trust anchor, must name an HTTP or HTTPS CRL distribution point
 * and have a CRL that is signed by its issuer, current and does not list it. CRLs are fetched through the {@link
 * HttpFetcher}, so the egress policy applies, and only after the chain has validated, so the URLs come from
 * certificates a trusted CA issued. The JDK's PKIX revocation checker then evaluates them with network fallback
 * disabled: it fetches nothing itself and does not try OCSP.
 *
 * <p>Fetched CRLs are cached until their next update. A missing, unreachable, stale or unverifiable CRL is
 * reported as {@code certificate_status_unknown}, so callers fail closed.
 */
public final class CrlRevocationChecker {

    /** Maximum accepted size of a CRL in bytes. */
    public static final int MAX_BYTES = 8 * 1024 * 1024;

    private final HttpFetcher fetcher;
    private final Clock clock;
    private final Map<String, X509CRL> cache;
    private final Map<String, Instant> failedUntil = new java.util.concurrent.ConcurrentHashMap<>();
    /** Fetches under way, so concurrent checks that miss the cache for one CRL share a single fetch. */
    private final Map<String, java.util.concurrent.CompletableFuture<X509CRL>> inFlight =
            new java.util.concurrent.ConcurrentHashMap<>();

    /** How long a failed fetch is remembered, so an unreachable CRL does not cost a timeout on every check. */
    static final java.time.Duration FAILURE_MEMORY = java.time.Duration.ofSeconds(60);

    public CrlRevocationChecker(HttpFetcher fetcher, Clock clock, int cacheEntries) {
        this.fetcher = Objects.requireNonNull(fetcher, "fetcher");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.cache = Collections.synchronizedMap(new LinkedHashMap<>(16, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, X509CRL> eldest) {
                return size() > cacheEntries;
            }
        });
    }

    /**
     * @param chain the validated chain, end-entity first, trust anchor excluded
     * @param anchor the trusted certificate the chain validated to
     * @throws VerificationFailure {@code certificate_revoked} or {@code certificate_status_unknown}
     */
    public void check(List<X509Certificate> chain, X509Certificate anchor) {
        if (chain.size() == 1 && chain.get(0).equals(anchor)) {
            return; // a directly trusted certificate has no issuer in this path to revoke it
        }
        Instant now = clock.instant();
        List<X509CRL> crls = new ArrayList<>();
        for (X509Certificate certificate : chain) {
            crls.add(crlFor(certificate, now));
        }
        try {
            CertPathValidator validator = CertPathValidator.getInstance("PKIX");
            PKIXRevocationChecker revocation = (PKIXRevocationChecker) validator.getRevocationChecker();
            revocation.setOptions(
                    EnumSet.of(PKIXRevocationChecker.Option.PREFER_CRLS, PKIXRevocationChecker.Option.NO_FALLBACK));
            PKIXParameters parameters = new PKIXParameters(Set.of(new TrustAnchor(anchor, null)));
            parameters.setDate(Date.from(now));
            parameters.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(crls)));
            parameters.setRevocationEnabled(false);
            parameters.addCertPathChecker(revocation);
            Brainpool.applyTo(parameters, chain, List.of(anchor));
            validator.validate(CertificateFactory.getInstance("X.509").generateCertPath(chain), parameters);
        } catch (CertPathValidatorException e) {
            if (e.getReason() == CertPathValidatorException.BasicReason.REVOKED) {
                throw new VerificationFailure("certificate_revoked", "a certificate in the chain is revoked", e);
            }
            if (e.getReason() == PKIXReason.NO_TRUST_ANCHOR) {
                throw new VerificationFailure("certificate_untrusted", "certificate chain does not validate", e);
            }
            throw new VerificationFailure(
                    "certificate_status_unknown", "certificate revocation status cannot be determined", e);
        } catch (GeneralSecurityException e) {
            throw new VerificationFailure(
                    "certificate_status_unknown", "certificate revocation status cannot be determined", e);
        }
    }

    private X509CRL crlFor(X509Certificate certificate, Instant now) {
        List<String> points = CertificateIdentifiers.crlDistributionPoints(certificate);
        if (points.isEmpty()) {
            throw new VerificationFailure(
                    "certificate_status_unknown", "certificate has no HTTP CRL distribution point");
        }
        VerificationFailure last = null;
        for (String point : points) {
            X509CRL cached = cache.get(point);
            if (cached != null && isCurrent(cached, now)) {
                return cached;
            }
            Instant retryAfter = failedUntil.get(point);
            if (retryAfter != null && now.isBefore(retryAfter)) {
                last = new VerificationFailure("certificate_status_unknown", "CRL fetch failed recently");
                continue;
            }
            try {
                X509CRL crl = fetchShared(point);
                if (!isCurrent(crl, now)) {
                    throw new VerificationFailure("certificate_status_unknown", "CRL is not current");
                }
                cache.put(point, crl);
                failedUntil.remove(point);
                return crl;
            } catch (VerificationFailure e) {
                failedUntil.put(point, now.plus(FAILURE_MEMORY));
                last = e;
            }
        }
        throw last;
    }

    /** Fetches a CRL, or waits for the fetch another check already started for the same distribution point. */
    private X509CRL fetchShared(String point) {
        java.util.concurrent.CompletableFuture<X509CRL> mine = new java.util.concurrent.CompletableFuture<>();
        java.util.concurrent.CompletableFuture<X509CRL> running = inFlight.putIfAbsent(point, mine);
        if (running != null) {
            try {
                return running.join();
            } catch (java.util.concurrent.CompletionException e) {
                if (e.getCause() instanceof VerificationFailure failure) {
                    throw failure;
                }
                throw new VerificationFailure("certificate_status_unknown", "CRL cannot be fetched", e.getCause());
            }
        }
        try {
            X509CRL crl = fetch(point);
            mine.complete(crl);
            return crl;
        } catch (RuntimeException e) {
            mine.completeExceptionally(e);
            throw e;
        } finally {
            inFlight.remove(point, mine);
        }
    }

    private X509CRL fetch(String point) {
        byte[] bytes;
        try {
            bytes = fetcher.get(URI.create(point), "application/pkix-crl", MAX_BYTES);
        } catch (HttpFetcher.FetchException | IllegalArgumentException e) {
            throw new VerificationFailure("certificate_status_unknown", "CRL cannot be fetched", e);
        }
        try {
            return (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(new ByteArrayInputStream(bytes));
        } catch (GeneralSecurityException | ClassCastException | IllegalArgumentException e) {
            throw new VerificationFailure("certificate_status_unknown", "CRL cannot be parsed", e);
        }
    }

    /** A CRL is usable while its next update has not passed; a CRL without next update is not accepted. */
    private static boolean isCurrent(X509CRL crl, Instant now) {
        Date next = crl.getNextUpdate();
        return next != null
                && now.isBefore(next.toInstant())
                && !now.isBefore(crl.getThisUpdate().toInstant().minusSeconds(300));
    }
}
