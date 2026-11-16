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

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64;
import io.github.suengineering.eudiw.core.VerificationFailure;
import io.github.suengineering.eudiw.core.jose.AlgorithmPolicy;
import io.github.suengineering.eudiw.core.jose.JwsSignatureVerifier;
import io.github.suengineering.eudiw.core.json.Json;
import io.github.suengineering.eudiw.core.net.HttpFetcher;
import io.github.suengineering.eudiw.core.x509.CertificateChainValidator;
import io.github.suengineering.eudiw.core.x509.CertificateKeys;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64.Decoder;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Supplier;

/**
 * Resolves the status of a Referenced Token from a Status List Token in JWT format (Token Status List draft 14,
 * section 8.3). The Status List Token must be signed with a key from an {@code x5c} chain that validates to the
 * configured trust anchors (HAIP 1.0 section 6.1).
 *
 * <p>A list that cannot be fetched, verified or indexed yields {@link StatusDecision.Result#INDETERMINATE}; the
 * caller's policy decides whether that rejects the credential.
 */
public final class StatusListChecker {

    private static final JOSEObjectType TYPE = new JOSEObjectType("statuslist+jwt");
    private static final String ACCEPT = "application/statuslist+jwt";
    private static final double MAX_NUMERIC_DATE = 253_402_300_799d;

    private final HttpFetcher fetcher;
    private final Supplier<Set<TrustAnchor>> trustAnchors;
    private final AlgorithmPolicy algorithms;
    private final Clock clock;
    private final Duration clockSkew;
    private final Duration maxCacheAge;
    private final int maxTokenBytes;
    private final int maxListBytes;
    private final Map<String, CachedList> cache;
    private final int maxCacheEntries;

    private record CachedList(StatusList list, Instant until) {}

    public StatusListChecker(
            HttpFetcher fetcher,
            Supplier<Set<TrustAnchor>> trustAnchors,
            AlgorithmPolicy algorithms,
            Clock clock,
            Duration clockSkew,
            Duration maxCacheAge,
            int maxCacheEntries) {
        this.fetcher = Objects.requireNonNull(fetcher, "fetcher");
        this.trustAnchors = Objects.requireNonNull(trustAnchors, "trustAnchors");
        this.algorithms = Objects.requireNonNull(algorithms, "algorithms");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.clockSkew = Objects.requireNonNull(clockSkew, "clockSkew");
        this.maxCacheAge = Objects.requireNonNull(maxCacheAge, "maxCacheAge");
        this.maxTokenBytes = 4 * 1024 * 1024;
        this.maxListBytes = StatusList.DEFAULT_MAX_BYTES;
        this.maxCacheEntries = maxCacheEntries;
        this.cache = new LinkedHashMap<>(16, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, CachedList> eldest) {
                return size() > StatusListChecker.this.maxCacheEntries;
            }
        };
    }

    /**
     * @param statusClaim the verified {@code status} claim of the Referenced Token
     * @param cacheScope isolates cached lists, for example tenant and trust profile revision
     * @throws VerificationFailure {@code malformed_credential} when the status claim itself is malformed
     */
    public StatusDecision check(Map<String, Object> statusClaim, String cacheScope) {
        if (!(statusClaim.get("status_list") instanceof Map<?, ?> reference)) {
            throw new VerificationFailure("malformed_credential", "status claim has no status_list");
        }
        Object idx = reference.get("idx");
        if (!(idx instanceof Number n)
                || !inRange(n.doubleValue(), Integer.MAX_VALUE)
                || n.doubleValue() != Math.rint(n.doubleValue())) {
            throw new VerificationFailure("malformed_credential", "status_list.idx must be a non-negative integer");
        }
        if (!(reference.get("uri") instanceof String uri)) {
            throw new VerificationFailure("malformed_credential", "status_list.uri must be a string");
        }

        StatusList list;
        try {
            list = resolve(uri, cacheScope);
        } catch (VerificationFailure failure) {
            return StatusDecision.indeterminate(failure.code());
        }
        int value;
        try {
            value = list.statusAt(n.longValue());
        } catch (VerificationFailure failure) {
            return StatusDecision.indeterminate(failure.code());
        }
        return StatusDecision.of(value);
    }

    private StatusList resolve(String uri, String cacheScope) {
        String key = cacheScope + "\n" + uri;
        Instant now = clock.instant();
        synchronized (cache) {
            CachedList cached = cache.get(key);
            if (cached != null && now.isBefore(cached.until())) {
                return cached.list();
            }
        }
        byte[] body;
        try {
            body = fetcher.get(URI.create(uri), ACCEPT, maxTokenBytes);
        } catch (HttpFetcher.FetchException | IllegalArgumentException e) {
            throw new VerificationFailure("status_list_unavailable", "status list cannot be fetched", e);
        }
        Verified verified = verifyToken(new String(body, StandardCharsets.US_ASCII).strip(), uri, now);
        synchronized (cache) {
            cache.put(key, new CachedList(verified.list(), verified.cacheUntil()));
        }
        return verified.list();
    }

    private record Verified(StatusList list, Instant cacheUntil) {}

    Verified verifyToken(String compact, String expectedUri, Instant now) {
        JWSObject jws;
        try {
            jws = JWSObject.parse(compact);
        } catch (ParseException e) {
            throw new VerificationFailure("status_list_invalid", "status list token is not a JWS", e);
        }
        if (!TYPE.equals(jws.getHeader().getType())) {
            throw new VerificationFailure("status_list_invalid", "typ must be statuslist+jwt");
        }
        List<Base64> x5c = jws.getHeader().getX509CertChain();
        if (x5c == null || x5c.isEmpty()) {
            throw new VerificationFailure("status_list_invalid", "status list token has no x5c header");
        }
        List<X509Certificate> chain =
                CertificateChainValidator.parse(x5c.stream().map(Base64::decode).toList());
        X509Certificate signer = CertificateChainValidator.validate(chain, trustAnchors.get(), now);
        JWK key = CertificateKeys.publicJwk(signer);
        JwsSignatureVerifier.verify(jws, key, algorithms);

        Map<String, Object> claims = Json.parseObject(jws.getPayload().toString(), "status_list_invalid");
        if (!expectedUri.equals(claims.get("sub"))) {
            throw new VerificationFailure("status_list_invalid", "sub does not match the status list uri");
        }
        if (!(claims.get("iat") instanceof Number)) {
            throw new VerificationFailure("status_list_invalid", "iat is required");
        }
        Instant cacheUntil = now.plus(maxCacheAge);
        if (claims.get("exp") != null) {
            if (!(claims.get("exp") instanceof Number exp) || !inRange(exp.doubleValue(), MAX_NUMERIC_DATE)) {
                throw new VerificationFailure("status_list_invalid", "exp must be a valid NumericDate");
            }
            Instant expiry = Instant.ofEpochSecond(exp.longValue());
            if (now.isAfter(expiry.plus(clockSkew))) {
                throw new VerificationFailure("status_list_invalid", "status list token has expired");
            }
            cacheUntil = min(cacheUntil, expiry);
        }
        if (claims.get("ttl") != null) {
            if (!(claims.get("ttl") instanceof Number ttl)
                    || ttl.doubleValue() <= 0
                    || !inRange(ttl.doubleValue(), MAX_NUMERIC_DATE)) {
                throw new VerificationFailure("status_list_invalid", "ttl must be a positive number");
            }
            cacheUntil = min(cacheUntil, now.plusSeconds(ttl.longValue()));
        }
        if (!(claims.get("status_list") instanceof Map<?, ?> statusList)
                || !(statusList.get("bits") instanceof Number bits)
                || !(statusList.get("lst") instanceof String lst)) {
            throw new VerificationFailure("status_list_invalid", "status_list must contain bits and lst");
        }
        byte[] compressed;
        try {
            Decoder decoder = java.util.Base64.getUrlDecoder();
            compressed = decoder.decode(lst);
        } catch (IllegalArgumentException e) {
            throw new VerificationFailure("status_list_invalid", "lst is not base64url", e);
        }
        if (bits.doubleValue() != Math.rint(bits.doubleValue()) || !inRange(bits.doubleValue(), 8)) {
            throw new VerificationFailure("status_list_invalid", "bits must be an integer");
        }
        return new Verified(StatusList.decode(bits.intValue(), compressed, maxListBytes), cacheUntil);
    }

    private static boolean inRange(double value, double max) {
        return Double.isFinite(value) && value >= 0 && value <= max;
    }

    private static Instant min(Instant a, Instant b) {
        return a.isBefore(b) ? a : b;
    }
}
