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
package io.github.suengineering.eudiw.core.trust;

import io.github.suengineering.eudiw.core.VerificationFailure;
import io.github.suengineering.eudiw.core.net.HttpFetcher;
import io.github.suengineering.eudiw.core.x509.TrustStore;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Loads configured trusted lists and turns the services they approve into trusted certificates.
 *
 * <p>{@link #refresh()} fetches and verifies every list. A list that fails keeps its last verified version, but
 * only until that version's next update: after that its certificates stop being trusted, so an unreachable or
 * tampered list fails closed. A list whose sequence number is lower than the last accepted one is refused, which
 * stops an attacker from replaying an older, still unexpired list.
 *
 * <p>{@link #issuance()} and {@link #status()} read only lists that are current at the clock's time. Each trusted
 * certificate carries the locations of the list that listed it and, for lists reached through a list of trusted
 * lists, that list's location too, which is what DCQL {@code etsi_tl} values name.
 */
public final class TrustedLists {

    /** Outcome of loading one list. */
    public record LoadResult(String location, boolean ok, String code) {}

    private record Loaded(TrustedList list, TrustedListSource source, Set<String> sourceIds) {}

    private final List<TrustedListSource> sources;
    private final HttpFetcher fetcher;
    private final Clock clock;
    private final Map<String, Loaded> loaded = new ConcurrentHashMap<>();

    public TrustedLists(List<TrustedListSource> sources, HttpFetcher fetcher, Clock clock) {
        this.sources = List.copyOf(sources);
        this.fetcher = Objects.requireNonNull(fetcher, "fetcher");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public boolean isEmpty() {
        return sources.isEmpty();
    }

    /** Fetches and verifies every list now. Never throws for a list that fails; the result reports it. */
    public synchronized List<LoadResult> refresh() {
        List<LoadResult> results = new ArrayList<>();
        for (TrustedListSource source : sources) {
            String id = source.identifier();
            TrustedList list;
            try {
                list = load(source.location(), source.format(), source.signers());
                accept(id, new Loaded(list, source, Set.of(id)));
                results.add(new LoadResult(id, true, "ok"));
            } catch (VerificationFailure e) {
                results.add(new LoadResult(id, false, e.code()));
                Loaded previous = loaded.get(id);
                if (previous == null) {
                    continue;
                }
                list = previous.list();
            }
            if (source.followPointers()) {
                results.addAll(followPointers(source, list));
            }
        }
        return results;
    }

    private List<LoadResult> followPointers(TrustedListSource source, TrustedList listOfLists) {
        List<LoadResult> results = new ArrayList<>();
        String lotlId = source.identifier();
        for (TrustedList.Pointer pointer : listOfLists.pointers()) {
            if (pointer.location().equals(lotlId)
                    || pointer.location().equals(source.location().toString())
                    || TrustedList.TSL_TYPE_EU_LOTL.equals(pointer.type().orElse(""))
                    || !TrustedList.MIME_TSL_XML.equals(pointer.mimeType().orElse(""))) {
                continue;
            }
            if (!source.territories().isEmpty()
                    && !source.territories().contains(pointer.territory().orElse(""))) {
                continue;
            }
            try {
                URI location = URI.create(pointer.location());
                if (!"https".equalsIgnoreCase(location.getScheme()) && !"http".equalsIgnoreCase(location.getScheme())) {
                    throw new VerificationFailure(ListRules.INVALID, "pointer is not an HTTP URL");
                }
                TrustedList list = load(location, TrustedList.Format.TSL_XML, pointer.signerCertificates());
                accept(pointer.location(), new Loaded(list, source, Set.of(pointer.location(), lotlId)));
                results.add(new LoadResult(pointer.location(), true, "ok"));
            } catch (VerificationFailure | IllegalArgumentException e) {
                results.add(new LoadResult(
                        pointer.location(), false, e instanceof VerificationFailure f ? f.code() : ListRules.INVALID));
            }
        }
        return results;
    }

    private TrustedList load(URI location, TrustedList.Format format, Collection<X509Certificate> signers) {
        byte[] bytes = read(location, format);
        TrustedList list = format == TrustedList.Format.TSL_XML
                ? TslXmlParser.verify(bytes, location.toString(), signers)
                : LoteJsonParser.verify(bytes, location.toString(), signers);
        if (!list.isCurrentAt(clock.instant())) {
            throw new VerificationFailure("trusted_list_expired", "trusted list is closed, expired or not yet issued");
        }
        return list;
    }

    private byte[] read(URI location, TrustedList.Format format) {
        int max = format == TrustedList.Format.TSL_XML ? TslXmlParser.MAX_BYTES : LoteJsonParser.MAX_BYTES;
        if ("file".equalsIgnoreCase(location.getScheme())) {
            try {
                Path path = Path.of(location);
                if (Files.size(path) > max) {
                    throw new VerificationFailure(ListRules.INVALID, "trusted list too large");
                }
                return Files.readAllBytes(path);
            } catch (IOException | IllegalArgumentException e) {
                throw new VerificationFailure("trusted_list_unavailable", "trusted list file cannot be read", e);
            }
        }
        String accept = format == TrustedList.Format.TSL_XML
                ? TrustedList.MIME_TSL_XML + ", application/xml"
                : "application/jose, application/json";
        try {
            return fetcher.get(location, accept, max);
        } catch (HttpFetcher.FetchException e) {
            throw new VerificationFailure("trusted_list_unavailable", "trusted list cannot be fetched", e);
        }
    }

    private void accept(String key, Loaded candidate) {
        loaded.compute(key, (k, previous) -> {
            if (previous != null
                    && candidate.list().sequenceNumber() < previous.list().sequenceNumber()) {
                throw new VerificationFailure("trusted_list_rollback", "trusted list sequence number went backwards");
            }
            return candidate;
        });
        generation++;
    }

    /** Certificates that may anchor credential issuers, from lists current now. */
    public TrustStore issuance() {
        return store(false);
    }

    /** Certificates that may anchor status list tokens: issuance services plus status services. */
    public TrustStore status() {
        return store(true);
    }

    /** The earliest next update among the lists in use, or empty when none is loaded. */
    public java.util.Optional<Instant> earliestNextUpdate() {
        return loaded.values().stream()
                .map(l -> l.list().nextUpdate())
                .flatMap(java.util.Optional::stream)
                .min(Instant::compareTo);
    }

    private record Snapshot(long generation, Instant validUntil, TrustStore store) {}

    private volatile long generation;
    private volatile Snapshot issuanceSnapshot;
    private volatile Snapshot statusSnapshot;

    private TrustStore store(boolean forStatus) {
        Instant now = clock.instant();
        Snapshot cached = forStatus ? statusSnapshot : issuanceSnapshot;
        if (cached != null && cached.generation() == generation && now.isBefore(cached.validUntil())) {
            return cached.store();
        }
        long currentGeneration = generation;
        Instant validUntil = now.plusSeconds(300);
        for (Loaded entry : loaded.values()) {
            Instant next = entry.list().nextUpdate().orElse(validUntil);
            if (next.isAfter(now) && next.isBefore(validUntil)) {
                validUntil = next;
            }
        }
        Snapshot fresh = new Snapshot(currentGeneration, validUntil, build(forStatus, now));
        if (forStatus) {
            statusSnapshot = fresh;
        } else {
            issuanceSnapshot = fresh;
        }
        return fresh.store();
    }

    private TrustStore build(boolean forStatus, Instant now) {
        Map<X509Certificate, Set<String>> trusted = new LinkedHashMap<>();
        for (Loaded entry : loaded.values()) {
            if (!entry.list().isCurrentAt(now)) {
                continue;
            }
            TrustedListSource source = entry.source();
            for (TrustedList.Service service : entry.list().services()) {
                String type = service.type().orElse("");
                boolean wanted = source.issuanceServiceTypes().contains(type)
                        || (forStatus && source.statusServiceTypes().contains(type));
                boolean approved = service.status().isEmpty()
                        || source.acceptedStatuses().contains(service.status().get());
                if (!wanted || !approved) {
                    continue;
                }
                for (X509Certificate certificate : service.certificates()) {
                    trusted.computeIfAbsent(certificate, c -> new LinkedHashSet<>())
                            .addAll(entry.sourceIds());
                }
            }
        }
        return TrustStore.ofSources(trusted);
    }
}
