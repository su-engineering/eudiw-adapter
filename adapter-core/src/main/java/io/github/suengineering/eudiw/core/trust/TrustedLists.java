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
 * tampered list fails closed. A national list reached through a list of trusted lists (LOTL) is trusted only while
 * a current LOTL still points to it and still publishes the certificate that signed it. A list whose sequence
 * number is lower than the highest one accepted is refused, which stops an attacker from replaying an older, still
 * unexpired list; a {@link SequenceStore} can keep that across restarts.
 *
 * <p>{@link #issuance()} and {@link #status()} read only lists that are current at the clock's time, together with
 * a fixed base store (for example configured anchor certificates). Each trusted certificate carries the identifiers
 * of the list that listed it and, for lists reached through a LOTL, that LOTL's identifier too, which is what DCQL
 * {@code etsi_tl} values name.
 */
public final class TrustedLists {

    /** Outcome of loading one list. */
    public record LoadResult(String location, boolean ok, String code) {}

    /** Remembers the highest accepted sequence number per list identifier. */
    public interface SequenceStore {
        /** The highest sequence number accepted for the list, or -1 when none was. */
        long highest(String identifier);

        void record(String identifier, long sequenceNumber);

        /**
         * Records the sequence number unless a higher one is already recorded, as one atomic step. A store shared
         * by several nodes should override this; the default is atomic only within one process.
         *
         * @return whether the number was recorded
         */
        default boolean advance(String identifier, long sequenceNumber) {
            synchronized (this) {
                if (sequenceNumber < highest(identifier)) {
                    return false;
                }
                record(identifier, sequenceNumber);
                return true;
            }
        }

        static SequenceStore inMemory() {
            Map<String, Long> map = new ConcurrentHashMap<>();
            return new SequenceStore() {
                @Override
                public long highest(String identifier) {
                    return map.getOrDefault(identifier, -1L);
                }

                @Override
                public void record(String identifier, long sequenceNumber) {
                    map.merge(identifier, sequenceNumber, Math::max);
                }
            };
        }
    }

    /** A verified list, the source that configured it, its identifiers and, for a pointed-to list, its LOTL. */
    private record Loaded(TrustedList list, TrustedListSource source, Set<String> sourceIds, String parent) {}

    private record Snapshot(long generation, Instant validUntil, TrustStore store) {}

    private final List<TrustedListSource> sources;
    private final HttpFetcher fetcher;
    private final Clock clock;
    private final TrustStore base;
    private final SequenceStore sequences;
    private final Map<String, Loaded> loaded = new ConcurrentHashMap<>();
    private volatile long generation;
    private volatile Snapshot issuanceSnapshot;
    private volatile Snapshot statusSnapshot;

    public TrustedLists(List<TrustedListSource> sources, HttpFetcher fetcher, Clock clock) {
        this(sources, fetcher, clock, TrustStore.empty(), SequenceStore.inMemory());
    }

    /**
     * @param base certificates trusted regardless of lists, merged into {@link #issuance()} and {@link #status()}
     * @param sequences where the highest accepted sequence numbers are kept
     */
    public TrustedLists(
            List<TrustedListSource> sources,
            HttpFetcher fetcher,
            Clock clock,
            TrustStore base,
            SequenceStore sequences) {
        this.sources = List.copyOf(sources);
        this.fetcher = Objects.requireNonNull(fetcher, "fetcher");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.base = Objects.requireNonNull(base, "base");
        this.sequences = Objects.requireNonNull(sequences, "sequences");
    }

    public boolean isEmpty() {
        return sources.isEmpty();
    }

    /** Fetches and verifies every list now. Never throws because of a list; the result reports each one. */
    public synchronized List<LoadResult> refresh() {
        List<LoadResult> results = new ArrayList<>();
        for (TrustedListSource source : sources) {
            String id = source.identifier();
            TrustedList list;
            try {
                list = load(source.location(), source.format(), source.signers());
                accept(id, new Loaded(list, source, Set.of(id), null));
                results.add(new LoadResult(id, true, "ok"));
            } catch (RuntimeException e) {
                list = null;
                results.add(new LoadResult(id, false, code(e)));
            }
            if (list == null) {
                Loaded previous = loaded.get(id);
                if (previous != null && previous.list().isCurrentAt(clock.instant())) {
                    list = previous.list();
                }
            }
            if (source.followPointers()) {
                if (list != null) {
                    results.addAll(followPointers(source, list));
                }
                evictUnpointed(id, list == null ? List.of() : list.pointers());
            }
        }
        return results;
    }

    private List<LoadResult> followPointers(TrustedListSource source, TrustedList listOfLists) {
        List<LoadResult> results = new ArrayList<>();
        String lotlId = source.identifier();
        for (TrustedList.Pointer pointer : followable(source, listOfLists)) {
            try {
                URI location = URI.create(pointer.location());
                if (!"https".equalsIgnoreCase(location.getScheme()) && !"http".equalsIgnoreCase(location.getScheme())) {
                    throw new VerificationFailure(ListRules.INVALID, "pointer is not an HTTP URL");
                }
                TrustedList list = load(location, TrustedList.Format.TSL_XML, pointer.signerCertificates());
                accept(pointer.location(), new Loaded(list, source, Set.of(pointer.location(), lotlId), lotlId));
                results.add(new LoadResult(pointer.location(), true, "ok"));
            } catch (RuntimeException e) {
                results.add(new LoadResult(pointer.location(), false, code(e)));
            }
        }
        return results;
    }

    private static List<TrustedList.Pointer> followable(TrustedListSource source, TrustedList listOfLists) {
        List<TrustedList.Pointer> result = new ArrayList<>();
        for (TrustedList.Pointer pointer : listOfLists.pointers()) {
            if (pointer.location().equals(source.identifier())
                    || pointer.location().equals(source.location().toString())
                    || TrustedList.TSL_TYPE_EU_LOTL.equals(pointer.type().orElse(""))
                    || !TrustedList.MIME_TSL_XML.equals(pointer.mimeType().orElse(""))) {
                continue;
            }
            if (!source.territories().isEmpty()
                    && !source.territories().contains(pointer.territory().orElse(""))) {
                continue;
            }
            result.add(pointer);
        }
        return result;
    }

    /**
     * Drops lists reached through this LOTL that it no longer points to, or whose signing certificate it no
     * longer publishes. With no current LOTL, drops them all.
     */
    private void evictUnpointed(String lotlId, List<TrustedList.Pointer> pointers) {
        boolean removed = loaded.entrySet().removeIf(entry -> {
            Loaded child = entry.getValue();
            if (!lotlId.equals(child.parent())) {
                return false;
            }
            for (TrustedList.Pointer pointer : pointers) {
                if (pointer.location().equals(entry.getKey())
                        && pointer.signerCertificates().contains(child.list().signer())) {
                    return false;
                }
            }
            return true;
        });
        if (removed) {
            generation++;
        }
    }

    private static String code(RuntimeException e) {
        return e instanceof VerificationFailure f ? f.code() : ListRules.INVALID;
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
        long sequence = candidate.list().sequenceNumber();
        Loaded previous = loaded.get(key);
        if ((previous != null && sequence < previous.list().sequenceNumber()) || !sequences.advance(key, sequence)) {
            throw new VerificationFailure("trusted_list_rollback", "trusted list sequence number went backwards");
        }
        loaded.put(key, candidate);
        generation++;
    }

    /** Certificates that may anchor credential issuers: the base store and lists current now. */
    public TrustStore issuance() {
        return store(false);
    }

    /** Certificates that may anchor status list tokens: the base store, issuance services and status services. */
    public TrustStore status() {
        return store(true);
    }

    /** Whether at least one configured list currently contributes, or no list is configured. */
    public boolean hasCurrentList() {
        if (sources.isEmpty()) {
            return true;
        }
        Instant now = clock.instant();
        return loaded.values().stream().anyMatch(l -> l.list().isCurrentAt(now));
    }

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
        Map<X509Certificate, Set<String>> names = new LinkedHashMap<>();
        for (X509Certificate certificate : base.certificates()) {
            trusted.computeIfAbsent(certificate, c -> new LinkedHashSet<>()).addAll(base.sourcesOf(certificate));
        }
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
                    names.computeIfAbsent(certificate, c -> new LinkedHashSet<>())
                            .add(service.entityName());
                }
            }
        }
        return TrustStore.ofSources(trusted, names);
    }
}
