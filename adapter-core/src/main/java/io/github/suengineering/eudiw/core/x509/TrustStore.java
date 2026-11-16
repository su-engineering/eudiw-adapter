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

import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * An immutable set of trusted certificates, each remembering where it came from: a configured file, or the
 * location of the trusted list that listed it. The sources let DCQL {@code trusted_authorities} of type {@code
 * etsi_tl} match a credential to the list that anchored its issuer.
 */
public final class TrustStore {

    private static final TrustStore EMPTY = new TrustStore(Map.of());

    private final Map<X509Certificate, Set<String>> sources;
    private final Set<TrustAnchor> anchors;

    private TrustStore(Map<X509Certificate, Set<String>> sources) {
        Map<X509Certificate, Set<String>> copy = new LinkedHashMap<>();
        sources.forEach((certificate, from) -> copy.put(certificate, Set.copyOf(from)));
        this.sources = Map.copyOf(copy);
        Set<TrustAnchor> trustAnchors = new LinkedHashSet<>();
        for (X509Certificate certificate : copy.keySet()) {
            trustAnchors.add(new TrustAnchor(certificate, null));
        }
        this.anchors = Set.copyOf(trustAnchors);
    }

    public static TrustStore empty() {
        return EMPTY;
    }

    /** Certificates that all come from one source, for example a configured anchors file. */
    public static TrustStore of(Collection<X509Certificate> certificates, String source) {
        Objects.requireNonNull(source, "source");
        Map<X509Certificate, Set<String>> map = new LinkedHashMap<>();
        for (X509Certificate certificate : certificates) {
            map.put(Objects.requireNonNull(certificate, "certificate"), Set.of(source));
        }
        return new TrustStore(map);
    }

    /** Certificates with their sources. */
    public static TrustStore ofSources(Map<X509Certificate, ? extends Set<String>> sources) {
        return new TrustStore(Map.copyOf(sources));
    }

    /** Wraps plain trust anchors; their source is {@code "configured"}. */
    public static TrustStore ofAnchors(Set<TrustAnchor> trustAnchors) {
        return of(trustAnchors.stream().map(TrustAnchor::getTrustedCert).toList(), "configured");
    }

    /** The union of both stores; a certificate present in both keeps the sources of both. */
    public TrustStore merge(TrustStore other) {
        Map<X509Certificate, Set<String>> map = new LinkedHashMap<>();
        for (TrustStore store : new TrustStore[] {this, other}) {
            store.sources.forEach((certificate, from) ->
                    map.computeIfAbsent(certificate, c -> new LinkedHashSet<>()).addAll(from));
        }
        return new TrustStore(map);
    }

    public Set<TrustAnchor> anchors() {
        return anchors;
    }

    public boolean isEmpty() {
        return sources.isEmpty();
    }

    /** Where a trusted certificate came from; empty when it is not in this store. */
    public Set<String> sourcesOf(X509Certificate certificate) {
        return sources.getOrDefault(certificate, Set.of());
    }

    public Set<X509Certificate> certificates() {
        return sources.keySet();
    }
}
