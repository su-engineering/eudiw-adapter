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

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64;
import io.github.suengineering.eudiw.core.VerificationFailure;
import io.github.suengineering.eudiw.core.x509.CertificateChainValidator;
import io.github.suengineering.eudiw.core.x509.CertificateKeys;
import io.github.suengineering.eudiw.core.x509.CertificateNames;
import io.github.suengineering.eudiw.core.x509.TrustStore;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Supplier;

/**
 * The X.509 Issuer Signature Mechanism (SD-JWT VC section 3.5, HAIP 1.0 section 6.1.1): the issuer key is the
 * end-entity certificate in the {@code x5c} header, whose chain must validate to a configured trust anchor.
 *
 * <p>When the credential carries an {@code iss} claim, it must be bound to the certificate (a SAN URI equal to
 * it, or a SAN dNSName equal to its host), so that a certificate trusted for one issuer cannot sign credentials
 * claiming another (SD-JWT VC section 10.2). Without {@code iss}, the issuer is the certificate subject.
 */
public final class X5cIssuerKeyResolver implements IssuerKeyResolver {

    private final Supplier<TrustStore> trustStore;
    private final Clock clock;

    /**
     * @param trustAnchors current trust anchors, consulted on every call so updates apply
     * @param clock time source
     */
    public X5cIssuerKeyResolver(Supplier<Set<TrustAnchor>> trustAnchors, Clock clock) {
        Objects.requireNonNull(trustAnchors, "trustAnchors");
        this.trustStore = () -> TrustStore.ofAnchors(trustAnchors.get());
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    private X5cIssuerKeyResolver(Clock clock, Supplier<TrustStore> trustStore) {
        this.trustStore = Objects.requireNonNull(trustStore, "trustStore");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * @param trustStore current trusted certificates and their sources, consulted on every call so trusted list
     *     updates apply
     * @param clock time source
     */
    public static X5cIssuerKeyResolver withTrustStore(Supplier<TrustStore> trustStore, Clock clock) {
        return new X5cIssuerKeyResolver(clock, trustStore);
    }

    @Override
    public ResolvedIssuerKey resolve(JWSHeader header, Map<String, Object> unverifiedPayload) {
        List<Base64> x5c = header.getX509CertChain();
        if (x5c == null || x5c.isEmpty()) {
            throw new VerificationFailure("issuer_untrusted", "credential has no x5c header");
        }
        List<X509Certificate> chain =
                CertificateChainValidator.parse(x5c.stream().map(Base64::decode).toList());
        TrustStore store = trustStore.get();
        CertificateChainValidator.ValidatedPath path =
                CertificateChainValidator.validatePath(chain, store.anchors(), clock.instant());
        X509Certificate leaf = path.leaf();

        Object iss = unverifiedPayload.get("iss");
        String issuer;
        if (iss == null) {
            issuer = leaf.getSubjectX500Principal().getName();
        } else if (iss instanceof String s && CertificateNames.bindsIssuer(leaf, s)) {
            issuer = s;
        } else {
            throw new VerificationFailure("issuer_untrusted", "iss is not bound to the signing certificate");
        }
        return new ResolvedIssuerKey(CertificateKeys.publicJwk(leaf), issuer, chain, store.sourcesOf(path.anchor()));
    }
}
