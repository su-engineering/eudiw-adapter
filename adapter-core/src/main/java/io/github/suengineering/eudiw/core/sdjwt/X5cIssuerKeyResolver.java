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

    private final Supplier<Set<TrustAnchor>> trustAnchors;
    private final Clock clock;

    /**
     * @param trustAnchors current trust anchors, consulted on every call so trust list updates apply
     */
    public X5cIssuerKeyResolver(Supplier<Set<TrustAnchor>> trustAnchors, Clock clock) {
        this.trustAnchors = Objects.requireNonNull(trustAnchors, "trustAnchors");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public ResolvedIssuerKey resolve(JWSHeader header, Map<String, Object> unverifiedPayload) {
        List<Base64> x5c = header.getX509CertChain();
        if (x5c == null || x5c.isEmpty()) {
            throw new VerificationFailure("issuer_untrusted", "credential has no x5c header");
        }
        List<X509Certificate> chain =
                CertificateChainValidator.parse(x5c.stream().map(Base64::decode).toList());
        X509Certificate leaf = CertificateChainValidator.validate(chain, trustAnchors.get(), clock.instant());

        Object iss = unverifiedPayload.get("iss");
        String issuer;
        if (iss == null) {
            issuer = leaf.getSubjectX500Principal().getName();
        } else if (iss instanceof String s && CertificateNames.bindsIssuer(leaf, s)) {
            issuer = s;
        } else {
            throw new VerificationFailure("issuer_untrusted", "iss is not bound to the signing certificate");
        }
        return new ResolvedIssuerKey(CertificateKeys.publicJwk(leaf), issuer, chain);
    }
}
