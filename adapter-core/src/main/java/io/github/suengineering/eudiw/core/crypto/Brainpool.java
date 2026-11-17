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
package io.github.suengineering.eudiw.core.crypto;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Opt-in support for the brainpool curves that ISO/IEC 18013-5 allows for mdoc signatures. The JDK knows their
 * parameters but cannot verify signatures on them, so they need a provider such as BouncyCastle, which the
 * {@code adapter-crypto-brainpool} module supplies. Until {@link #enable} is called, brainpool keys are refused.
 *
 * <p>The provider is added last, so it never replaces the JDK for anything the JDK can do. It is used explicitly, and
 * only, where a brainpool key is involved: COSE signatures, certificate path validation and CRL signatures.
 */
public final class Brainpool {

    /** Standard names of the brainpool curves of the COSE Elliptic Curves registry (values 256 to 259). */
    public static final List<String> CURVES =
            List.of("brainpoolP256r1", "brainpoolP320r1", "brainpoolP384r1", "brainpoolP512r1");

    private static volatile Provider provider;

    private Brainpool() {}

    /**
     * Turns brainpool support on for this JVM.
     *
     * @param brainpoolProvider a provider that verifies ECDSA on brainpool curves, such as BouncyCastle
     */
    public static synchronized void enable(Provider brainpoolProvider) {
        Objects.requireNonNull(brainpoolProvider, "brainpoolProvider");
        if (Security.getProvider(brainpoolProvider.getName()) == null) {
            Security.addProvider(brainpoolProvider);
        }
        provider = Security.getProvider(brainpoolProvider.getName());
    }

    /** Turns brainpool support off again; for tests. The provider stays registered but is no longer used. */
    public static synchronized void disable() {
        provider = null;
    }

    /** The provider to verify brainpool signatures with, when support is on. */
    public static Optional<Provider> provider() {
        return Optional.ofNullable(provider);
    }

    /**
     * Has path validation verify certificate and CRL signatures with the brainpool provider, when support is on and
     * a certificate of the path or a trust anchor has a brainpool key. Other paths keep the JDK's providers.
     */
    public static void applyTo(
            PKIXParameters parameters, Collection<X509Certificate> chain, Collection<X509Certificate> anchors) {
        Provider p = provider;
        if (p == null) {
            return;
        }
        boolean involved = chain.stream().anyMatch(c -> isBrainpool(c.getPublicKey()))
                || anchors.stream().anyMatch(c -> isBrainpool(c.getPublicKey()));
        if (involved) {
            parameters.setSigProvider(p.getName());
        }
    }

    /** Verifies a certificate's signature, with the brainpool provider when the key is a brainpool key. */
    public static void verify(X509Certificate certificate, PublicKey issuerKey) throws GeneralSecurityException {
        Provider p = provider;
        if (p != null && isBrainpool(issuerKey)) {
            certificate.verify(issuerKey, p);
        } else {
            certificate.verify(issuerKey);
        }
    }

    /** Whether the key is on one of the brainpool curves, whether or not support is on. */
    public static boolean isBrainpool(PublicKey key) {
        if (!(key instanceof ECPublicKey ec)) {
            return false;
        }
        for (String curve : CURVES) {
            if (sameCurve(parameters(curve), ec.getParams())) {
                return true;
            }
        }
        return false;
    }

    /** The JDK's parameters for a named curve. */
    public static ECParameterSpec parameters(String curve) {
        try {
            AlgorithmParameters p = AlgorithmParameters.getInstance("EC");
            p.init(new ECGenParameterSpec(curve));
            return p.getParameterSpec(ECParameterSpec.class);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("curve unavailable: " + curve, e);
        }
    }

    /** Equal domain parameters: field, coefficients, generator, order and cofactor. */
    public static boolean sameCurve(ECParameterSpec a, ECParameterSpec b) {
        return a.getCurve().equals(b.getCurve())
                && a.getGenerator().equals(b.getGenerator())
                && a.getOrder().equals(b.getOrder())
                && BigInteger.valueOf(a.getCofactor()).equals(BigInteger.valueOf(b.getCofactor()));
    }
}
