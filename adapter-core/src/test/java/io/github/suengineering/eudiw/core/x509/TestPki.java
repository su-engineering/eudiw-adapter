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

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/** Synthetic certificate authorities and end-entity certificates for tests. */
public final class TestPki {

    private static final AtomicLong SERIAL = new AtomicLong(1000);

    public record Issued(X509Certificate certificate, KeyPair keyPair) {}

    private TestPki() {}

    public static KeyPair ecKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static Issued rootCa(String name, Instant notBefore, Instant notAfter) {
        KeyPair keys = ecKeyPair();
        X509Certificate cert = build(
                name,
                name,
                keys.getPublic(),
                keys.getPrivate(),
                null,
                notBefore,
                notAfter,
                true,
                KeyUsage.keyCertSign | KeyUsage.cRLSign,
                List.of());
        return new Issued(cert, keys);
    }

    public static Issued intermediateCa(String name, Issued parent, Instant notBefore, Instant notAfter) {
        KeyPair keys = ecKeyPair();
        X509Certificate cert = build(
                name,
                parent.certificate().getSubjectX500Principal().getName(),
                keys.getPublic(),
                parent.keyPair().getPrivate(),
                parent.certificate(),
                notBefore,
                notAfter,
                true,
                KeyUsage.keyCertSign | KeyUsage.cRLSign,
                List.of());
        return new Issued(cert, keys);
    }

    /**
     * @param sans subject alternative names as {@link GeneralName}s
     */
    public static Issued endEntity(
            String name, Issued parent, Instant notBefore, Instant notAfter, int keyUsage, List<GeneralName> sans) {
        KeyPair keys = ecKeyPair();
        X509Certificate cert = build(
                name,
                parent.certificate().getSubjectX500Principal().getName(),
                keys.getPublic(),
                parent.keyPair().getPrivate(),
                parent.certificate(),
                notBefore,
                notAfter,
                false,
                keyUsage,
                sans);
        return new Issued(cert, keys);
    }

    /** A self-signed end-entity certificate (not a CA). */
    public static Issued selfSignedEndEntity(String name, Instant notBefore, Instant notAfter) {
        KeyPair keys = ecKeyPair();
        X509Certificate cert = build(
                name,
                name,
                keys.getPublic(),
                keys.getPrivate(),
                null,
                notBefore,
                notAfter,
                false,
                KeyUsage.digitalSignature,
                List.of());
        return new Issued(cert, keys);
    }

    public static GeneralName dns(String name) {
        return new GeneralName(GeneralName.dNSName, name);
    }

    public static GeneralName uri(String uri) {
        return new GeneralName(GeneralName.uniformResourceIdentifier, uri);
    }

    private static X509Certificate build(
            String subject,
            String issuer,
            PublicKey publicKey,
            PrivateKey signingKey,
            X509Certificate issuerCert,
            Instant notBefore,
            Instant notAfter,
            boolean ca,
            int keyUsage,
            List<GeneralName> sans) {
        try {
            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    new X500Name(issuer),
                    BigInteger.valueOf(SERIAL.incrementAndGet()),
                    Date.from(notBefore),
                    Date.from(notAfter),
                    new X500Name(subject),
                    publicKey);
            JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsage));
            builder.addExtension(Extension.subjectKeyIdentifier, false, utils.createSubjectKeyIdentifier(publicKey));
            if (issuerCert != null) {
                builder.addExtension(
                        Extension.authorityKeyIdentifier, false, utils.createAuthorityKeyIdentifier(issuerCert));
            }
            if (!sans.isEmpty()) {
                builder.addExtension(
                        Extension.subjectAlternativeName, false, new GeneralNames(sans.toArray(new GeneralName[0])));
            }
            return new JcaX509CertificateConverter()
                    .getCertificate(builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(signingKey)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static List<X509Certificate> chain(Issued... certificates) {
        List<X509Certificate> out = new ArrayList<>();
        for (Issued issued : certificates) {
            out.add(issued.certificate());
        }
        return out;
    }
}
