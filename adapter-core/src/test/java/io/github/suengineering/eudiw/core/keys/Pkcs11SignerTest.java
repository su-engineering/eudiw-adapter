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
package io.github.suengineering.eudiw.core.keys;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import io.github.suengineering.eudiw.core.dcql.DcqlQuery;
import io.github.suengineering.eudiw.core.jose.AlgorithmPolicy;
import io.github.suengineering.eudiw.core.jose.JwsSignatureVerifier;
import io.github.suengineering.eudiw.core.oid4vp.AuthorizationRequests;
import io.github.suengineering.eudiw.core.oid4vp.VerifierIdentity;
import io.github.suengineering.eudiw.core.x509.TestPki;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Signs request objects with a non-extractable key inside SoftHSM through the JDK PKCS#11 provider. Runs where a
 * SoftHSM library is installed; CI installs it and sets {@code eudiw.require-pkcs11} so the test cannot skip there.
 */
class Pkcs11SignerTest {

    private static final List<Path> LIBRARIES = List.of(
            Path.of("/usr/lib/softhsm/libsofthsm2.so"),
            Path.of("/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"),
            Path.of("/opt/homebrew/lib/softhsm/libsofthsm2.so"),
            Path.of("/usr/local/lib/softhsm/libsofthsm2.so"));
    private static final char[] PIN = "1234".toCharArray();
    private static final String LABEL = "rp-request-signing";

    private static Path library;
    private static TestPki.Issued rpRoot;
    private static X509Certificate rpCertificate;

    @BeforeAll
    static void createToken() throws Exception {
        library = LIBRARIES.stream().filter(Files::isRegularFile).findFirst().orElse(null);
        if (library == null) {
            if (Boolean.getBoolean("eudiw.require-pkcs11")) {
                throw new IllegalStateException("SoftHSM is required but not installed");
            }
            assumeTrue(false, "SoftHSM not installed");
        }
        String conf = System.getenv("SOFTHSM2_CONF");
        assumeTrue(conf != null, "SOFTHSM2_CONF not set");
        Path tokens = Path.of(conf).getParent().resolve("tokens");
        if (Files.exists(tokens)) {
            deleteRecursively(tokens);
        }
        Files.createDirectories(tokens);
        Files.writeString(Path.of(conf), "directories.tokendir = " + tokens + "\nobjectstore.backend = file\n");
        Process init = new ProcessBuilder(
                        "softhsm2-util",
                        "--init-token",
                        "--free",
                        "--label",
                        "eudiw-test",
                        "--pin",
                        "1234",
                        "--so-pin",
                        "5678")
                .redirectErrorStream(true)
                .start();
        String output = new String(init.getInputStream().readAllBytes());
        assertThat(init.waitFor()).as(output).isZero();

        // Generate the key inside the token, then store its certificate under the same label.
        Provider provider = Pkcs11Keys.provider(library, 0);
        KeyStore store = KeyStore.getInstance("PKCS11", provider);
        store.load(null, PIN);
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", provider);
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair pair = generator.generateKeyPair();
        Instant now = Instant.now();
        rpRoot = TestPki.rootCa("CN=RP Root", now.minus(Duration.ofDays(1)), now.plus(Duration.ofDays(30)));
        rpCertificate = new JcaX509CertificateConverter()
                .getCertificate(new JcaX509v3CertificateBuilder(
                                rpRoot.certificate(),
                                BigInteger.valueOf(now.toEpochMilli()),
                                Date.from(now.minus(Duration.ofDays(1))),
                                Date.from(now.plus(Duration.ofDays(30))),
                                new X500Name("CN=Verifier in HSM"),
                                pair.getPublic())
                        .addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
                        .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature))
                        .build(new JcaContentSignerBuilder("SHA256withECDSA")
                                .build(rpRoot.keyPair().getPrivate())));
        store.setKeyEntry(LABEL, pair.getPrivate(), null, new Certificate[] {rpCertificate});
    }

    @Test
    void signsARequestObjectThatVerifiesWithTheCertificate() throws Exception {
        Pkcs11Keys.Loaded loaded = Pkcs11Keys.load(library, 0, LABEL, PIN);
        assertThat(loaded.key().getEncoded())
                .as("the key must stay in the token")
                .isNull();

        VerifierIdentity identity =
                new VerifierIdentity(loaded.key(), List.of(rpCertificate), Optional.of(loaded.provider()));
        DcqlQuery query = DcqlQuery.parse(Map.of(
                "credentials",
                List.of(Map.of(
                        "id",
                        "age",
                        "format",
                        "dc+sd-jwt",
                        "meta",
                        Map.of("vct_values", List.of("https://vct.example")),
                        "claims",
                        List.of(Map.of("path", List.of("age_over_18")))))));
        String request = AuthorizationRequests.signRequestObject(
                identity,
                new AuthorizationRequests.Parameters(
                        URI.create("https://adapter.example/oid4vp/responses"),
                        "nonce-1",
                        "state-1",
                        query,
                        AuthorizationRequests.newResponseEncryptionKey(),
                        null,
                        Duration.ofMinutes(5)),
                Instant.now());

        JWSObject jws = JWSObject.parse(request);
        assertThat(jws.getSignature().decode()).as("JOSE R || S, not DER").hasSize(64);
        JwsSignatureVerifier.verify(
                jws,
                new ECKey.Builder(Curve.P_256, (ECPublicKey) rpCertificate.getPublicKey()).build(),
                AlgorithmPolicy.ES256_ONLY);
    }

    @Test
    void aKeyThatDoesNotMatchTheCertificateIsRefused() {
        Pkcs11Keys.Loaded loaded = Pkcs11Keys.load(library, 0, LABEL, PIN);
        TestPki.Issued other = TestPki.endEntity(
                "CN=Other",
                rpRoot,
                Instant.now().minus(Duration.ofDays(1)),
                Instant.now().plus(Duration.ofDays(1)),
                KeyUsage.digitalSignature,
                List.of());
        assertThatThrownBy(() -> new VerifierIdentity(
                        loaded.key(), List.of(other.certificate()), Optional.of(loaded.provider())))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("does not match");
    }

    @Test
    void aMissingLabelIsReported() {
        assertThatThrownBy(() -> Pkcs11Keys.load(library, 0, "no-such-key", PIN))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("no private key");
    }

    private static void deleteRecursively(Path path) throws IOException {
        if (Files.isDirectory(path)) {
            try (var files = Files.list(path)) {
                for (Path p : files.toList()) {
                    deleteRecursively(p);
                }
            }
        }
        Files.delete(path);
    }
}
