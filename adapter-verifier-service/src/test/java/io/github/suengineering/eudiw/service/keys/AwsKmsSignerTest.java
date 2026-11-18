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
package io.github.suengineering.eudiw.service.keys;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import io.github.suengineering.eudiw.core.keys.Es256JwsSigner;
import io.github.suengineering.eudiw.core.oid4vp.VerifierIdentity;
import io.github.suengineering.eudiw.core.x509.TestPki;
import io.github.suengineering.eudiw.kms.aws.AwsKmsSigner;
import java.math.BigInteger;
import java.net.URI;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.KeySpec;
import software.amazon.awssdk.services.kms.model.KeyUsageType;

/**
 * The request-signing key in AWS KMS, against local-kms, an open-source KMS emulator (not AWS itself). The key is
 * created in the emulator, its public key is certified by a test CA, and the adapter only ever asks KMS to sign.
 */
class AwsKmsSignerTest {

    // local-kms 3.x (nsmithuk/local-kms), built 2026-02-28
    static final String KMS_IMAGE =
            "nsmithuk/local-kms:latest@sha256:e070866476b20973a9e23a9b636204b7a222e4169a6e03198d27b80d47ed28e3";
    static final StaticCredentialsProvider CREDENTIALS =
            StaticCredentialsProvider.create(AwsBasicCredentials.create("test-access-key", "test-secret-key"));

    static GenericContainer<?> kms;
    static URI endpoint;
    static KmsClient admin;
    static TestPki.Issued root;

    @BeforeAll
    static void startKms() {
        kms = new GenericContainer<>(KMS_IMAGE).withExposedPorts(8080).waitingFor(Wait.forListeningPort());
        kms.start();
        endpoint = URI.create("http://" + kms.getHost() + ":" + kms.getMappedPort(8080));
        admin = KmsClient.builder()
                .endpointOverride(endpoint)
                .region(Region.EU_WEST_1)
                .credentialsProvider(CREDENTIALS)
                .httpClientBuilder(software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient.builder())
                .build();
        Instant now = Instant.now();
        root = TestPki.rootCa("CN=RP Root", now.minus(Duration.ofDays(1)), now.plus(Duration.ofDays(30)));
    }

    @AfterAll
    static void stopKms() {
        if (admin != null) {
            admin.close();
        }
        if (kms != null) {
            kms.stop();
        }
    }

    @Test
    void signsRequestObjectsOfAnySizeWithAKeyThatNeverLeavesKms() throws Exception {
        String keyId = createKey(KeySpec.ECC_NIST_P256);
        java.security.cert.X509Certificate leaf = certify(publicKey(keyId));
        VerifierIdentity identity = new VerifierIdentity(signer(keyId), List.of(leaf));

        // Larger than the 4096 bytes KMS accepts as a raw message: the digest is what is sent.
        JWSObject jws = new JWSObject(
                new JWSHeader(JWSAlgorithm.ES256), new Payload("{\"padding\":\"" + "x".repeat(6000) + "\"}"));
        jws.sign(new Es256JwsSigner(identity.signer()));

        assertThat(JWSObject.parse(jws.serialize()).verify(new ECDSAVerifier((ECPublicKey) leaf.getPublicKey())))
                .isTrue();
    }

    @Test
    void signsThroughAnAlias() throws Exception {
        String keyId = createKey(KeySpec.ECC_NIST_P256);
        admin.createAlias(r -> r.aliasName("alias/eudiw-rp").targetKeyId(keyId));

        VerifierIdentity identity = new VerifierIdentity(signer("alias/eudiw-rp"), List.of(certify(publicKey(keyId))));

        assertThat(identity.signer().signEs256(new byte[] {1})).hasSize(64);
    }

    @Test
    void refusesAKeyThatDoesNotMatchTheCertificateAtStartup() throws Exception {
        String keyId = createKey(KeySpec.ECC_NIST_P256);
        java.security.cert.X509Certificate other = certify(TestPki.ecKeyPair().getPublic());

        assertThatThrownBy(() -> new VerifierIdentity(signer(keyId), List.of(other)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("does not match the end-entity certificate");
    }

    @Test
    void namesTheProblemWithAnUnknownOrWrongKey() throws Exception {
        assertThatThrownBy(() -> signer("alias/does-not-exist").signEs256(new byte[] {2}))
                .isInstanceOf(JOSEException.class)
                .hasMessageContaining("AWS KMS refused to sign")
                .hasMessageContaining("NotFoundException");

        String rsa = createKey(KeySpec.RSA_2048);
        assertThatThrownBy(() -> signer(rsa).signEs256(new byte[] {3}))
                .isInstanceOf(JOSEException.class)
                .hasMessageContaining("AWS KMS");
    }

    @Test
    void anUnreachableKmsIsAnErrorWithoutCredentials() {
        AwsKmsSigner signer = new AwsKmsSigner(
                new AwsKmsSigner.Settings(
                        "alias/eudiw-rp", Optional.of("eu-west-1"), Optional.of(URI.create("http://127.0.0.1:1"))),
                CREDENTIALS);

        assertThatThrownBy(() -> signer.signEs256(new byte[] {4}))
                .isInstanceOf(JOSEException.class)
                .hasMessageContaining("cannot be reached")
                .hasMessageNotContaining("test-secret-key");
    }

    private static AwsKmsSigner signer(String keyId) {
        return new AwsKmsSigner(
                new AwsKmsSigner.Settings(keyId, Optional.of("eu-west-1"), Optional.of(endpoint)), CREDENTIALS);
    }

    private static String createKey(KeySpec spec) {
        return admin.createKey(r -> r.keySpec(spec).keyUsage(KeyUsageType.SIGN_VERIFY))
                .keyMetadata()
                .keyId();
    }

    private static PublicKey publicKey(String keyId) throws Exception {
        byte[] spki = admin.getPublicKey(r -> r.keyId(keyId)).publicKey().asByteArray();
        return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(spki));
    }

    private static java.security.cert.X509Certificate certify(PublicKey key) throws Exception {
        Instant now = Instant.now();
        return new JcaX509CertificateConverter()
                .getCertificate(new JcaX509v3CertificateBuilder(
                                root.certificate(),
                                BigInteger.valueOf(System.nanoTime()),
                                Date.from(now.minus(Duration.ofDays(1))),
                                Date.from(now.plus(Duration.ofDays(30))),
                                new X500Name("CN=Verifier in KMS"),
                                key)
                        .addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
                        .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature))
                        .build(new JcaContentSignerBuilder("SHA256withECDSA")
                                .build(root.keyPair().getPrivate())));
    }
}
