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
import io.github.suengineering.eudiw.core.json.Json;
import io.github.suengineering.eudiw.core.keys.Es256JwsSigner;
import io.github.suengineering.eudiw.core.keys.VaultTransitSigner;
import io.github.suengineering.eudiw.core.oid4vp.VerifierIdentity;
import io.github.suengineering.eudiw.core.x509.TestPki;
import io.github.suengineering.eudiw.service.config.ConfigLoader;
import java.io.StringReader;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;

/**
 * The request-signing key in HashiCorp Vault's Transit engine, against a real Vault server (dev mode). The key is
 * created in Vault, its public key is certified by a test CA, and the adapter only ever asks Vault to sign.
 */
class VaultTransitSignerTest {

    static final String VAULT_IMAGE =
            "hashicorp/vault:1.21.1@sha256:f4e2687b72858a9e2160c344c9fa1ef74c07f21a89a8c00534ab64d3f187b927";
    static final String ROOT_TOKEN = "eudiw-test-root-token";

    static GenericContainer<?> vault;
    static URI address;
    static java.security.cert.X509Certificate leaf;
    static TestPki.Issued root;

    @TempDir
    Path dir;

    @BeforeAll
    static void startVault() throws Exception {
        vault = new GenericContainer<>(VAULT_IMAGE)
                .withEnv("VAULT_DEV_ROOT_TOKEN_ID", ROOT_TOKEN)
                .withEnv("VAULT_DEV_LISTEN_ADDRESS", "0.0.0.0:8200")
                .withExposedPorts(8200)
                .waitingFor(Wait.forHttp("/v1/sys/health").forStatusCode(200));
        vault.start();
        address = URI.create("http://" + vault.getHost() + ":" + vault.getMappedPort(8200));
        vaultCall("POST", "/v1/sys/mounts/transit", "{\"type\":\"transit\"}");
        vaultCall("POST", "/v1/transit/keys/rp", "{\"type\":\"ecdsa-p256\"}");
        vaultCall("POST", "/v1/transit/keys/rsa", "{\"type\":\"rsa-2048\"}");
        leaf = certify(publicKey("rp", 1));
    }

    @AfterAll
    static void stopVault() {
        if (vault != null) {
            vault.stop();
        }
    }

    @Test
    void signsRequestObjectsWithAKeyThatNeverLeavesVault() throws Exception {
        VerifierIdentity identity =
                new VerifierIdentity(signer("rp", OptionalInt.empty(), token(ROOT_TOKEN)), List.of(leaf));

        JWSObject jws = new JWSObject(new JWSHeader(JWSAlgorithm.ES256), new Payload("{\"probe\":true}"));
        jws.sign(new Es256JwsSigner(identity.signer()));

        assertThat(JWSObject.parse(jws.serialize()).verify(new ECDSAVerifier((ECPublicKey) leaf.getPublicKey())))
                .isTrue();
    }

    @Test
    void readsTheTokenOnEverySignatureAndNeverReportsIt() throws Exception {
        Path tokenFile = token("not-a-valid-token");
        VaultTransitSigner signer = signer("rp", OptionalInt.empty(), tokenFile);

        assertThatThrownBy(() -> signer.signEs256(new byte[] {1}))
                .isInstanceOf(JOSEException.class)
                .hasMessageContaining("HTTP 403")
                .hasMessageContaining("permission denied")
                .hasMessageNotContaining("not-a-valid-token");

        // The agent replaces the token: the next signature uses it, without a new signer.
        Files.writeString(tokenFile, ROOT_TOKEN + "\n");
        assertThat(signer.signEs256(new byte[] {1})).hasSize(64);
    }

    @Test
    void aRotatedKeyFailsClosedUnlessTheVersionIsPinned() throws Exception {
        vaultCall("POST", "/v1/transit/keys/rotating", "{\"type\":\"ecdsa-p256\"}");
        java.security.cert.X509Certificate certificate = certify(publicKey("rotating", 1));
        Path tokenFile = token(ROOT_TOKEN);
        VerifierIdentity latest =
                new VerifierIdentity(signer("rotating", OptionalInt.empty(), tokenFile), List.of(certificate));
        VerifierIdentity pinned =
                new VerifierIdentity(signer("rotating", OptionalInt.of(1), tokenFile), List.of(certificate));

        vaultCall("POST", "/v1/transit/keys/rotating/rotate", "{}");

        assertThatThrownBy(() -> latest.signer().signEs256(new byte[] {2}))
                .isInstanceOf(JOSEException.class)
                .hasMessageContaining("no longer matches");
        assertThat(pinned.signer().signEs256(new byte[] {2})).hasSize(64);
    }

    @Test
    void refusesAKeyThatDoesNotMatchTheCertificateAtStartup() throws Exception {
        java.security.cert.X509Certificate other = certify(TestPki.ecKeyPair().getPublic());

        assertThatThrownBy(() ->
                        new VerifierIdentity(signer("rp", OptionalInt.empty(), token(ROOT_TOKEN)), List.of(other)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("does not match the end-entity certificate");
    }

    @Test
    void namesTheProblemWithANonEcKey() throws Exception {
        VaultTransitSigner signer = signer("rsa", OptionalInt.empty(), token(ROOT_TOKEN));

        assertThatThrownBy(() -> signer.signEs256(new byte[] {3}))
                .isInstanceOf(JOSEException.class)
                .hasMessageContaining("Vault Transit");
    }

    @Test
    void anUnreachableVaultIsAnErrorWithoutSecrets() throws Exception {
        VaultTransitSigner signer = new VaultTransitSigner(new VaultTransitSigner.Settings(
                URI.create("http://127.0.0.1:1"),
                "transit",
                "rp",
                OptionalInt.empty(),
                Optional.empty(),
                token(ROOT_TOKEN)));

        assertThatThrownBy(() -> signer.signEs256(new byte[] {4}))
                .isInstanceOf(JOSEException.class)
                .hasMessageContaining("cannot be reached")
                .hasMessageNotContaining(ROOT_TOKEN);
    }

    @Test
    void aNewTokenIsNotANewConfigurationRevision() throws Exception {
        Files.writeString(dir.resolve("rp.pem"), pem(leaf));
        Files.writeString(dir.resolve("anchors.pem"), pem(root.certificate()));
        Files.writeString(dir.resolve("vault-token"), ROOT_TOKEN + "\n");
        Path file = dir.resolve("tenants.json");
        Files.writeString(file, """
                {"tenants":[{"id":"t","verifier":{"certificate_chain_file":"rp.pem",
                    "vault_transit":{"address":"%s","key_name":"rp","token_file":"vault-token"}},
                  "clients":[{"client_id":"c","policies":["p"]}],
                  "policies":[{"id":"p","dcql":{"credentials":[{"id":"age","format":"dc+sd-jwt",
                      "meta":{"vct_values":["https://credentials.test.example/age"]},"claims":[{"path":["age_over_18"]}]}]},
                    "output":{"age_over_18":{"credential":"age","path":["age_over_18"]}},
                    "trust_anchors_file":"anchors.pem"}]}]}""".formatted(address));
        String before = ConfigLoader.load(file, false).revision();

        // Vault Agent renews into a different token; each replica has its own.
        @SuppressWarnings("unchecked")
        Map<String, Object> auth =
                (Map<String, Object>) Json.parseObject(vaultCall("POST", "/v1/auth/token/create", "{}"), "test")
                        .get("auth");
        Files.writeString(dir.resolve("vault-token"), auth.get("client_token") + "\n");

        assertThat(ConfigLoader.load(file, false).revision()).isEqualTo(before);
    }

    private static String pem(java.security.cert.X509Certificate c) throws Exception {
        return "-----BEGIN CERTIFICATE-----\n"
                + java.util.Base64.getMimeEncoder().encodeToString(c.getEncoded()) + "\n-----END CERTIFICATE-----\n";
    }

    private VaultTransitSigner signer(String key, OptionalInt version, Path tokenFile) {
        return new VaultTransitSigner(
                new VaultTransitSigner.Settings(address, "transit", key, version, Optional.empty(), tokenFile));
    }

    private Path token(String value) throws Exception {
        Path file = Files.createTempFile(dir, "vault-token", "");
        Files.writeString(file, value + "\n");
        return file;
    }

    private static String vaultCall(String method, String path, String body) throws Exception {
        HttpResponse<String> response = HttpClient.newHttpClient()
                .send(
                        HttpRequest.newBuilder(address.resolve(path))
                                .header("X-Vault-Token", ROOT_TOKEN)
                                .method(
                                        method,
                                        body == null
                                                ? HttpRequest.BodyPublishers.noBody()
                                                : HttpRequest.BodyPublishers.ofString(body))
                                .build(),
                        HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode())
                .as(method + " " + path + ": " + response.body())
                .isBetween(200, 204);
        return response.body();
    }

    @SuppressWarnings("unchecked")
    private static PublicKey publicKey(String key, int version) throws Exception {
        Map<String, Object> data =
                (Map<String, Object>) Json.parseObject(vaultCall("GET", "/v1/transit/keys/" + key, null), "test")
                        .get("data");
        Map<String, Object> keys = (Map<String, Object>) data.get("keys");
        String pem = (String) ((Map<String, Object>) keys.get(Integer.toString(version))).get("public_key");
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            return new JcaPEMKeyConverter().getPublicKey((SubjectPublicKeyInfo) parser.readObject());
        }
    }

    private static java.security.cert.X509Certificate certify(PublicKey key) throws Exception {
        Instant now = Instant.now();
        if (root == null) {
            root = TestPki.rootCa("CN=RP Root", now.minus(Duration.ofDays(1)), now.plus(Duration.ofDays(30)));
        }
        return new JcaX509CertificateConverter()
                .getCertificate(new JcaX509v3CertificateBuilder(
                                root.certificate(),
                                BigInteger.valueOf(now.toEpochMilli()),
                                Date.from(now.minus(Duration.ofDays(1))),
                                Date.from(now.plus(Duration.ofDays(30))),
                                new X500Name("CN=Verifier in Vault"),
                                key)
                        .addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
                        .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature))
                        .build(new JcaContentSignerBuilder("SHA256withECDSA")
                                .build(root.keyPair().getPrivate())));
    }
}
