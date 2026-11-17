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
package io.github.suengineering.eudiw.core.status;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.suengineering.eudiw.core.cbor.CborEncoder;
import io.github.suengineering.eudiw.core.cbor.CborItem;
import io.github.suengineering.eudiw.core.jose.AlgorithmPolicy;
import io.github.suengineering.eudiw.core.net.HttpFetcher;
import io.github.suengineering.eudiw.core.status.StatusDecision.Result;
import io.github.suengineering.eudiw.core.x509.TestPki;
import io.github.suengineering.eudiw.core.x509.TestPki.Issued;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.jupiter.api.Test;

/** Status List Tokens in CWT form (Token Status List section 5.2), as an mdoc issuer may serve them. */
class StatusListCwtTest {

    private static final String URI = "https://status.test.example/lists/1";
    // section 4 example: statuses 1,2,0,3,0,1,0,1,1,2,3,3
    private static final byte[] TWO_BIT = Base64.getUrlDecoder().decode("eNo76fITAAPfAgc");

    private final Instant now = Instant.parse("2027-01-15T10:00:00Z");
    private final Issued root = TestPki.rootCa("CN=Status Root", now.minusSeconds(86400), now.plusSeconds(86400 * 365));
    private final Issued signer = TestPki.endEntity(
            "CN=Status Signer",
            root,
            now.minusSeconds(86400),
            now.plusSeconds(86400 * 30),
            KeyUsage.digitalSignature,
            List.of());
    private final AtomicReference<byte[]> served = new AtomicReference<>();
    private final AtomicReference<String> accepted = new AtomicReference<>();
    private final HttpFetcher fetcher = (uri, accept, maxBytes) -> {
        accepted.set(accept);
        if (served.get() == null) {
            throw new HttpFetcher.FetchException("not found");
        }
        return served.get();
    };

    @Test
    void aCwtListAnswersAnMdocReference() {
        served.set(cwt(claims(URI, now.plusSeconds(3600)), "application/statuslist+cwt", signer));
        StatusListChecker checker = checker();
        assertThat(checker.check(status(2), "t", true).result()).isEqualTo(Result.VALID);
        assertThat(checker.check(status(0), "t", true).result()).isEqualTo(Result.INVALID);
        assertThat(checker.check(status(1), "t", true).result()).isEqualTo(Result.SUSPENDED);
        assertThat(accepted.get()).startsWith("application/statuslist+cwt");
    }

    @Test
    void anUntrustworthyCwtIsIndeterminate() {
        Issued otherRoot = TestPki.rootCa("CN=Other Root", now.minusSeconds(86400), now.plusSeconds(86400 * 365));
        Issued stranger = TestPki.endEntity(
                "CN=Stranger",
                otherRoot,
                now.minusSeconds(86400),
                now.plusSeconds(86400 * 30),
                KeyUsage.digitalSignature,
                List.of());
        for (byte[] token : List.of(
                cwt(claims(URI, now.plusSeconds(3600)), "application/statuslist+jwt", signer),
                cwt(
                        claims("https://status.test.example/lists/2", now.plusSeconds(3600)),
                        "application/statuslist+cwt",
                        signer),
                cwt(claims(URI, now.minusSeconds(3600)), "application/statuslist+cwt", signer),
                cwt(claims(URI, now.plusSeconds(3600)), "application/statuslist+cwt", stranger),
                tampered(cwt(claims(URI, now.plusSeconds(3600)), "application/statuslist+cwt", signer)))) {
            served.set(token);
            StatusDecision decision = checker().check(status(2), "t", true);
            assertThat(decision.result()).isEqualTo(Result.INDETERMINATE);
        }
    }

    @Test
    void aCwtFromAnIndependentImplementationVerifies() throws Exception {
        // Served by eudi-dev v3.8.0 after the credential at index 122 was revoked (see resources/status/README.md).
        byte[] token = java.nio.file.Files.readAllBytes(
                java.nio.file.Path.of("src/test/resources/status/eudi-dev-statuslist.cwt"));
        X509Certificate ca = (X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509")
                .generateCertificate(java.nio.file.Files.newInputStream(
                        java.nio.file.Path.of("src/test/resources/status/eudi-dev-wallet-ca.crt")));
        StatusListChecker checker = new StatusListChecker(
                (uri, accept, maxBytes) -> token,
                () -> Set.of(new TrustAnchor(ca, null)),
                AlgorithmPolicy.DEFAULT,
                Clock.fixed(Instant.parse("2026-11-17T15:50:00Z"), ZoneOffset.UTC),
                Duration.ofSeconds(60),
                Duration.ofHours(1),
                100);
        Map<String, Object> revoked =
                Map.of("status_list", Map.of("idx", 122L, "uri", "https://localhost:8086/api/statuslist"));
        assertThat(checker.check(revoked, "t", true).result()).isEqualTo(Result.INVALID);
        Map<String, Object> valid =
                Map.of("status_list", Map.of("idx", 0L, "uri", "https://localhost:8086/api/statuslist"));
        assertThat(checker.check(valid, "t", true).result()).isEqualTo(Result.VALID);
    }

    // -- helpers

    private StatusListChecker checker() {
        return new StatusListChecker(
                fetcher,
                () -> Set.of(new TrustAnchor(root.certificate(), null)),
                AlgorithmPolicy.DEFAULT,
                Clock.fixed(now, ZoneOffset.UTC),
                Duration.ofSeconds(60),
                Duration.ofHours(1),
                100);
    }

    private Map<CborItem, CborItem> claims(String sub, Instant exp) {
        Map<CborItem, CborItem> claims = new LinkedHashMap<>();
        claims.put(CborEncoder.integer(2), CborEncoder.text(sub));
        claims.put(
                CborEncoder.integer(6), CborEncoder.integer(now.minusSeconds(60).getEpochSecond()));
        claims.put(CborEncoder.integer(4), CborEncoder.integer(exp.getEpochSecond()));
        claims.put(CborEncoder.integer(65534), CborEncoder.integer(600));
        Map<CborItem, CborItem> list = new LinkedHashMap<>();
        list.put(CborEncoder.text("bits"), CborEncoder.integer(2));
        list.put(CborEncoder.text("lst"), CborEncoder.bytes(TWO_BIT));
        claims.put(CborEncoder.integer(65533), CborEncoder.map(list));
        return claims;
    }

    /** A COSE_Sign1_Tagged CWT, ES256, with the signer chain in x5chain. */
    static byte[] cwt(Map<CborItem, CborItem> claims, String type, Issued by) {
        try {
            Map<CborItem, CborItem> header = new LinkedHashMap<>();
            header.put(CborEncoder.integer(1), CborEncoder.integer(-7));
            header.put(CborEncoder.integer(16), CborEncoder.text(type));
            byte[] protectedBytes = CborEncoder.map(header).encoded();
            byte[] payload = CborEncoder.map(claims).encoded();
            byte[] toBeSigned = CborEncoder.array(
                            CborEncoder.text("Signature1"),
                            CborEncoder.bytes(protectedBytes),
                            CborEncoder.bytes(new byte[0]),
                            CborEncoder.bytes(payload))
                    .encoded();
            PrivateKey key = by.keyPair().getPrivate();
            Signature s = Signature.getInstance("SHA256withECDSAinP1363Format");
            s.initSign(key);
            s.update(toBeSigned);
            X509Certificate certificate = by.certificate();
            Map<CborItem, CborItem> unprotected = new LinkedHashMap<>();
            unprotected.put(CborEncoder.integer(33), CborEncoder.bytes(certificate.getEncoded()));
            return CborEncoder.tag(
                            18,
                            CborEncoder.array(
                                    CborEncoder.bytes(protectedBytes),
                                    CborEncoder.map(unprotected),
                                    CborEncoder.bytes(payload),
                                    CborEncoder.bytes(s.sign())))
                    .encoded();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] tampered(byte[] token) {
        byte[] copy = token.clone();
        copy[copy.length - 1] ^= 1;
        return copy;
    }

    private static Map<String, Object> status(long idx) {
        return Map.of("status_list", Map.of("idx", idx, "uri", URI));
    }
}
