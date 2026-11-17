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
package io.github.suengineering.eudiw.crypto.brainpool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.suengineering.eudiw.core.ConformanceWarning;
import io.github.suengineering.eudiw.core.VerificationFailure;
import io.github.suengineering.eudiw.core.cbor.CborEncoder;
import io.github.suengineering.eudiw.core.cbor.CborItem;
import io.github.suengineering.eudiw.core.cose.CoseAlgorithm;
import io.github.suengineering.eudiw.core.crypto.Brainpool;
import io.github.suengineering.eudiw.core.mdoc.MdocDeviceAuthentication;
import io.github.suengineering.eudiw.core.mdoc.MdocIssuerVerifier;
import io.github.suengineering.eudiw.core.mdoc.MdocPresentationVerifier;
import io.github.suengineering.eudiw.core.mdoc.SessionTranscripts;
import io.github.suengineering.eudiw.core.mdoc.TestMdocIssuer;
import io.github.suengineering.eudiw.core.x509.TrustStore;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** An mDL on brainpoolP256r1 whose certificates and signatures were made by OpenSSL (see resources/README.md). */
class BrainpoolMdocTest {

    private static final Instant NOW = Instant.parse("2026-11-20T12:00:00Z");
    private static final CborItem TRANSCRIPT = SessionTranscripts.openId4VpRedirect(
            "x509_hash:brainpool-fixture", "nonce-brainpool", Optional.empty(), "https://verifier.example/response");

    @AfterEach
    void off() {
        Brainpool.disable();
    }

    @Test
    void withoutTheModuleABrainpoolMdocIsRefused() throws Exception {
        assertThatThrownBy(() -> verifier().verify(fixture(), MdocIssuerVerifier.MDL_DOCTYPE, TRANSCRIPT))
                .isInstanceOf(VerificationFailure.class);
        assertThat(CoseAlgorithm.ESB256.available()).isFalse();
    }

    @Test
    void enabledABrainpoolMdocVerifies() throws Exception {
        BrainpoolSupport.enable();
        MdocPresentationVerifier.VerifiedMdoc mdoc =
                verifier().verify(fixture(), MdocIssuerVerifier.MDL_DOCTYPE, TRANSCRIPT);
        assertThat(mdoc.claims())
                .isEqualTo(Map.of("org.iso.18013.5.1", Map.of("age_over_18", true, "issuing_country", "DE")));
        // The document signer has no CRL distribution point (Annex B), which only warns.
        assertThat(mdoc.warnings())
                .extracting(ConformanceWarning::code)
                .containsExactly(ConformanceWarning.SIGNER_WITHOUT_CRL_DP);
        assertThat(CoseAlgorithm.ESB256.available()).isTrue();
    }

    @Test
    void enabledTheDeviceSignatureStillBindsTheTranscript() throws Exception {
        BrainpoolSupport.enable();
        CborItem other = SessionTranscripts.openId4VpRedirect(
                "x509_hash:brainpool-fixture", "another-nonce", Optional.empty(), "https://verifier.example/response");
        assertThatThrownBy(() -> verifier().verify(fixture(), MdocIssuerVerifier.MDL_DOCTYPE, other))
                .isInstanceOfSatisfying(
                        VerificationFailure.class, f -> assertThat(f.code()).isEqualTo("holder_binding_invalid"));
    }

    @Test
    void enabledNistCurvesAreUnchanged() throws Exception {
        BrainpoolSupport.enable();
        TestMdocIssuer issuer = new TestMdocIssuer(
                "CN=Test IACA,C=DE",
                "CN=Test DS,C=DE",
                true,
                NOW.minus(Duration.ofDays(30)),
                NOW.plus(Duration.ofDays(300)));
        CborItem document = issuer.document(
                "eu.europa.ec.eudi.pid.1",
                "eu.europa.ec.eudi.pid.1",
                "eu.europa.ec.eudi.pid.1",
                Map.of("age_over_18", CborEncoder.bool(true)),
                NOW.minusSeconds(60),
                NOW.minusSeconds(60),
                NOW.plus(Duration.ofDays(30)));
        assertThat(new MdocIssuerVerifier(
                                () -> TrustStore.of(List.of(issuer.iaca), "test"),
                                Clock.fixed(NOW, ZoneOffset.UTC),
                                Duration.ofMinutes(1),
                                null,
                                MdocIssuerVerifier.mdlOnly())
                        .verify(document)
                        .elements())
                .containsKey("eu.europa.ec.eudi.pid.1");
    }

    private static MdocPresentationVerifier verifier() throws Exception {
        X509Certificate iaca = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(Files.newInputStream(Path.of("src/test/resources/brainpool-iaca.crt")));
        return new MdocPresentationVerifier(
                new MdocIssuerVerifier(
                        () -> TrustStore.of(List.of(iaca), "test"),
                        Clock.fixed(NOW, ZoneOffset.UTC),
                        Duration.ofMinutes(1),
                        null,
                        MdocIssuerVerifier.mdlOnly()),
                MdocDeviceAuthentication.SIGNATURE);
    }

    private static String fixture() throws Exception {
        return Files.readString(Path.of("src/test/resources/brainpool-device-response.b64"))
                .strip();
    }
}
