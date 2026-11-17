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
package io.github.suengineering.eudiw.core.mdoc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.suengineering.eudiw.core.ConformanceWarning;
import io.github.suengineering.eudiw.core.VerificationFailure;
import io.github.suengineering.eudiw.core.cbor.CborDecoder;
import io.github.suengineering.eudiw.core.cbor.CborEncoder;
import io.github.suengineering.eudiw.core.cbor.CborItem;
import io.github.suengineering.eudiw.core.x509.TrustStore;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/** Departures from ISO/IEC 18013-5 that the verifier accepts with a warning instead of a rejection. */
class MdocConformanceWarningsTest {

    private static final Instant NOW = Instant.parse("2026-11-17T12:00:00Z");
    private static final String PID = "eu.europa.ec.eudi.pid.1";
    private static final CborItem TRANSCRIPT = SessionTranscripts.openId4VpRedirect(
            "x509_hash:verifier", "nonce-1", Optional.empty(), "https://verifier.example/response");
    private static final CborItem EMPTY = CborEncoder.embedded(CborEncoder.map(Map.of()));

    @Test
    void aP384DeviceKeyIsAcceptedWithAWarningUnlessStrict() throws Exception {
        TestMdocIssuer issuer = issuer(300);
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp384r1"));
        KeyPair device = g.generateKeyPair();
        issuer.deviceKeyOverride = TestMdocIssuer.coseKey((ECPublicKey) device.getPublic(), 2);
        CborItem.MapItem document = deviceSigned(
                issuer,
                issuer.document(
                        PID,
                        PID,
                        PID,
                        Map.of("age_over_18", CborEncoder.bool(true)),
                        NOW.minusSeconds(60),
                        NOW.minusSeconds(60),
                        NOW.plus(Duration.ofDays(30))),
                device);
        VerifiedIssuerSigned issuerSigned = verifier(issuer.iaca).verify(document);

        assertThat(MdocDeviceAuthentication.SIGNATURE.authenticate(document, issuerSigned, TRANSCRIPT))
                .extracting(ConformanceWarning::code)
                .containsExactly(ConformanceWarning.DEVICE_KEY_CURVE);
        assertThatThrownBy(() ->
                        MdocDeviceAuthentication.STRICT_SIGNATURE.authenticate(document, issuerSigned, TRANSCRIPT))
                .isInstanceOfSatisfying(
                        VerificationFailure.class, f -> assertThat(f.code()).isEqualTo("unsupported_key"));
    }

    @Test
    void aP256DeviceKeyGivesNoWarning() throws Exception {
        TestMdocIssuer issuer = issuer(300);
        CborItem.MapItem document = deviceSigned(issuer, pid(issuer), issuer.deviceKeys);
        assertThat(MdocDeviceAuthentication.STRICT_SIGNATURE.authenticate(
                        document, verifier(issuer.iaca).verify(document), TRANSCRIPT))
                .isEmpty();
    }

    @Test
    void aRootInTheX5chainIsIgnoredAndNeverTrusted() throws Exception {
        TestMdocIssuer issuer = issuer(300);
        issuer.rootInChain = true;
        CborItem.MapItem document = (CborItem.MapItem) pid(issuer);
        VerifiedIssuerSigned verified = verifier(issuer.iaca).verify(document);
        assertThat(verified.warnings())
                .extracting(ConformanceWarning::code)
                .containsExactly(ConformanceWarning.X5CHAIN_INCLUDES_ROOT);
        assertThat(verified.chain()).containsExactly(issuer.signer);
        // The root it carries is not a trust anchor: a verifier that trusts another IACA still rejects.
        assertThatThrownBy(() -> verifier(issuer(300).iaca).verify(document))
                .isInstanceOfSatisfying(
                        VerificationFailure.class, f -> assertThat(f.code()).isEqualTo("certificate_untrusted"));
    }

    @Test
    void annexBSignerDutiesWarnForTheMdlOnly() throws Exception {
        TestMdocIssuer longLived = issuer(600);
        CborItem mdl = longLived.document(
                MdocIssuerVerifier.MDL_DOCTYPE,
                "org.iso.18013.5.1",
                "org.iso.18013.5.1",
                Map.of("age_over_18", CborEncoder.bool(true)),
                NOW.minusSeconds(60),
                NOW.minusSeconds(60),
                NOW.plus(Duration.ofDays(30)));
        assertThat(verifier(longLived.iaca).verify(mdl).warnings())
                .extracting(ConformanceWarning::code)
                .containsExactlyInAnyOrder(
                        ConformanceWarning.SIGNER_VALIDITY, ConformanceWarning.SIGNER_WITHOUT_CRL_DP);
        // The Annex B profile is not applied to other doctypes, so neither is its warning.
        assertThat(verifier(longLived.iaca).verify(pid(longLived)).warnings()).isEmpty();
    }

    // -- helpers

    private static CborItem pid(TestMdocIssuer issuer) throws Exception {
        return issuer.document(
                PID,
                PID,
                PID,
                Map.of("age_over_18", CborEncoder.bool(true)),
                NOW.minusSeconds(60),
                NOW.minusSeconds(60),
                NOW.plus(Duration.ofDays(30)));
    }

    private static CborItem.MapItem deviceSigned(TestMdocIssuer issuer, CborItem document, KeyPair device)
            throws Exception {
        boolean p384 = ((ECPublicKey) device.getPublic())
                        .getParams()
                        .getCurve()
                        .getField()
                        .getFieldSize()
                == 384;
        CborItem signature = TestMdocIssuer.deviceSignature(
                device.getPrivate(),
                p384 ? -35 : -7,
                TestMdocIssuer.deviceAuthentication(TRANSCRIPT, PID, EMPTY),
                false);
        CborItem signed = TestMdocIssuer.withDeviceSigned(
                document, EMPTY, CborEncoder.map(Map.of(CborEncoder.text("deviceSignature"), signature)));
        return (CborItem.MapItem) CborDecoder.decode(signed.encoded());
    }

    private static MdocIssuerVerifier verifier(X509Certificate anchor) {
        return new MdocIssuerVerifier(
                () -> TrustStore.of(List.of(anchor), "test"),
                Clock.fixed(NOW, ZoneOffset.UTC),
                Duration.ofMinutes(1),
                null,
                MdocIssuerVerifier.mdlOnly());
    }

    private static TestMdocIssuer issuer(int signerDays) throws Exception {
        return new TestMdocIssuer(
                "CN=Test IACA,C=DE",
                "CN=Test DS,C=DE",
                true,
                NOW.minus(Duration.ofDays(30)),
                NOW.minus(Duration.ofDays(30)).plus(Duration.ofDays(signerDays)));
    }
}
