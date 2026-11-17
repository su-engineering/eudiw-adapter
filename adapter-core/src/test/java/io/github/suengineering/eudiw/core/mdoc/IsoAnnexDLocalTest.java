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
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.github.suengineering.eudiw.core.cbor.CborDecoder;
import io.github.suengineering.eudiw.core.cbor.CborItem;
import io.github.suengineering.eudiw.core.x509.TrustStore;
import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Issuer data authentication of the device retrieval response example in ISO/IEC 18013-5:2021 Annex D, which
 * cannot be committed. It runs only when {@code EUDIW_ISO_18013_5_ANNEX_D} names a directory, outside this
 * repository, holding {@code device-response.cbor} (the Annex D.4.1.2 response) and {@code iaca.der} (the IACA of
 * Annex D.5.2), extracted from a licensed copy of the standard.
 */
class IsoAnnexDLocalTest {

    @Test
    void theAnnexDResponsePassesIssuerDataAuthentication() throws Exception {
        String dir = System.getenv("EUDIW_ISO_18013_5_ANNEX_D");
        if (dir == null) {
            System.err.println(
                    "SKIPPED IsoAnnexDLocalTest: set EUDIW_ISO_18013_5_ANNEX_D to run the ISO Annex D check");
        }
        assumeTrue(dir != null, "EUDIW_ISO_18013_5_ANNEX_D is not set");
        byte[] response = Files.readAllBytes(Path.of(dir, "device-response.cbor"));
        X509Certificate iaca = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(Files.readAllBytes(Path.of(dir, "iaca.der"))));

        CborItem.MapItem deviceResponse = (CborItem.MapItem) CborDecoder.decode(response);
        CborItem document = ((CborItem.Array) deviceResponse.get("documents").orElseThrow())
                .items()
                .get(0);
        // The example MSO is valid from 2020-10-01 for a year.
        MdocIssuerVerifier verifier = new MdocIssuerVerifier(
                () -> TrustStore.of(List.of(iaca), "iso-annex-d"),
                Clock.fixed(Instant.parse("2021-01-01T00:00:00Z"), ZoneOffset.UTC),
                Duration.ofMinutes(1),
                null,
                MdocIssuerVerifier.mdlOnly());
        VerifiedIssuerSigned verified = verifier.verify(document);
        assertThat(verified.docType()).isEqualTo(MdocIssuerVerifier.MDL_DOCTYPE);
        assertThat(verified.elements()).containsKey("org.iso.18013.5.1");
        assertThat(verified.elements().get("org.iso.18013.5.1")).isNotEmpty();
    }
}
