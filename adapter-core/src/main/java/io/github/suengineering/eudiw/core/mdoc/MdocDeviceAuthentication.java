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

import io.github.suengineering.eudiw.core.VerificationFailure;
import io.github.suengineering.eudiw.core.cbor.CborItem;

/**
 * mdoc authentication: proof that the presenting device holds the key the MSO binds, over this session's
 * transcript (ISO/IEC 18013-5:2021 clause 9.1.3). Without it an issued mdoc could be replayed by anyone who
 * obtained a copy, so a presentation is never accepted unless this step passes.
 */
@FunctionalInterface
public interface MdocDeviceAuthentication {

    /**
     * @param document the Document of the DeviceResponse
     * @param issuerSigned the issuer-verified part, carrying the device key
     * @param sessionTranscript the session transcript of this request
     * @throws VerificationFailure when the device authentication is missing or does not verify
     */
    void authenticate(CborItem.MapItem document, VerifiedIssuerSigned issuerSigned, CborItem sessionTranscript);

    /**
     * Rejects every presentation. Used until device authentication is implemented (ADR-012): issuer verification
     * alone must not be enough to accept an mdoc.
     */
    MdocDeviceAuthentication NOT_IMPLEMENTED = (document, issuerSigned, transcript) -> {
        throw new VerificationFailure("unsupported_format", "mdoc device authentication is not implemented yet");
    };
}
