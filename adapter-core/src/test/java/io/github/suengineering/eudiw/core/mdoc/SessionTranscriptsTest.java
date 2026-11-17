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

import com.nimbusds.jose.jwk.ECKey;
import java.util.HexFormat;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/** The non-normative examples of OpenID4VP 1.0 Appendix B.2.6.1. */
class SessionTranscriptsTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final String CLIENT_ID = "x509_san_dns:example.com";
    private static final String NONCE = "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA";
    private static final String RESPONSE_URI = "https://example.com/response";

    @Test
    void theExampleJwkHasTheExampleThumbprint() throws Exception {
        ECKey jwk = ECKey.parse("""
                {"kty":"EC","crv":"P-256",
                 "x":"DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0",
                 "y":"XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc",
                 "use":"enc","alg":"ECDH-ES","kid":"1"}""");
        assertThat(HEX.formatHex(jwk.computeThumbprint("SHA-256").decode()))
                .isEqualTo("4283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047");
    }

    @Test
    void handoverInfoMatchesTheExample() {
        assertThat(HEX.formatHex(SessionTranscripts.handoverInfo(CLIENT_ID, NONCE, thumbprint(), RESPONSE_URI)
                        .encoded()))
                .isEqualTo("847818783530395f73616e5f646e733a6578616d706c652e636f6d782b6578633767"
                        + "426b786a7831726463397564527276654b7653734a4971383061766c58654c486847"
                        + "7771744158204283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6"
                        + "bd669047781c68747470733a2f2f6578616d706c652e636f6d2f726573706f6e7365");
    }

    @Test
    void sessionTranscriptMatchesTheExample() {
        assertThat(HEX.formatHex(SessionTranscripts.openId4VpRedirect(CLIENT_ID, NONCE, thumbprint(), RESPONSE_URI)
                        .encoded()))
                .isEqualTo("83f6f682714f70656e494434565048616e646f7665725820048bc053c00442af9b8e"
                        + "ed494cefdd9d95240d254b046b11b68013722aad38ac");
    }

    @Test
    void anUnencryptedResponseHasANullThumbprint() {
        byte[] info = SessionTranscripts.handoverInfo(CLIENT_ID, NONCE, Optional.empty(), RESPONSE_URI)
                .encoded();
        // The third element is CBOR null (0xf6) right before the response URI's text header (0x78 0x1c).
        assertThat(HEX.formatHex(info)).contains("f6781c");
    }

    private static Optional<byte[]> thumbprint() {
        return Optional.of(HEX.parseHex("4283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047"));
    }
}
