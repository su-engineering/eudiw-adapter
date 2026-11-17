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
package io.github.suengineering.eudiw.service;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.suengineering.eudiw.core.json.Json;
import io.github.suengineering.eudiw.service.engine.WebhookSigner;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The shared vector the Node and Python examples verify must be exactly what the adapter's signer produces, so the
 * example verifiers are tested against the real sender.
 */
class WebhookVectorTest {

    @Test
    void theExampleVectorIsWhatTheAdapterSends() throws Exception {
        Map<String, Object> vector = Json.parseObject(
                Files.readString(Path.of("..", "examples", "shared", "webhook-vector.json")), "invalid");
        @SuppressWarnings("unchecked")
        Map<String, Object> headers = (Map<String, Object>) vector.get("headers");
        byte[] current = secret((String) vector.get("secret"));
        byte[] previous = secret((String) vector.get("previous_secret"));
        String signature = WebhookSigner.signatureHeader(
                List.of(current, previous),
                (String) headers.get("webhook-id"),
                Long.parseLong((String) headers.get("webhook-timestamp")),
                (String) vector.get("body"));
        assertThat(signature).isEqualTo(headers.get("webhook-signature"));
    }

    private static byte[] secret(String value) {
        return Base64.getDecoder().decode(value.substring("whsec_".length()));
    }
}
