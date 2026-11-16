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
package io.github.suengineering.eudiw.service.engine;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Standard Webhooks symmetric signatures: HMAC-SHA256 over {@code id.timestamp.body}, serialized as {@code
 * v1,<base64>}; several secrets give a space-separated list for rotation.
 */
public final class WebhookSigner {

    private WebhookSigner() {}

    public static String signatureHeader(List<byte[]> secrets, String id, long timestamp, String body) {
        if (id.contains(".")) {
            throw new IllegalArgumentException("webhook id must not contain a full stop");
        }
        byte[] content = (id + "." + timestamp + "." + body).getBytes(StandardCharsets.UTF_8);
        List<String> signatures = new ArrayList<>();
        for (byte[] secret : secrets) {
            try {
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(new SecretKeySpec(secret, "HmacSHA256"));
                signatures.add("v1," + Base64.getEncoder().encodeToString(mac.doFinal(content)));
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException(e);
            }
        }
        return String.join(" ", signatures);
    }
}
