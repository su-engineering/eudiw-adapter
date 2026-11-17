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
package io.github.suengineering.eudiw.service.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

class DataProtectionTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final byte[] PLAINTEXT = "{\"age_over_18\":true}".getBytes(StandardCharsets.UTF_8);

    private static byte[] key() {
        byte[] key = new byte[32];
        RANDOM.nextBytes(key);
        return key;
    }

    @Test
    void ciphertextRoundTripsAndIsBoundToTenantAndPurpose() {
        DataProtection protection = new DataProtection(key());
        byte[] data = protection.encrypt("t", "result:1", PLAINTEXT);
        assertThat(protection.decrypt("t", "result:1", data)).isEqualTo(PLAINTEXT);
        assertThatThrownBy(() -> protection.decrypt("u", "result:1", data)).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> protection.decrypt("t", "result:2", data)).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void aPreviousKeyStillDecryptsButNoLongerEncrypts() {
        byte[] old = key();
        byte[] next = key();
        byte[] written = new DataProtection(old).encrypt("t", "result:1", PLAINTEXT);

        DataProtection rotated = new DataProtection(next, List.of(old));
        assertThat(rotated.decrypt("t", "result:1", written)).isEqualTo(PLAINTEXT);
        byte[] fresh = rotated.encrypt("t", "result:1", PLAINTEXT);
        assertThat(new DataProtection(next).decrypt("t", "result:1", fresh)).isEqualTo(PLAINTEXT);
        assertThatThrownBy(() -> new DataProtection(old).decrypt("t", "result:1", fresh))
                .isInstanceOf(IllegalStateException.class);
        // Once the old key is dropped, what it wrote cannot be read.
        assertThatThrownBy(() -> new DataProtection(next).decrypt("t", "result:1", written))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void ciphertextCarriesTheKeyId() {
        DataProtection protection = new DataProtection(key());
        byte[] data = protection.encrypt("t", "p", PLAINTEXT);
        assertThat(new String(data, 0, 3, StandardCharsets.US_ASCII)).isEqualTo("EDP");
        assertThat(java.util.HexFormat.of().formatHex(data, 4, 12)).isEqualTo(protection.keyId());
    }

    @Test
    void ciphertextWrittenBeforeKeyIdsStillDecrypts() throws Exception {
        byte[] old = key();
        byte[] next = key();
        byte[] legacy = legacyEncrypt(old, "t", "result:1", PLAINTEXT);
        assertThat(new DataProtection(old).decrypt("t", "result:1", legacy)).isEqualTo(PLAINTEXT);
        assertThat(new DataProtection(next, List.of(old)).decrypt("t", "result:1", legacy))
                .isEqualTo(PLAINTEXT);
    }

    @Test
    void refusesKeysOfTheWrongLength() {
        assertThatThrownBy(() -> new DataProtection(new byte[16])).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new DataProtection(key(), List.of(new byte[31])))
                .isInstanceOf(IllegalArgumentException.class);
    }

    /** The 0.2.0 format: IV and GCM output, no marker and no key id. */
    private static byte[] legacyEncrypt(byte[] master, String tenant, String purpose, byte[] plaintext)
            throws Exception {
        Mac extract = Mac.getInstance("HmacSHA256");
        extract.init(
                new SecretKeySpec("eudiw-adapter data protection v1".getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        Mac expand = Mac.getInstance("HmacSHA256");
        expand.init(new SecretKeySpec(extract.doFinal(master), "HmacSHA256"));
        expand.update(("tenant:" + tenant).getBytes(StandardCharsets.UTF_8));
        expand.update((byte) 1);
        byte[] iv = new byte[12];
        RANDOM.nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(expand.doFinal(), "AES"), new GCMParameterSpec(128, iv));
        cipher.updateAAD((tenant + "\n" + purpose).getBytes(StandardCharsets.UTF_8));
        byte[] ciphertext = cipher.doFinal(plaintext);
        return ByteBuffer.allocate(iv.length + ciphertext.length)
                .put(iv)
                .put(ciphertext)
                .array();
    }
}
