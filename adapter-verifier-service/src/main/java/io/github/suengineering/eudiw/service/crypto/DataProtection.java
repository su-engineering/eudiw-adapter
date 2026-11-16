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

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Encrypts data at rest (results, per-request private keys) with AES-256-GCM under a key derived per tenant from
 * the deployment's master key (HKDF-SHA256, RFC 5869). The tenant and a purpose label are bound as associated data,
 * so ciphertext cannot be moved between tenants or fields.
 */
public final class DataProtection {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int IV_LENGTH = 12;

    private final byte[] masterKey;

    public DataProtection(byte[] masterKey) {
        if (masterKey.length != 32) {
            throw new IllegalArgumentException("the data protection key must be 32 bytes");
        }
        this.masterKey = masterKey.clone();
    }

    public byte[] encrypt(String tenantId, String purpose, byte[] plaintext) {
        try {
            byte[] iv = new byte[IV_LENGTH];
            RANDOM.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, tenantKey(tenantId), new GCMParameterSpec(128, iv));
            cipher.updateAAD(aad(tenantId, purpose));
            byte[] ciphertext = cipher.doFinal(plaintext);
            return ByteBuffer.allocate(iv.length + ciphertext.length)
                    .put(iv)
                    .put(ciphertext)
                    .array();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("encryption failed", e);
        }
    }

    public byte[] decrypt(String tenantId, String purpose, byte[] data) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(
                    Cipher.DECRYPT_MODE,
                    tenantKey(tenantId),
                    new GCMParameterSpec(128, Arrays.copyOfRange(data, 0, IV_LENGTH)));
            cipher.updateAAD(aad(tenantId, purpose));
            return cipher.doFinal(data, IV_LENGTH, data.length - IV_LENGTH);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("decryption failed", e);
        }
    }

    /** One-way hash for values that are only ever compared (idempotency keys, response codes). */
    public static String hash(String value) {
        try {
            return HexFormat.of()
                    .formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private SecretKeySpec tenantKey(String tenantId) throws GeneralSecurityException {
        // HKDF-Extract with a fixed salt, then one block of HKDF-Expand with the tenant as info.
        Mac extract = Mac.getInstance("HmacSHA256");
        extract.init(
                new SecretKeySpec("eudiw-adapter data protection v1".getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        byte[] prk = extract.doFinal(masterKey);
        Mac expand = Mac.getInstance("HmacSHA256");
        expand.init(new SecretKeySpec(prk, "HmacSHA256"));
        expand.update(("tenant:" + tenantId).getBytes(StandardCharsets.UTF_8));
        expand.update((byte) 1);
        return new SecretKeySpec(expand.doFinal(), "AES");
    }

    private static byte[] aad(String tenantId, String purpose) {
        return (tenantId + "\n" + purpose).getBytes(StandardCharsets.UTF_8);
    }
}
