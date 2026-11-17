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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Encrypts data at rest (results, per-request private keys) with AES-256-GCM under a key derived per tenant from
 * the deployment's master key (HKDF-SHA256, RFC 5869). The tenant and a purpose label are bound as associated data,
 * so ciphertext cannot be moved between tenants or fields.
 *
 * <p>Ciphertext names the master key that wrote it: a four-byte marker, an eight-byte key id derived from the key,
 * then the IV and the GCM output. Only the current key encrypts; previous keys still decrypt, so a key can be
 * rotated while results and request keys written under the old one are still live. Ciphertext from 0.2.0, which has
 * no key id, is tried against every key.
 */
public final class DataProtection {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int IV_LENGTH = 12;
    private static final int KEY_ID_LENGTH = 8;
    private static final byte[] MARKER = {'E', 'D', 'P', 1};
    private static final int HEADER_LENGTH = MARKER.length + KEY_ID_LENGTH;

    private record MasterKey(byte[] id, byte[] key) {}

    private final MasterKey current;
    private final List<MasterKey> all;

    public DataProtection(byte[] masterKey) {
        this(masterKey, List.of());
    }

    /**
     * @param masterKey the key that encrypts
     * @param previousKeys keys that only decrypt, for ciphertext written before a rotation
     */
    public DataProtection(byte[] masterKey, List<byte[]> previousKeys) {
        current = masterKey(masterKey);
        List<MasterKey> keys = new ArrayList<>();
        keys.add(current);
        for (byte[] previous : previousKeys) {
            MasterKey key = masterKey(previous);
            if (keys.stream().noneMatch(k -> Arrays.equals(k.id(), key.id()))) {
                keys.add(key);
            }
        }
        all = List.copyOf(keys);
    }

    private static MasterKey masterKey(byte[] key) {
        if (key.length != 32) {
            throw new IllegalArgumentException("the data protection key must be 32 bytes");
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            byte[] id = Arrays.copyOf(
                    mac.doFinal("eudiw-adapter data protection key id".getBytes(StandardCharsets.UTF_8)),
                    KEY_ID_LENGTH);
            return new MasterKey(id, key.clone());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The id written into new ciphertext, as hex; it reveals nothing about the key. */
    public String keyId() {
        return HexFormat.of().formatHex(current.id());
    }

    public byte[] encrypt(String tenantId, String purpose, byte[] plaintext) {
        try {
            byte[] iv = new byte[IV_LENGTH];
            RANDOM.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, tenantKey(current, tenantId), new GCMParameterSpec(128, iv));
            cipher.updateAAD(aad(tenantId, purpose));
            byte[] ciphertext = cipher.doFinal(plaintext);
            return ByteBuffer.allocate(HEADER_LENGTH + iv.length + ciphertext.length)
                    .put(MARKER)
                    .put(current.id())
                    .put(iv)
                    .put(ciphertext)
                    .array();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("encryption failed", e);
        }
    }

    public byte[] decrypt(String tenantId, String purpose, byte[] data) {
        if (data.length > HEADER_LENGTH + IV_LENGTH
                && Arrays.equals(data, 0, MARKER.length, MARKER, 0, MARKER.length)) {
            byte[] id = Arrays.copyOfRange(data, MARKER.length, HEADER_LENGTH);
            for (MasterKey key : all) {
                if (Arrays.equals(key.id(), id)) {
                    byte[] plaintext = open(key, tenantId, purpose, data, HEADER_LENGTH);
                    if (plaintext != null) {
                        return plaintext;
                    }
                }
            }
        }
        // Written before key ids (0.2.0), or an IV that happened to start with the marker.
        for (MasterKey key : all) {
            byte[] plaintext = open(key, tenantId, purpose, data, 0);
            if (plaintext != null) {
                return plaintext;
            }
        }
        throw new IllegalStateException("decryption failed");
    }

    /** The plaintext, or {@code null} when this key does not authenticate the data. */
    private static byte[] open(MasterKey key, String tenantId, String purpose, byte[] data, int offset) {
        if (data.length < offset + IV_LENGTH + 16) {
            return null;
        }
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(
                    Cipher.DECRYPT_MODE,
                    tenantKey(key, tenantId),
                    new GCMParameterSpec(128, Arrays.copyOfRange(data, offset, offset + IV_LENGTH)));
            cipher.updateAAD(aad(tenantId, purpose));
            return cipher.doFinal(data, offset + IV_LENGTH, data.length - offset - IV_LENGTH);
        } catch (javax.crypto.AEADBadTagException e) {
            return null;
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

    private static SecretKeySpec tenantKey(MasterKey key, String tenantId) throws GeneralSecurityException {
        // HKDF-Extract with a fixed salt, then one block of HKDF-Expand with the tenant as info.
        Mac extract = Mac.getInstance("HmacSHA256");
        extract.init(
                new SecretKeySpec("eudiw-adapter data protection v1".getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        byte[] prk = extract.doFinal(key.key());
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
