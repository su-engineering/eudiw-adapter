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
package io.github.suengineering.eudiw.core.keys;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Loads a private key from a PKCS#11 token through the JDK's SunPKCS11 provider: a hardware HSM, a cloud HSM or KMS
 * with a PKCS#11 library, or SoftHSM for tests. The key never leaves the token; signing happens inside it.
 */
public final class Pkcs11Keys {

    /** A key handle and the provider that can use it. */
    public record Loaded(PrivateKey key, Provider provider) {}

    private static final Map<String, Provider> PROVIDERS = new ConcurrentHashMap<>();

    private Pkcs11Keys() {}

    /**
     * @param library path of the PKCS#11 library
     * @param slotListIndex index of the slot in the library's slot list
     * @param keyLabel label ({@code CKA_LABEL}) of the private key, which is its alias in the PKCS#11 key store
     * @param pin user PIN of the token
     * @throws IllegalArgumentException when the token or key cannot be used
     */
    public static Loaded load(Path library, int slotListIndex, String keyLabel, char[] pin) {
        Objects.requireNonNull(library, "library");
        Objects.requireNonNull(keyLabel, "keyLabel");
        Provider provider = provider(library, slotListIndex);
        try {
            KeyStore store = KeyStore.getInstance("PKCS11", provider);
            store.load(null, pin);
            Key key = store.getKey(keyLabel, null);
            if (!(key instanceof PrivateKey privateKey)) {
                throw new IllegalArgumentException("no private key with label " + keyLabel + " on the token");
            }
            return new Loaded(privateKey, provider);
        } catch (GeneralSecurityException | IOException e) {
            throw new IllegalArgumentException("PKCS#11 token cannot be opened: " + e.getMessage(), e);
        }
    }

    /** The provider for one library and slot; created once per JVM, since a PKCS#11 library is initialized once. */
    public static Provider provider(Path library, int slotListIndex) {
        if (!Files.isRegularFile(library)) {
            throw new IllegalArgumentException("PKCS#11 library not found: " + library);
        }
        String name = "eudiw-" + Integer.toHexString((library.toAbsolutePath() + "#" + slotListIndex).hashCode());
        return PROVIDERS.computeIfAbsent(name, n -> {
            Provider base = Security.getProvider("SunPKCS11");
            if (base == null) {
                throw new IllegalArgumentException("the SunPKCS11 provider is not available in this JVM");
            }
            String config =
                    "--name=" + n + "\nlibrary=" + library.toAbsolutePath() + "\nslotListIndex=" + slotListIndex + "\n";
            return base.configure(config);
        });
    }
}
