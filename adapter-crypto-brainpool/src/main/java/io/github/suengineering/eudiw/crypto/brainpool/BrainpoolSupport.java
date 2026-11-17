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
package io.github.suengineering.eudiw.crypto.brainpool;

import io.github.suengineering.eudiw.core.crypto.Brainpool;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Turns on verification of ISO mdoc signatures on the brainpool curves (brainpoolP256r1, P320r1, P384r1, P512r1),
 * which the JDK cannot verify. BouncyCastle is added as the last security provider and used only where a brainpool
 * key is involved (ADR-012). Nothing happens until {@link #enable()} is called.
 */
public final class BrainpoolSupport {

    private BrainpoolSupport() {}

    /** Enables brainpool curves for this JVM. Calling it again does nothing more. */
    public static void enable() {
        Brainpool.enable(new BouncyCastleProvider());
    }
}
