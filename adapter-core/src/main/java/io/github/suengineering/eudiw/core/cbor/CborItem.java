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
package io.github.suengineering.eudiw.core.cbor;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * A decoded CBOR data item (RFC 8949). Each item keeps the exact bytes it was decoded from, so signatures and
 * digests can be computed over the data as received rather than over a re-encoding.
 */
public sealed interface CborItem {

    /** The bytes this item was decoded from, or its encoding when built by {@link CborEncoder}. */
    byte[] encoded();

    /** Major types 0 and 1. */
    record Int(BigInteger value, byte[] raw) implements CborItem {
        public byte[] encoded() {
            return raw.clone();
        }

        /** The value as a long, or empty when it does not fit. */
        public Optional<Long> asLong() {
            return value.bitLength() < 64 ? Optional.of(value.longValue()) : Optional.empty();
        }
    }

    /** Major type 2. */
    record Bytes(byte[] value, byte[] raw) implements CborItem {
        public byte[] value() {
            return value.clone();
        }

        public byte[] encoded() {
            return raw.clone();
        }
    }

    /** Major type 3, valid UTF-8. */
    record Text(String value, byte[] raw) implements CborItem {
        public byte[] encoded() {
            return raw.clone();
        }
    }

    /** Major type 4. */
    record Array(List<CborItem> items, byte[] raw) implements CborItem {
        public Array {
            items = List.copyOf(items);
        }

        public byte[] encoded() {
            return raw.clone();
        }
    }

    /** Major type 5, keys unique, in the order received. */
    record MapItem(Map<CborItem, CborItem> entries, byte[] raw) implements CborItem {
        public MapItem {
            entries = Collections.unmodifiableMap(new LinkedHashMap<>(entries));
        }

        public byte[] encoded() {
            return raw.clone();
        }

        /** The value under a text key. */
        public Optional<CborItem> get(String key) {
            for (Map.Entry<CborItem, CborItem> e : entries.entrySet()) {
                if (e.getKey() instanceof Text t && t.value().equals(key)) {
                    return Optional.of(e.getValue());
                }
            }
            return Optional.empty();
        }

        /** The value under an integer key. */
        public Optional<CborItem> get(long key) {
            BigInteger k = BigInteger.valueOf(key);
            for (Map.Entry<CborItem, CborItem> e : entries.entrySet()) {
                if (e.getKey() instanceof Int i && i.value().equals(k)) {
                    return Optional.of(e.getValue());
                }
            }
            return Optional.empty();
        }
    }

    /** Major type 6. */
    record Tag(long number, CborItem content, byte[] raw) implements CborItem {
        public byte[] encoded() {
            return raw.clone();
        }
    }

    /** Major type 7: false, true, null and undefined. */
    record Simple(int value, byte[] raw) implements CborItem {
        public static final int FALSE = 20;
        public static final int TRUE = 21;
        public static final int NULL = 22;
        public static final int UNDEFINED = 23;

        public byte[] encoded() {
            return raw.clone();
        }

        public boolean isNull() {
            return value == NULL;
        }
    }

    /** Major type 7: half, single and double precision floats. */
    record Float(double value, byte[] raw) implements CborItem {
        public byte[] encoded() {
            return raw.clone();
        }
    }

    /**
     * Structural equality over the encoding, used for map keys. Two items are the same key when their encodings
     * are equal; CBOR requires keys to be distinct data items (RFC 8949 section 5.6).
     */
    static boolean sameEncoding(CborItem a, CborItem b) {
        return Arrays.equals(a.encoded(), b.encoded());
    }
}
