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

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Builds CBOR items with preferred serialization: shortest integer and length encodings, definite lengths
 * (RFC 8949 section 4.2.1). Used for the structures the verifier builds itself, such as the session transcript.
 * Maps keep insertion order; callers that need a deterministic map encoding must insert keys in a fixed order.
 */
public final class CborEncoder {

    private CborEncoder() {}

    public static CborItem.Int integer(long value) {
        BigInteger v = BigInteger.valueOf(value);
        byte[] raw = value >= 0 ? head(0, v) : head(1, BigInteger.valueOf(-1).subtract(v));
        return new CborItem.Int(v, raw);
    }

    public static CborItem.Text text(String value) {
        byte[] content = value.getBytes(StandardCharsets.UTF_8);
        return new CborItem.Text(value, concat(head(3, BigInteger.valueOf(content.length)), content));
    }

    public static CborItem.Bytes bytes(byte[] value) {
        return new CborItem.Bytes(value.clone(), concat(head(2, BigInteger.valueOf(value.length)), value));
    }

    public static CborItem.Simple nil() {
        return new CborItem.Simple(CborItem.Simple.NULL, new byte[] {(byte) 0xf6});
    }

    public static CborItem.Simple bool(boolean value) {
        return value
                ? new CborItem.Simple(CborItem.Simple.TRUE, new byte[] {(byte) 0xf5})
                : new CborItem.Simple(CborItem.Simple.FALSE, new byte[] {(byte) 0xf4});
    }

    public static CborItem.Array array(CborItem... items) {
        return array(List.of(items));
    }

    public static CborItem.Array array(List<CborItem> items) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(head(4, BigInteger.valueOf(items.size())));
        items.forEach(i -> out.writeBytes(i.encoded()));
        return new CborItem.Array(items, out.toByteArray());
    }

    public static CborItem.MapItem map(Map<CborItem, CborItem> entries) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(head(5, BigInteger.valueOf(entries.size())));
        entries.forEach((k, v) -> {
            out.writeBytes(k.encoded());
            out.writeBytes(v.encoded());
        });
        return new CborItem.MapItem(new LinkedHashMap<>(entries), out.toByteArray());
    }

    public static CborItem.Tag tag(long number, CborItem content) {
        return new CborItem.Tag(number, content, concat(head(6, BigInteger.valueOf(number)), content.encoded()));
    }

    /** {@code #6.24(bstr .cbor item)}: the item's encoding wrapped as an embedded CBOR byte string. */
    public static CborItem.Tag embedded(CborItem item) {
        return tag(24, bytes(item.encoded()));
    }

    private static byte[] head(int major, BigInteger argument) {
        int m = major << 5;
        long v = argument.longValue();
        if (argument.bitLength() > 64 || argument.signum() < 0) {
            throw new IllegalArgumentException("argument out of range");
        }
        if (argument.compareTo(BigInteger.valueOf(24)) < 0) {
            return new byte[] {(byte) (m | v)};
        }
        if (argument.bitLength() <= 8) {
            return new byte[] {(byte) (m | 24), (byte) v};
        }
        if (argument.bitLength() <= 16) {
            return new byte[] {(byte) (m | 25), (byte) (v >>> 8), (byte) v};
        }
        if (argument.bitLength() <= 32) {
            return new byte[] {(byte) (m | 26), (byte) (v >>> 24), (byte) (v >>> 16), (byte) (v >>> 8), (byte) v};
        }
        byte[] out = new byte[9];
        out[0] = (byte) (m | 27);
        for (int i = 0; i < 8; i++) {
            out[8 - i] = (byte) (v >>> (8 * i));
        }
        return out;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
