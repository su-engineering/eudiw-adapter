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

import io.github.suengineering.eudiw.core.VerificationFailure;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * A strict CBOR decoder (RFC 8949) for wallet input.
 *
 * <p>It refuses indefinite lengths, duplicate map keys, invalid UTF-8, reserved additional information values,
 * trailing bytes, and input beyond fixed size, depth and item limits. Non-preferred integer and length encodings
 * are accepted: they cannot change what is signed, because every item keeps its exact encoded bytes.
 */
public final class CborDecoder {

    /** Largest input accepted. */
    public static final int MAX_BYTES = 1024 * 1024;
    /** Deepest nesting of arrays, maps and tags. */
    public static final int MAX_DEPTH = 32;
    /** Most data items in one input. */
    public static final int MAX_ITEMS = 100_000;

    private final byte[] in;
    private int pos;
    private int items;

    private CborDecoder(byte[] in) {
        this.in = in;
    }

    /**
     * Decodes exactly one data item.
     *
     * @throws VerificationFailure {@code malformed_credential} when the input is not acceptable CBOR
     */
    public static CborItem decode(byte[] input) {
        if (input == null || input.length == 0) {
            throw fail("empty CBOR input");
        }
        if (input.length > MAX_BYTES) {
            throw fail("CBOR input too large");
        }
        CborDecoder decoder = new CborDecoder(input);
        CborItem item = decoder.item(0);
        if (decoder.pos != input.length) {
            throw fail("trailing bytes after CBOR item");
        }
        return item;
    }

    private CborItem item(int depth) {
        if (depth > MAX_DEPTH) {
            throw fail("CBOR nesting too deep");
        }
        if (++items > MAX_ITEMS) {
            throw fail("too many CBOR items");
        }
        int start = pos;
        int initial = u8();
        int major = initial >>> 5;
        int info = initial & 0x1f;
        if (info == 31) {
            throw fail(major == 7 ? "unexpected break" : "indefinite length not allowed");
        }
        if (info >= 28) {
            throw fail("reserved additional information");
        }
        switch (major) {
            case 0 -> {
                BigInteger v = argument(info);
                return new CborItem.Int(v, slice(start));
            }
            case 1 -> {
                BigInteger v = argument(info);
                return new CborItem.Int(BigInteger.valueOf(-1).subtract(v), slice(start));
            }
            case 2 -> {
                byte[] content = take(length(info));
                return new CborItem.Bytes(content, slice(start));
            }
            case 3 -> {
                byte[] content = take(length(info));
                return new CborItem.Text(utf8(content), slice(start));
            }
            case 4 -> {
                int n = length(info);
                List<CborItem> list = new ArrayList<>(Math.min(n, 1024));
                for (int i = 0; i < n; i++) {
                    list.add(item(depth + 1));
                }
                return new CborItem.Array(list, slice(start));
            }
            case 5 -> {
                int n = length(info);
                Map<CborItem, CborItem> map = new LinkedHashMap<>();
                Set<String> keys = new HashSet<>();
                for (int i = 0; i < n; i++) {
                    CborItem key = item(depth + 1);
                    if (!keys.add(keyIdentity(key))) {
                        throw fail("duplicate CBOR map key");
                    }
                    map.put(key, item(depth + 1));
                }
                return new CborItem.MapItem(map, slice(start));
            }
            case 6 -> {
                BigInteger number = argument(info);
                if (number.bitLength() >= 64) {
                    throw fail("CBOR tag number too large");
                }
                CborItem content = item(depth + 1);
                return new CborItem.Tag(number.longValue(), content, slice(start));
            }
            default -> {
                return simple(info, start);
            }
        }
    }

    private CborItem simple(int info, int start) {
        if (info < 20) {
            throw fail("unassigned simple value");
        }
        return switch (info) {
            case 20, 21, 22, 23 -> new CborItem.Simple(info, slice(start));
            case 24 -> throw fail("unassigned simple value");
            case 25 -> new CborItem.Float(half(u16()), slice(start));
            case 26 -> new CborItem.Float(java.lang.Float.intBitsToFloat((int) u32()), slice(start));
            case 27 -> new CborItem.Float(Double.longBitsToDouble(u64().longValue()), slice(start));
            default -> throw fail("reserved additional information");
        };
    }

    /** Duplicate detection by value, so a non-preferred encoding cannot smuggle in a second equal key. */
    private static String keyIdentity(CborItem key) {
        return switch (key) {
            case CborItem.Int i -> "i:" + i.value();
            case CborItem.Text t -> "t:" + t.value();
            case CborItem.Bytes b -> "b:" + java.util.HexFormat.of().formatHex(b.value());
            default -> "e:" + java.util.HexFormat.of().formatHex(key.encoded());
        };
    }

    private BigInteger argument(int info) {
        if (info < 24) {
            return BigInteger.valueOf(info);
        }
        return switch (info) {
            case 24 -> BigInteger.valueOf(u8());
            case 25 -> BigInteger.valueOf(u16());
            case 26 -> BigInteger.valueOf(u32());
            default -> u64();
        };
    }

    private int length(int info) {
        BigInteger n = argument(info);
        if (n.compareTo(BigInteger.valueOf(in.length - pos)) > 0) {
            throw fail("CBOR length exceeds input");
        }
        return n.intValueExact();
    }

    private byte[] take(int n) {
        if (n > in.length - pos) {
            throw fail("truncated CBOR input");
        }
        byte[] out = Arrays.copyOfRange(in, pos, pos + n);
        pos += n;
        return out;
    }

    private byte[] slice(int start) {
        return Arrays.copyOfRange(in, start, pos);
    }

    private int u8() {
        if (pos >= in.length) {
            throw fail("truncated CBOR input");
        }
        return in[pos++] & 0xff;
    }

    private int u16() {
        return (u8() << 8) | u8();
    }

    private long u32() {
        return ((long) u16() << 16) | u16();
    }

    private BigInteger u64() {
        return BigInteger.valueOf(u32()).shiftLeft(32).or(BigInteger.valueOf(u32()));
    }

    private static double half(int bits) {
        int exponent = (bits >> 10) & 0x1f;
        int mantissa = bits & 0x3ff;
        double value;
        if (exponent == 0) {
            value = mantissa * Math.pow(2, -24);
        } else if (exponent == 31) {
            value = mantissa == 0 ? Double.POSITIVE_INFINITY : Double.NaN;
        } else {
            value = (mantissa + 1024) * Math.pow(2, exponent - 25);
        }
        return (bits & 0x8000) != 0 ? -value : value;
    }

    private static String utf8(byte[] bytes) {
        try {
            return StandardCharsets.UTF_8
                    .newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes))
                    .toString();
        } catch (CharacterCodingException e) {
            throw fail("invalid UTF-8 in CBOR text string");
        }
    }

    private static VerificationFailure fail(String message) {
        return new VerificationFailure("malformed_credential", message);
    }
}
