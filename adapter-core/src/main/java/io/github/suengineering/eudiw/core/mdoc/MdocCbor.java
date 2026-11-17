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
package io.github.suengineering.eudiw.core.mdoc;

import io.github.suengineering.eudiw.core.VerificationFailure;
import io.github.suengineering.eudiw.core.cbor.CborDecoder;
import io.github.suengineering.eudiw.core.cbor.CborItem;

/** Typed access to mdoc CBOR structures; any mismatch is {@code malformed_credential}. */
final class MdocCbor {

    /** Tag for an embedded CBOR data item in a byte string (RFC 8949 section 3.4.5.1). */
    static final long EMBEDDED = 24;

    private MdocCbor() {}

    static CborItem.MapItem map(CborItem item, String what) {
        if (item instanceof CborItem.MapItem m) {
            return m;
        }
        throw malformed(what + " is not a map");
    }

    static CborItem.Array array(CborItem item, String what) {
        if (item instanceof CborItem.Array a) {
            return a;
        }
        throw malformed(what + " is not an array");
    }

    static String text(CborItem item, String what) {
        if (item instanceof CborItem.Text t) {
            return t.value();
        }
        throw malformed(what + " is not a text string");
    }

    static String text(CborItem.MapItem map, String key) {
        return text(field(map, key), key);
    }

    static CborItem field(CborItem.MapItem map, String key) {
        return map.get(key).orElseThrow(() -> malformed("missing " + key));
    }

    static long unsigned(CborItem item, String what) {
        if (item instanceof CborItem.Int i && i.value().signum() >= 0) {
            return i.asLong().orElseThrow(() -> malformed(what + " is too large"));
        }
        throw malformed(what + " is not an unsigned integer");
    }

    /** The data item inside {@code #6.24(bstr .cbor item)}. */
    static CborItem embedded(CborItem item, String what) {
        if (item instanceof CborItem.Tag t && t.number() == EMBEDDED && t.content() instanceof CborItem.Bytes b) {
            return CborDecoder.decode(b.value());
        }
        throw malformed(what + " is not an embedded CBOR byte string");
    }

    static VerificationFailure malformed(String message) {
        return new VerificationFailure("malformed_credential", message);
    }
}
