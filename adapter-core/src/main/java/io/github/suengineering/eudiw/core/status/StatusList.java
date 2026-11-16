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
package io.github.suengineering.eudiw.core.status;

import io.github.suengineering.eudiw.core.VerificationFailure;
import java.io.ByteArrayOutputStream;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/**
 * A decompressed Status List (Token Status List draft 14, section 4): statuses packed from the least significant
 * bit of each byte.
 */
public final class StatusList {

    /** Default bound on the decompressed size: 2^23 entries at 8 bits. */
    public static final int DEFAULT_MAX_BYTES = 8 * 1024 * 1024;

    private final int bits;
    private final byte[] bytes;

    private StatusList(int bits, byte[] bytes) {
        this.bits = bits;
        this.bytes = bytes;
    }

    /**
     * @param bits 1, 2, 4 or 8
     * @param compressed ZLIB (RFC 1950) compressed byte array
     * @param maxBytes upper bound on the decompressed size
     * @throws VerificationFailure {@code status_list_invalid}
     */
    public static StatusList decode(int bits, byte[] compressed, int maxBytes) {
        if (bits != 1 && bits != 2 && bits != 4 && bits != 8) {
            throw new VerificationFailure("status_list_invalid", "bits must be 1, 2, 4 or 8");
        }
        Inflater inflater = new Inflater(false); // ZLIB wrapper required
        try {
            inflater.setInput(compressed);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            while (!inflater.finished()) {
                int n = inflater.inflate(buffer);
                if (n == 0 && (inflater.needsInput() || inflater.needsDictionary())) {
                    throw new VerificationFailure("status_list_invalid", "truncated or invalid ZLIB data");
                }
                if (out.size() + n > maxBytes) {
                    throw new VerificationFailure("status_list_invalid", "status list exceeds size limit");
                }
                out.write(buffer, 0, n);
            }
            if (inflater.getRemaining() != 0) {
                throw new VerificationFailure("status_list_invalid", "trailing data after ZLIB stream");
            }
            return new StatusList(bits, out.toByteArray());
        } catch (DataFormatException e) {
            throw new VerificationFailure("status_list_invalid", "invalid ZLIB data", e);
        } finally {
            inflater.end();
        }
    }

    public int bits() {
        return bits;
    }

    /** Number of entries the list holds. */
    public long size() {
        return (long) bytes.length * 8 / bits;
    }

    /**
     * @throws VerificationFailure {@code status_index_out_of_range}
     */
    public int statusAt(long index) {
        if (index < 0 || index >= size()) {
            throw new VerificationFailure("status_index_out_of_range", "status index outside the list");
        }
        int perByte = 8 / bits;
        int value = bytes[(int) (index / perByte)] & 0xFF;
        int shift = (int) (index % perByte) * bits;
        return (value >>> shift) & ((1 << bits) - 1);
    }
}
