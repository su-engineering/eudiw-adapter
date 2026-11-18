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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.suengineering.eudiw.core.VerificationFailure;
import io.github.suengineering.eudiw.core.json.Json;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.zip.Deflater;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Test vectors from Token Status List draft 14, section 4 and Appendix C. */
class StatusListTest {

    @Test
    void section42Examples() {
        StatusList oneBit = StatusList.decode(1, b64("eNrbuRgAAhcBXQ"), StatusList.DEFAULT_MAX_BYTES);
        int[] expected1 = {1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1};
        for (int i = 0; i < expected1.length; i++) {
            assertThat(oneBit.statusAt(i)).as("index %d", i).isEqualTo(expected1[i]);
        }

        StatusList twoBit = StatusList.decode(2, b64("eNo76fITAAPfAgc"), StatusList.DEFAULT_MAX_BYTES);
        int[] expected2 = {1, 2, 0, 3, 0, 1, 0, 1, 1, 2, 3, 3};
        for (int i = 0; i < expected2.length; i++) {
            assertThat(twoBit.statusAt(i)).as("index %d", i).isEqualTo(expected2[i]);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"1", "2", "3", "4"})
    @SuppressWarnings("unchecked")
    void appendixCVectors(String section) {
        Map<String, Object> vector = (Map<String, Object>) vectors().get(section);
        int bits = ((Number) vector.get("bits")).intValue();
        StatusList list = StatusList.decode(bits, b64((String) vector.get("lst")), StatusList.DEFAULT_MAX_BYTES);
        Map<String, Object> set = (Map<String, Object>) vector.get("set");

        assertThat(list.size()).isEqualTo(1L << 20);
        for (Map.Entry<String, Object> e : set.entrySet()) {
            assertThat(list.statusAt(Long.parseLong(e.getKey())))
                    .as("index %s", e.getKey())
                    .isEqualTo(((Number) e.getValue()).intValue());
        }
        long unset = 0;
        for (long i = 1; i < list.size(); i += 4099) {
            if (!set.containsKey(Long.toString(i))) {
                assertThat(list.statusAt(i)).isZero();
                unset++;
            }
        }
        assertThat(unset).isPositive();
    }

    @Test
    void outOfRangeIndexIsRejected() {
        StatusList list = StatusList.decode(1, b64("eNrbuRgAAhcBXQ"), StatusList.DEFAULT_MAX_BYTES);

        assertFailure(() -> list.statusAt(16), "status_index_out_of_range");
        assertFailure(() -> list.statusAt(-1), "status_index_out_of_range");
    }

    @Test
    void decompressionIsBounded() {
        byte[] bomb = zlib(new byte[16 * 1024 * 1024]);
        assertThat(bomb.length).isLessThan(64 * 1024);

        assertFailure(() -> StatusList.decode(8, bomb, StatusList.DEFAULT_MAX_BYTES), "status_list_invalid");
    }

    @Test
    void invalidInputIsRejected() {
        assertFailure(() -> StatusList.decode(3, b64("eNrbuRgAAhcBXQ"), 1024), "status_list_invalid");
        assertFailure(() -> StatusList.decode(1, new byte[] {1, 2, 3}, 1024), "status_list_invalid");
        byte[] raw = rawDeflate(new byte[] {1}); // DEFLATE without the required ZLIB wrapper
        assertFailure(() -> StatusList.decode(1, raw, 1024), "status_list_invalid");
        byte[] truncated = java.util.Arrays.copyOf(b64("eNrbuRgAAhcBXQ"), 5);
        assertFailure(() -> StatusList.decode(1, truncated, 1024), "status_list_invalid");
    }

    private static byte[] zlib(byte[] input) {
        Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION);
        deflater.setInput(input);
        deflater.finish();
        byte[] buffer = new byte[input.length + 64];
        int n = deflater.deflate(buffer);
        deflater.end();
        return java.util.Arrays.copyOf(buffer, n);
    }

    private static byte[] rawDeflate(byte[] input) {
        Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION, true);
        deflater.setInput(input);
        deflater.finish();
        byte[] buffer = new byte[64];
        int n = deflater.deflate(buffer);
        deflater.end();
        return java.util.Arrays.copyOf(buffer, n);
    }

    static byte[] b64(String s) {
        return Base64.getUrlDecoder().decode(s);
    }

    private static Map<String, Object> vectors() {
        try (InputStream in = StatusListTest.class.getResourceAsStream("/status-list/appendix-c.json")) {
            return Json.parseObject(new String(in.readAllBytes(), StandardCharsets.UTF_8), "test");
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static void assertFailure(org.assertj.core.api.ThrowableAssert.ThrowingCallable call, String code) {
        assertThatThrownBy(call)
                .isInstanceOfSatisfying(
                        VerificationFailure.class, f -> assertThat(f.code()).isEqualTo(code));
    }
}
