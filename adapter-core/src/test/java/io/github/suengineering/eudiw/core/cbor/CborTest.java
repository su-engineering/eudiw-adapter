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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.authlete.cbor.CBORDecoder;
import io.github.suengineering.eudiw.core.VerificationFailure;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

class CborTest {

    private static final HexFormat HEX = HexFormat.of();

    /** RFC 8949 Appendix A: preferred encodings of integers. */
    @ParameterizedTest
    @CsvSource({
        "0,00",
        "1,01",
        "10,0a",
        "23,17",
        "24,1818",
        "25,1819",
        "100,1864",
        "1000,1903e8",
        "1000000,1a000f4240",
        "1000000000000,1b000000e8d4a51000",
        "-1,20",
        "-10,29",
        "-100,3863",
        "-1000,3903e7"
    })
    void integersUseThePreferredEncoding(long value, String hex) {
        assertThat(HEX.formatHex(CborEncoder.integer(value).encoded())).isEqualTo(hex);
        CborItem decoded = CborDecoder.decode(HEX.parseHex(hex));
        assertThat(((CborItem.Int) decoded).value()).isEqualTo(BigInteger.valueOf(value));
    }

    /** RFC 8949 Appendix A: strings, arrays, maps and tags. */
    @Test
    void structuresMatchTheRfcExamples() {
        assertThat(HEX.formatHex(CborEncoder.text("a").encoded())).isEqualTo("6161");
        assertThat(HEX.formatHex(CborEncoder.text("ü").encoded())).isEqualTo("62c3bc");
        assertThat(HEX.formatHex(CborEncoder.bytes(HEX.parseHex("01020304")).encoded()))
                .isEqualTo("4401020304");
        CborItem nested = CborEncoder.array(
                CborEncoder.integer(1),
                CborEncoder.array(CborEncoder.integer(2), CborEncoder.integer(3)),
                CborEncoder.array(CborEncoder.integer(4), CborEncoder.integer(5)));
        assertThat(HEX.formatHex(nested.encoded())).isEqualTo("8301820203820405");
        Map<CborItem, CborItem> map = new LinkedHashMap<>();
        map.put(CborEncoder.integer(1), CborEncoder.integer(2));
        map.put(CborEncoder.integer(3), CborEncoder.integer(4));
        assertThat(HEX.formatHex(CborEncoder.map(map).encoded())).isEqualTo("a201020304");
        assertThat(HEX.formatHex(
                        CborEncoder.tag(1, CborEncoder.integer(1363896240)).encoded()))
                .isEqualTo("c11a514b67b0");
        assertThat(HEX.formatHex(CborEncoder.nil().encoded())).isEqualTo("f6");
        // A long string needs a two-byte length.
        assertThat(HEX.formatHex(CborEncoder.text("x".repeat(24)).encoded())).startsWith("7818");
    }

    @Test
    void decodedItemsKeepTheirExactBytes() {
        // A non-preferred length (0x58 0x01 for one byte) is accepted, and the bytes are kept as received.
        byte[] tagged = HEX.parseHex("d818580141");
        CborItem item = CborDecoder.decode(tagged);
        assertThat(item.encoded()).isEqualTo(tagged);
        assertThat(((CborItem.Tag) item).content().encoded()).isEqualTo(HEX.parseHex("580141"));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "", // empty
                "9f01ff", // indefinite array
                "5f4101ff", // indefinite byte string
                "a20101" + "0102", // duplicate map key 1
                "a201011801" + "02", // duplicate key 1, second in a non-preferred encoding
                "a2616101616102", // duplicate text key "a"
                "0101", // trailing byte
                "62c328", // invalid UTF-8
                "1c", // reserved additional information
                "ff", // break outside an indefinite item
                "f8", // truncated simple value
                "5a7fffffff00", // length beyond the input
                "f0" // unassigned simple value
            })
    void malformedInputIsRejected(String hex) {
        assertThatThrownBy(() -> CborDecoder.decode(HEX.parseHex(hex)))
                .isInstanceOfSatisfying(
                        VerificationFailure.class, f -> assertThat(f.code()).isEqualTo("malformed_credential"));
    }

    @Test
    void nestingIsBounded() {
        byte[] deep = new byte[CborDecoder.MAX_DEPTH + 2];
        java.util.Arrays.fill(deep, (byte) 0x81);
        deep[deep.length - 1] = 0x00;
        assertThatThrownBy(() -> CborDecoder.decode(deep)).hasMessageContaining("too deep");
    }

    /** Differential: Authlete's independent decoder re-encodes each fixture to the same bytes we keep. */
    @Test
    void fixturesDecodeLikeAnIndependentImplementation() throws Exception {
        for (String name : new String[] {"pid", "mdl", "mdl-noeku"}) {
            byte[] bytes = fixture(name);
            CborItem ours = CborDecoder.decode(bytes);
            byte[] theirs = new CBORDecoder(bytes).next().encode();
            assertThat(ours.encoded()).isEqualTo(theirs).isEqualTo(bytes);
        }
    }

    /** Random mutations of real input never escape as anything but a clean rejection. */
    @Test
    void mutatedInputFailsCleanly() throws Exception {
        byte[] original = fixture("pid");
        Random random = new Random(18013);
        for (int i = 0; i < 3000; i++) {
            byte[] mutated = original.clone();
            int flips = 1 + random.nextInt(4);
            for (int f = 0; f < flips; f++) {
                mutated[random.nextInt(mutated.length)] = (byte) random.nextInt(256);
            }
            try {
                CborDecoder.decode(mutated);
            } catch (VerificationFailure expected) {
                assertThat(expected.code()).isEqualTo("malformed_credential");
            }
        }
    }

    static byte[] fixture(String name) throws Exception {
        String b64 = Files.readString(Path.of("src/test/resources/mdoc/eudi-dev-" + name + ".issuer-signed.b64"))
                .strip();
        return Base64.getUrlDecoder().decode(b64);
    }
}
