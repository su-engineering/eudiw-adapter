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
package io.github.suengineering.eudiw.service.engine;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class WalletSourceKeyTest {

    @Test
    void addressesCountAloneOrByTheirSlash64() {
        assertThat(VerificationEngine.sourceKey("203.0.113.7")).isEqualTo("203.0.113.7");
        assertThat(VerificationEngine.sourceKey("2001:db8:1:2:aaaa::1")).isEqualTo("2001:db8:1:2:0:0:0:0/64");
        assertThat(VerificationEngine.sourceKey("2001:db8:1:2:bbbb::9")).isEqualTo("2001:db8:1:2:0:0:0:0/64");
    }

    @Test
    void anythingElseSharesOneBucket() {
        assertThat(VerificationEngine.sourceKey(null)).isEqualTo("unparsed");
        assertThat(VerificationEngine.sourceKey("unknown")).isEqualTo("unparsed");
        assertThat(VerificationEngine.sourceKey("_obfuscated")).isEqualTo("unparsed");
        assertThat(VerificationEngine.sourceKey("wallet.example")).isEqualTo("unparsed");
        assertThat(VerificationEngine.sourceKey("::::::::")).isEqualTo("unparsed");
    }
}
