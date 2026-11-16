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
package io.github.suengineering.eudiw.core.net;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class EgressPolicyTest {

    @ParameterizedTest
    @ValueSource(
            strings = {
                "https://127.0.0.1/x",
                "https://localhost/x",
                "https://10.0.0.5/x",
                "https://172.16.1.1/x",
                "https://192.168.1.1/x",
                "https://169.254.169.254/latest/meta-data",
                "https://100.64.0.1/x",
                "https://0.0.0.0/x",
                "https://[::1]/x",
                "https://[fd00::1]/x",
                "https://[fe80::1]/x",
                "https://[::ffff:127.0.0.1]/x",
                "https://224.0.0.1/x",
                "http://8.8.8.8/x",
                "ftp://8.8.8.8/x",
                "https://user:pass@8.8.8.8/x"
            })
    void strictPolicyRejects(String url) {
        assertThatThrownBy(() -> EgressPolicy.STRICT.check(URI.create(url)))
                .isInstanceOf(HttpFetcher.FetchException.class);
    }

    @Test
    void strictPolicyAcceptsPublicHttps() {
        assertThatCode(() -> EgressPolicy.STRICT.check(URI.create("https://8.8.8.8/list")))
                .doesNotThrowAnyException();
    }

    @Test
    void allowListAndDevelopmentRelaxations() {
        EgressPolicy allowList = new EgressPolicy(false, false, Set.of("8.8.8.8"));
        assertThatCode(() -> allowList.check(URI.create("https://8.8.8.8/x"))).doesNotThrowAnyException();
        assertThatThrownBy(() -> allowList.check(URI.create("https://1.1.1.1/x")))
                .isInstanceOf(HttpFetcher.FetchException.class);

        EgressPolicy development = new EgressPolicy(true, true, Set.of());
        assertThatCode(() -> development.check(URI.create("http://127.0.0.1:8080/x")))
                .doesNotThrowAnyException();
    }
}
