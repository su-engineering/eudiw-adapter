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

class AuditTrailTest {

    @Test
    void aValueCannotStartAnotherAuditLine() {
        assertThat(AuditTrail.tag("portal-a\naction=result_retrieved outcome=ok"))
                .isEqualTo("portal-a?action=result_retrieved outcome=ok");
        assertThat(AuditTrail.tag("a\r\nb\u0000c\u001bd")).isEqualTo("a??b?c?d");
        assertThat(AuditTrail.tag("portal-a")).isEqualTo("portal-a");
        assertThat(AuditTrail.tag(null)).isEqualTo("none");
    }
}
