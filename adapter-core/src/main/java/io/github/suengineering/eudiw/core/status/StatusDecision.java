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

/**
 * The status of a credential.
 *
 * @param result the decision
 * @param value the raw Status Type value, or -1 when indeterminate
 * @param reason failure code when indeterminate, otherwise {@code null}
 */
public record StatusDecision(Result result, int value, String reason) {

    public enum Result {
        /** Status Type 0x00. */
        VALID,
        /** Status Type 0x01, revoked. */
        INVALID,
        /** Status Type 0x02. */
        SUSPENDED,
        /** Any other Status Type value; application specific. */
        OTHER,
        /** No statement can be made: the list could not be fetched, verified or indexed. */
        INDETERMINATE
    }

    static StatusDecision of(int value) {
        Result result =
                switch (value) {
                    case 0 -> Result.VALID;
                    case 1 -> Result.INVALID;
                    case 2 -> Result.SUSPENDED;
                    default -> Result.OTHER;
                };
        return new StatusDecision(result, value, null);
    }

    public static StatusDecision indeterminate(String reason) {
        return new StatusDecision(Result.INDETERMINATE, -1, reason);
    }
}
