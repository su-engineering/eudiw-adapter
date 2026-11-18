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
package io.github.suengineering.eudiw.service.api;

import io.github.suengineering.eudiw.service.store.SessionStore.SessionRow;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/** The status view of a session that polling and the event stream both return. It never carries claims. */
final class SessionView {

    private SessionView() {}

    /** Every status but {@code pending} is final for the stream: nothing more happens in front of the wallet. */
    static boolean isFinal(Map<String, Object> view) {
        return !"pending".equals(view.get("status"));
    }

    static Map<String, Object> of(SessionRow session, Instant now) {
        String status = session.status();
        if (status.equals("pending") && !now.isBefore(session.expiresAt())) {
            status = "expired";
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("id", session.id());
        out.put("status", status);
        out.put("policy_id", session.policyId());
        out.put("mode", session.mode());
        if (session.clientReference() != null) {
            out.put("client_reference", session.clientReference());
        }
        out.put("created_at", session.createdAt().toString());
        out.put("expires_at", session.expiresAt().toString());
        if (session.completedAt() != null) {
            out.put("completed_at", session.completedAt().toString());
        }
        if (status.equals("rejected") && session.failureCode() != null) {
            out.put("reason", session.failureCode());
        }
        out.put("result_available", status.equals("verified") && session.hasResult());
        return out;
    }
}
