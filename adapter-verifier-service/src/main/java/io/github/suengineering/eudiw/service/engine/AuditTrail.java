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

import io.github.suengineering.eudiw.service.store.SessionStore;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.time.Instant;
import org.jboss.logging.Logger;

/**
 * Records what happened to sessions in three places: the {@code audit_event} table, one line in the {@code
 * eudiw.audit} log category, and the {@code eudiw_events_total} counter. None of them carry claims, tokens, request
 * handles or nonces. Counter tags are bounded: tenant, policy and client ids from configuration, the action, the
 * outcome and a reason code.
 */
@ApplicationScoped
public class AuditTrail {

    private static final Logger AUDIT = Logger.getLogger("eudiw.audit");

    @Inject
    SessionStore store;

    @Inject
    MeterRegistry registry;

    /**
     * Records one event.
     *
     * @param policyId the session's policy, or {@code null} when the event has none
     * @param code a reason code, or {@code null}
     */
    public void record(
            String tenantId,
            String sessionId,
            String clientId,
            String policyId,
            String action,
            String outcome,
            String code,
            String revision,
            Instant now) {
        store.audit(tenantId, sessionId, clientId, action, outcome, code, revision, now);
        announce(tenantId, sessionId, clientId, policyId, action, outcome, code, revision, now);
    }

    /** The log line and counter for an event whose row was already written, in the transaction it records. */
    public void announce(
            String tenantId,
            String sessionId,
            String clientId,
            String policyId,
            String action,
            String outcome,
            String code,
            String revision,
            Instant now) {
        AUDIT.infof(
                "action=%s outcome=%s code=%s tenant=%s client=%s policy=%s session=%s revision=%s at=%s",
                tag(action),
                tag(outcome),
                tag(code),
                tag(tenantId),
                tag(clientId),
                tag(policyId),
                tag(sessionId),
                tag(revision),
                now);
        Counter.builder("eudiw.events")
                .description("Session events by action, outcome and reason code")
                .tag("tenant", tenantId)
                .tag("policy", tag(policyId))
                .tag("client", tag(clientId))
                .tag("action", action)
                .tag("outcome", outcome)
                .tag("code", tag(code))
                .register(registry)
                .increment();
    }

    /**
     * A value for the audit line or a metric tag. Line breaks and other control characters are replaced, so a value
     * can never start a forged audit line. Configuration ids are already restricted when the file is loaded; this
     * holds whatever the source.
     */
    static String tag(String value) {
        return value == null
                ? "none"
                : value.replace('\r', '?').replace('\n', '?').replaceAll("\\p{Cntrl}", "?");
    }
}
