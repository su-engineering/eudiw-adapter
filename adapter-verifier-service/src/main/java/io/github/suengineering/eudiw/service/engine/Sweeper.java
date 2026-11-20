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
import io.quarkus.scheduler.Scheduled;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

/** Expires sessions, deletes unretrieved results and old per-request keys. Safe to run on every node. */
@ApplicationScoped
public class Sweeper {

    @Inject
    SessionStore store;

    @Inject
    AdapterRuntime runtime;

    @Inject
    io.github.suengineering.eudiw.service.store.RateLimitStore rateLimits;

    @Inject
    io.micrometer.core.instrument.MeterRegistry registry;

    @Inject
    io.github.suengineering.eudiw.service.store.OidcStore oidc;

    @Scheduled(every = "{eudiw.sweep-interval:30s}", concurrentExecution = Scheduled.ConcurrentExecution.SKIP)
    void sweep() {
        java.time.Instant now = runtime.clock().instant();
        int expired = store.sweep(now, runtime.webhookClients());
        rateLimits.sweep(now.minusSeconds(120));
        oidc.sweep(now);
        if (expired > 0) {
            registry.counter("eudiw.sessions.expired").increment(expired);
        }
    }
}
