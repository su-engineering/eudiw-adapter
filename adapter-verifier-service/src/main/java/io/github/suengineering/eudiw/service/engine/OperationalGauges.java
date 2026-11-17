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

import io.github.suengineering.eudiw.service.config.AdapterConfig;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.MultiGauge;
import io.micrometer.core.instrument.Tags;
import io.quarkus.runtime.Startup;
import io.quarkus.scheduler.Scheduled;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Gauges for state that alerts should watch: registration certificate expiry, policies without a current trusted
 * list, and the active configuration revision. Refreshed every minute, so a configuration reload is picked up.
 */
@Startup
@ApplicationScoped
public class OperationalGauges {

    @Inject
    AdapterRuntime runtime;

    @Inject
    MeterRegistry registry;

    private MultiGauge registrationExpiry;
    private MultiGauge withoutLists;
    private MultiGauge revision;

    @PostConstruct
    void register() {
        registrationExpiry = MultiGauge.builder("eudiw.registration.certificate.expiry")
                .description("Seconds until a policy's registration certificate expires (negative once expired)")
                .baseUnit("seconds")
                .register(registry);
        withoutLists = MultiGauge.builder("eudiw.trusted.lists.current")
                .description("1 when a policy that uses trusted lists has a current list, 0 when it fails closed")
                .register(registry);
        revision = MultiGauge.builder("eudiw.config.info")
                .description("The active configuration revision")
                .register(registry);
        refresh();
    }

    @Scheduled(every = "60s", concurrentExecution = Scheduled.ConcurrentExecution.SKIP)
    void refresh() {
        Instant now = runtime.clock().instant();
        AdapterConfig config = runtime.config();
        List<MultiGauge.Row<?>> expiry = new ArrayList<>();
        for (AdapterConfig.Tenant tenant : config.tenants().values()) {
            for (AdapterConfig.Policy policy : tenant.policies().values()) {
                policy.registration()
                        .flatMap(r -> r.certificate())
                        .flatMap(c -> c.expiresAt())
                        .ifPresent(exp -> expiry.add(MultiGauge.Row.of(
                                Tags.of("tenant", tenant.id(), "policy", policy.id()),
                                exp.getEpochSecond() - now.getEpochSecond())));
            }
        }
        registrationExpiry.register(expiry, true);
        List<String> missing = runtime.policiesWithoutCurrentTrustedLists();
        List<MultiGauge.Row<?>> lists = new ArrayList<>();
        for (String key : runtime.policiesUsingTrustedLists()) {
            String[] parts = key.split("/", 2);
            lists.add(
                    MultiGauge.Row.of(Tags.of("tenant", parts[0], "policy", parts[1]), missing.contains(key) ? 0 : 1));
        }
        withoutLists.register(lists, true);
        revision.register(List.of(MultiGauge.Row.of(Tags.of("revision", config.revision()), 1)), true);
    }
}
