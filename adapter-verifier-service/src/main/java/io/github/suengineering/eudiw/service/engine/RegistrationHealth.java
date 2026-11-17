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
import io.smallrye.health.api.Wellness;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.eclipse.microprofile.health.HealthCheck;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.eclipse.microprofile.health.HealthCheckResponseBuilder;

/**
 * Registration certificates nearing or past their expiry, under {@code /health/well} so that an expiring certificate
 * alerts without taking the node out of service. An expired certificate is no longer sent: requests carry only the
 * registrar dataset until the certificate file is replaced.
 */
@Wellness
@ApplicationScoped
public class RegistrationHealth implements HealthCheck {

    /** Report a certificate this long before it expires. */
    static final Duration WARNING = Duration.ofDays(30);

    @Inject
    AdapterRuntime runtime;

    @Override
    public HealthCheckResponse call() {
        Instant now = Clock.systemUTC().instant();
        List<String> expired = new ArrayList<>();
        List<String> expiring = new ArrayList<>();
        for (AdapterConfig.Tenant tenant : runtime.config().tenants().values()) {
            for (AdapterConfig.Policy policy : tenant.policies().values()) {
                policy.registration()
                        .flatMap(r -> r.certificate())
                        .flatMap(c -> c.expiresAt())
                        .ifPresent(exp -> {
                            String name = tenant.id() + "/" + policy.id();
                            if (!now.isBefore(exp)) {
                                expired.add(name);
                            } else if (!now.plus(WARNING).isBefore(exp)) {
                                expiring.add(name + "@" + exp);
                            }
                        });
            }
        }
        HealthCheckResponseBuilder builder =
                HealthCheckResponse.named("registration-certificates").status(expired.isEmpty() && expiring.isEmpty());
        builder.withData("expired", String.join(",", expired));
        builder.withData("expiring_within_30_days", String.join(",", expiring));
        return builder.build();
    }
}
