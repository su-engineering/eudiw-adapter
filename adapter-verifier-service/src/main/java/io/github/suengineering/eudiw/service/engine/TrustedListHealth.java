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

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.List;
import org.eclipse.microprofile.health.HealthCheck;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.eclipse.microprofile.health.Readiness;

/**
 * Not ready while a policy that relies on trusted lists has no current list: its verifications would all fail.
 * Policies that also have configured anchors are reported the same way, since their list-based trust is missing.
 */
@Readiness
@ApplicationScoped
public class TrustedListHealth implements HealthCheck {

    @Inject
    AdapterRuntime runtime;

    @Override
    public HealthCheckResponse call() {
        List<String> missing = runtime.policiesWithoutCurrentTrustedLists();
        return HealthCheckResponse.named("trusted-lists")
                .status(missing.isEmpty())
                .withData("policies_without_current_lists", String.join(",", missing))
                .build();
    }
}
