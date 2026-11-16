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
 * Not ready until the first trusted list refresh has run, so a node does not take traffic before its lists are
 * loaded. After that it stays ready even when a policy has no current list: that policy's verifications fail closed
 * and the policy is named here and in the log, while other tenants keep working.
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
                .status(runtime.trustedListsAttempted())
                .withData("policies_without_current_lists", String.join(",", missing))
                .build();
    }
}
