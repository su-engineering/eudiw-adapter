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

import io.quarkus.scheduler.Scheduled;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

/** Checks the configuration directory for changes and reloads it (every 30 seconds by default; "off" disables). */
@ApplicationScoped
public class ConfigReloader {

    @Inject
    AdapterRuntime runtime;

    @Scheduled(every = "{eudiw.config.reload-interval}", concurrentExecution = Scheduled.ConcurrentExecution.SKIP)
    void check() {
        runtime.reloadIfChanged();
    }
}
