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
package io.github.suengineering.eudiw.service;

import io.github.suengineering.eudiw.service.config.ConfigLoader;
import java.nio.file.Path;

/** Prints the revision of a configuration file, so a test can compare it across separate JVMs. */
public final class RevisionProbe {

    private RevisionProbe() {}

    public static void main(String[] args) {
        System.out.println(
                "REVISION=" + ConfigLoader.load(Path.of(args[0]), false).revision());
    }
}
