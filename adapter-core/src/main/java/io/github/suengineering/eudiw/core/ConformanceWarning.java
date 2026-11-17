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
package io.github.suengineering.eudiw.core;

import java.util.Objects;

/**
 * A credential that verified but departs from a profile the verifier tolerates, such as a certificate rule that is the
 * issuer's duty. It does not reject the credential; the service records it in the audit log.
 *
 * @param code a stable code, for example {@code mdoc_device_key_curve_not_in_table_22}
 * @param detail a short explanation without personal data
 */
public record ConformanceWarning(String code, String detail) {

    /** The device key is on a curve that ISO/IEC 18013-5:2021 Table 22 does not list for device keys. */
    public static final String DEVICE_KEY_CURVE = "mdoc_device_key_curve_not_in_table_22";

    /** The document signer certificate is valid for longer than the Annex B profile allows. */
    public static final String SIGNER_VALIDITY = "mdoc_signer_validity_over_457_days";

    /** The document signer certificate has no CRL distribution point, which the Annex B profile requires. */
    public static final String SIGNER_WITHOUT_CRL_DP = "mdoc_signer_without_crl_distribution_point";

    /** The x5chain includes a root certificate; it was ignored and never trusted. */
    public static final String X5CHAIN_INCLUDES_ROOT = "mdoc_x5chain_includes_root";

    public ConformanceWarning {
        Objects.requireNonNull(code, "code");
        Objects.requireNonNull(detail, "detail");
    }
}
