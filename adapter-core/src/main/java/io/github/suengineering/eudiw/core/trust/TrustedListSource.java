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
package io.github.suengineering.eudiw.core.trust;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * One configured trusted list and what to take from it.
 *
 * @param identifier the list's identifier, used for DCQL {@code etsi_tl} matching; normally its public URL, also
 *     when the operator serves a local mirror
 * @param location {@code https:} URL, or {@code file:} for a list the operator mirrors locally
 * @param format the binding
 * @param signers certificates allowed to sign the list (pinned by the operator, for example as published in the
 *     Official Journal for the EU list of trusted lists)
 * @param followPointers for a list of trusted lists: also load the XML trusted lists it points to, each verified
 *     against the signer certificates its pointer publishes
 * @param territories when following pointers, only these scheme territories; empty means all
 * @param issuanceServiceTypes service type URIs whose certificates may anchor credential issuers
 * @param statusServiceTypes additional service type URIs whose certificates may anchor status list tokens
 *     (issuance types always may)
 * @param acceptedStatuses service status URIs that count as approved; a service without a status counts as
 *     approved, as ETSI TS 119 602 clause 6.6.0 defines
 */
public record TrustedListSource(
        String identifier,
        URI location,
        TrustedList.Format format,
        List<X509Certificate> signers,
        boolean followPointers,
        Set<String> territories,
        Set<String> issuanceServiceTypes,
        Set<String> statusServiceTypes,
        Set<String> acceptedStatuses) {

    /** Approved statuses of ETSI TS 119 612 clause 5.5.4 and of the TS 119 602 public sector EAA profile. */
    public static final Set<String> DEFAULT_ACCEPTED_STATUSES = Set.of(
            "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted",
            "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel",
            "http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/notified");

    public TrustedListSource {
        Objects.requireNonNull(identifier, "identifier");
        Objects.requireNonNull(location, "location");
        Objects.requireNonNull(format, "format");
        signers = List.copyOf(signers);
        territories = Set.copyOf(territories);
        issuanceServiceTypes = Set.copyOf(issuanceServiceTypes);
        statusServiceTypes = Set.copyOf(statusServiceTypes);
        acceptedStatuses = Set.copyOf(acceptedStatuses);
        String scheme = location.getScheme();
        if (!"https".equalsIgnoreCase(scheme) && !"http".equalsIgnoreCase(scheme) && !"file".equalsIgnoreCase(scheme)) {
            throw new IllegalArgumentException("trusted list location must be an https or file URI");
        }
        if (signers.isEmpty()) {
            throw new IllegalArgumentException("at least one signer certificate is required");
        }
        if (issuanceServiceTypes.isEmpty()) {
            throw new IllegalArgumentException("at least one issuance service type is required");
        }
        if (followPointers && format != TrustedList.Format.TSL_XML) {
            throw new IllegalArgumentException("only XML lists of trusted lists can be followed");
        }
    }
}
