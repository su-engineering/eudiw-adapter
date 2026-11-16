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

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * The parts of a signed and verified trusted list that matter for trust decisions: an ETSI TS 119 612 trusted
 * list (XML) or an ETSI TS 119 602 list of trusted entities (JSON). Both share one logical model (TS 119 602
 * Annex A.2.2 maps the fields).
 *
 * @param location where the list was obtained; also its identifier for DCQL {@code etsi_tl}
 * @param format the binding
 * @param type the TSL or LoTE type URI, if present
 * @param territory the scheme territory, if present
 * @param sequenceNumber the list sequence number
 * @param issued the list issue date and time
 * @param nextUpdate the latest date by which an update is issued; empty for a closed list
 * @param services every listed service of every listed entity
 * @param pointers pointers to other lists
 */
public record TrustedList(
        String location,
        Format format,
        Optional<String> type,
        Optional<String> territory,
        long sequenceNumber,
        Instant issued,
        Optional<Instant> nextUpdate,
        List<Service> services,
        List<Pointer> pointers) {

    /** ETSI TS 119 612 type of the EU list of trusted lists. */
    public static final String TSL_TYPE_EU_LOTL = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists";

    /** Media type of an XML trusted list (ETSI TS 119 612 clause 6.2.1.1). */
    public static final String MIME_TSL_XML = "application/vnd.etsi.tsl+xml";

    public enum Format {
        /** ETSI TS 119 612 XML trusted list with an enveloped XAdES signature. */
        TSL_XML,
        /** ETSI TS 119 602 JSON list of trusted entities with a compact JAdES signature. */
        LOTE_JSON
    }

    /**
     * @param entityName the listed entity (trust service provider) name, English when available
     * @param type the service type identifier, if present
     * @param status the current service status, if present
     * @param certificates X.509 certificates of the service digital identity
     */
    public record Service(
            String entityName, Optional<String> type, Optional<String> status, List<X509Certificate> certificates) {
        public Service {
            Objects.requireNonNull(entityName, "entityName");
            Objects.requireNonNull(type, "type");
            Objects.requireNonNull(status, "status");
            certificates = List.copyOf(certificates);
        }
    }

    /**
     * @param location the location of the other list
     * @param type its type, if given
     * @param territory its territory, if given
     * @param mimeType its media type, if given
     * @param signerCertificates certificates that may sign the other list
     */
    public record Pointer(
            String location,
            Optional<String> type,
            Optional<String> territory,
            Optional<String> mimeType,
            List<X509Certificate> signerCertificates) {
        public Pointer {
            Objects.requireNonNull(location, "location");
            signerCertificates = List.copyOf(signerCertificates);
        }
    }

    public TrustedList {
        Objects.requireNonNull(location, "location");
        Objects.requireNonNull(format, "format");
        Objects.requireNonNull(issued, "issued");
        Objects.requireNonNull(nextUpdate, "nextUpdate");
        services = List.copyOf(services);
        pointers = List.copyOf(pointers);
    }

    /** Whether the list may be relied on at {@code now}: not closed and its next update not yet passed. */
    public boolean isCurrentAt(Instant now) {
        return nextUpdate.isPresent() && now.isBefore(nextUpdate.get()) && !now.isBefore(issued.minusSeconds(300));
    }
}
