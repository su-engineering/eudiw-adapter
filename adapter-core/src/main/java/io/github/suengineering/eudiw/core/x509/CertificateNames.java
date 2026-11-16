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
package io.github.suengineering.eudiw.core.x509;

import java.net.URI;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;

/** Subject alternative names of a certificate. */
public final class CertificateNames {

    private static final int DNS_NAME = 2;
    private static final int URI_NAME = 6;

    private CertificateNames() {}

    public static List<String> dnsNames(X509Certificate certificate) {
        return names(certificate, DNS_NAME);
    }

    public static List<String> uris(X509Certificate certificate) {
        return names(certificate, URI_NAME);
    }

    /**
     * Whether an issuer identifier is bound to the certificate: it equals a SAN URI, or it is an {@code https}
     * URL whose host equals a SAN dNSName (case-insensitive).
     */
    public static boolean bindsIssuer(X509Certificate certificate, String issuer) {
        if (uris(certificate).contains(issuer)) {
            return true;
        }
        URI uri;
        try {
            uri = URI.create(issuer);
        } catch (IllegalArgumentException e) {
            return false;
        }
        if (!"https".equals(uri.getScheme()) || uri.getHost() == null) {
            return false;
        }
        String host = uri.getHost().toLowerCase(Locale.ROOT);
        for (String dns : dnsNames(certificate)) {
            if (dns.toLowerCase(Locale.ROOT).equals(host)) {
                return true;
            }
        }
        return false;
    }

    private static List<String> names(X509Certificate certificate, int type) {
        List<String> out = new ArrayList<>();
        try {
            Collection<List<?>> names = certificate.getSubjectAlternativeNames();
            if (names == null) {
                return out;
            }
            for (List<?> name : names) {
                if (name.size() >= 2
                        && name.get(0) instanceof Integer t
                        && t == type
                        && name.get(1) instanceof String s) {
                    out.add(s);
                }
            }
        } catch (CertificateParsingException e) {
            return out;
        }
        return out;
    }
}
