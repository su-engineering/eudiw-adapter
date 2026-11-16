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
package io.github.suengineering.eudiw.core.net;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.Locale;
import java.util.Set;

/**
 * Which outbound URLs the verifier may fetch. By default only {@code https} to public addresses: loopback,
 * private, link-local (including cloud metadata endpoints), carrier-grade NAT, unique-local, multicast and
 * unspecified addresses are refused after DNS resolution.
 *
 * <p>The address check runs before the connection; it does not prevent DNS rebinding between check and connect.
 * Production deployments should also restrict egress at the network layer.
 *
 * @param allowHttp accept plain {@code http} (development only)
 * @param allowPrivateAddresses accept non-public addresses (development only)
 * @param allowedHosts if non-empty, only these hosts (lower case) may be fetched
 */
public record EgressPolicy(boolean allowHttp, boolean allowPrivateAddresses, Set<String> allowedHosts) {

    public static final EgressPolicy STRICT = new EgressPolicy(false, false, Set.of());

    public EgressPolicy {
        allowedHosts = Set.copyOf(allowedHosts);
    }

    /**
     * @throws HttpFetcher.FetchException when the URL is not allowed
     */
    public void check(URI uri) throws HttpFetcher.FetchException {
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        if (!scheme.equals("https") && !(allowHttp && scheme.equals("http"))) {
            throw new HttpFetcher.FetchException("scheme not allowed: " + scheme);
        }
        if (uri.getUserInfo() != null) {
            throw new HttpFetcher.FetchException("user info in URL not allowed");
        }
        String host = uri.getHost();
        if (host == null || host.isEmpty()) {
            throw new HttpFetcher.FetchException("URL has no host");
        }
        if (!allowedHosts.isEmpty() && !allowedHosts.contains(host.toLowerCase(Locale.ROOT))) {
            throw new HttpFetcher.FetchException("host not in allow list");
        }
        if (allowPrivateAddresses) {
            return;
        }
        InetAddress[] addresses;
        try {
            addresses = InetAddress.getAllByName(host);
        } catch (UnknownHostException e) {
            throw new HttpFetcher.FetchException("host cannot be resolved", e);
        }
        for (InetAddress address : addresses) {
            if (!isPublic(address)) {
                throw new HttpFetcher.FetchException("host resolves to a non-public address");
            }
        }
    }

    static boolean isPublic(InetAddress address) {
        if (address.isLoopbackAddress()
                || address.isAnyLocalAddress()
                || address.isLinkLocalAddress()
                || address.isSiteLocalAddress()
                || address.isMulticastAddress()) {
            return false;
        }
        byte[] b = address.getAddress();
        if (address instanceof Inet4Address) {
            int first = b[0] & 0xFF;
            int second = b[1] & 0xFF;
            if (first == 0 || first >= 240) {
                return false; // "this network", reserved and broadcast
            }
            if (first == 100 && second >= 64 && second <= 127) {
                return false; // carrier-grade NAT 100.64.0.0/10
            }
            if (first == 198 && (second == 18 || second == 19)) {
                return false; // benchmarking 198.18.0.0/15
            }
            if (first == 192 && second == 0 && (b[2] & 0xFF) == 0) {
                return false; // IETF protocol assignments 192.0.0.0/24
            }
            return true;
        }
        if (address instanceof Inet6Address v6) {
            if ((b[0] & 0xFE) == 0xFC) {
                return false; // unique local fc00::/7
            }
            if (v6.isIPv4CompatibleAddress()) {
                return false;
            }
            // IPv4-mapped ::ffff:a.b.c.d is normalized to Inet4Address by the JDK
            return true;
        }
        return false;
    }
}
