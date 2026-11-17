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
 * unspecified addresses are refused after DNS resolution, and so are IPv6 addresses outside global unicast or in a
 * transition range that embeds an IPv4 address (NAT64, 6to4, Teredo).
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
        if (address instanceof Inet6Address) {
            // IPv4-mapped ::ffff:a.b.c.d is normalized to Inet4Address by the JDK. Everything else must be global
            // unicast 2000::/3, which already excludes NAT64 64:ff9b::/96 and 64:ff9b:1::/48, discard 100::/64,
            // IPv4-compatible, unique local and link-local addresses.
            if ((b[0] & 0xE0) != 0x20) {
                return false;
            }
            int first = ((b[0] & 0xFF) << 8) | (b[1] & 0xFF);
            int second = ((b[2] & 0xFF) << 8) | (b[3] & 0xFF);
            if (first == 0x2002) {
                return false; // 6to4 2002::/16 embeds an IPv4 address
            }
            if (first == 0x2001 && (second == 0x0000 || second == 0x0db8)) {
                return false; // Teredo 2001::/32, documentation 2001:db8::/32
            }
            if (first == 0x2001 && second == 0x0002 && b[4] == 0 && b[5] == 0) {
                return false; // benchmarking 2001:2::/48
            }
            if (first == 0x3FFF && (b[2] & 0xF0) == 0) {
                return false; // documentation 3fff::/20
            }
            return true;
        }
        return false;
    }
}
