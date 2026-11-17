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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class JdkHttpFetcherTest {

    private static final EgressPolicy LOCAL = new EgressPolicy(true, true, Set.of());

    private HttpServer server;

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/ok", exchange -> {
            byte[] body = "status list".getBytes(StandardCharsets.US_ASCII);
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        server.createContext("/large", exchange -> {
            exchange.sendResponseHeaders(200, 0);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(new byte[4096]);
            }
        });
        server.createContext("/missing", exchange -> {
            exchange.sendResponseHeaders(404, -1);
            exchange.close();
        });
        // Headers at once, then one body byte every 200 ms: the slow-body attack on the read deadline.
        server.createContext("/drip", exchange -> {
            exchange.sendResponseHeaders(200, 0);
            try (OutputStream out = exchange.getResponseBody()) {
                for (int i = 0; i < 100; i++) {
                    out.write('x');
                    out.flush();
                    Thread.sleep(200);
                }
            } catch (IOException | InterruptedException e) {
                // the client gave up
            }
        });
        server.setExecutor(java.util.concurrent.Executors.newCachedThreadPool());
        server.start();
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    private URI uri(String path) {
        return URI.create("http://127.0.0.1:" + server.getAddress().getPort() + path);
    }

    @Test
    void returnsTheBody() throws Exception {
        byte[] body = new JdkHttpFetcher(LOCAL, Duration.ofSeconds(5)).get(uri("/ok"), "text/plain", 1024);
        assertThat(new String(body, StandardCharsets.US_ASCII)).isEqualTo("status list");
    }

    @Test
    void refusesALargerBody() {
        assertThatThrownBy(() -> new JdkHttpFetcher(LOCAL, Duration.ofSeconds(5)).get(uri("/large"), "*/*", 1024))
                .isInstanceOf(HttpFetcher.FetchException.class)
                .hasMessage("response exceeds 1024 bytes");
    }

    @Test
    void refusesANonSuccessStatus() {
        assertThatThrownBy(() -> new JdkHttpFetcher(LOCAL, Duration.ofSeconds(5)).get(uri("/missing"), "*/*", 1024))
                .isInstanceOf(HttpFetcher.FetchException.class)
                .hasMessage("unexpected HTTP status 404");
    }

    @Test
    void theTimeoutCoversTheBody() {
        JdkHttpFetcher fetcher = new JdkHttpFetcher(LOCAL, Duration.ofSeconds(1));
        long start = System.nanoTime();
        assertThatThrownBy(() -> fetcher.get(uri("/drip"), "*/*", 1024))
                .isInstanceOf(HttpFetcher.FetchException.class)
                .hasMessage("request timed out");
        assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofSeconds(3));
    }

    @Test
    void stillChecksTheEgressPolicy() {
        assertThatThrownBy(() ->
                        new JdkHttpFetcher(EgressPolicy.STRICT, Duration.ofSeconds(5)).get(uri("/ok"), "*/*", 1024))
                .isInstanceOf(HttpFetcher.FetchException.class)
                .hasMessage("scheme not allowed: http");
    }

    @Test
    void goesThroughTheConfiguredProxy() throws Exception {
        java.util.List<String> seen = new java.util.concurrent.CopyOnWriteArrayList<>();
        HttpServer proxy = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        proxy.createContext("/", exchange -> {
            seen.add(exchange.getRequestURI().toString());
            byte[] body = "via proxy".getBytes(StandardCharsets.US_ASCII);
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        proxy.start();
        try {
            // Nothing listens on port 1, so only the proxy can answer.
            URI target = URI.create("http://127.0.0.1:1/status/7");
            JdkHttpFetcher fetcher = new JdkHttpFetcher(
                    LOCAL,
                    Duration.ofSeconds(5),
                    JdkHttpFetcher.proxy("127.0.0.1:" + proxy.getAddress().getPort()));
            byte[] body = fetcher.get(target, "*/*", 1024);
            assertThat(new String(body, StandardCharsets.US_ASCII)).isEqualTo("via proxy");
            assertThat(seen).containsExactly(target.toString());
        } finally {
            proxy.stop(0);
        }
    }

    @Test
    void theEgressPolicyStillAppliesBehindAProxy() {
        JdkHttpFetcher fetcher =
                new JdkHttpFetcher(EgressPolicy.STRICT, Duration.ofSeconds(5), JdkHttpFetcher.proxy("proxy.test:3128"));
        assertThatThrownBy(() -> fetcher.get(URI.create("https://127.0.0.1/list"), "*/*", 1024))
                .isInstanceOf(HttpFetcher.FetchException.class)
                .hasMessage("host resolves to a non-public address");
    }

    @Test
    void parsesTheProxySetting() {
        assertThat(JdkHttpFetcher.proxy("proxy.internal:3128"))
                .satisfies(a -> assertThat(a.getHostString()).isEqualTo("proxy.internal"))
                .satisfies(a -> assertThat(a.getPort()).isEqualTo(3128));
        assertThat(JdkHttpFetcher.proxy(" http://10.0.0.5:8080/ ").getPort()).isEqualTo(8080);
        for (String bad : new String[] {
            "proxy.internal",
            "https://proxy:443",
            "http://user:pw@proxy:3128",
            "http://proxy:3128/path",
            "socks5://p:1080"
        }) {
            assertThatThrownBy(() -> JdkHttpFetcher.proxy(bad)).as(bad).isInstanceOf(IllegalArgumentException.class);
        }
    }
}
