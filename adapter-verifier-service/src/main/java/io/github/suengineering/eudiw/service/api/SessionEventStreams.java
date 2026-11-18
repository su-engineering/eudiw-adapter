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
package io.github.suengineering.eudiw.service.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.suengineering.eudiw.service.config.AdapterConfig.ClientBinding;
import io.github.suengineering.eudiw.service.engine.AdapterRuntime;
import io.github.suengineering.eudiw.service.store.SessionStore;
import io.github.suengineering.eudiw.service.store.SessionStore.SessionRow;
import io.micrometer.core.instrument.MeterRegistry;
import io.quarkus.runtime.ShutdownEvent;
import io.quarkus.scheduler.Scheduled;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.sse.Sse;
import jakarta.ws.rs.sse.SseEventSink;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

/**
 * Open Server-Sent Event streams of session status (ADR-013). No stream holds a thread or a database connection:
 * one tick per node reads every watched session in a single query and sends what changed. State comes from
 * PostgreSQL, so a session completed on another node reaches streams on this one by the next tick.
 */
@ApplicationScoped
public class SessionEventStreams {

    private static final Logger LOG = Logger.getLogger(SessionEventStreams.class);
    static final Duration HEARTBEAT = Duration.ofSeconds(15);

    @Inject
    SessionStore store;

    @Inject
    AdapterRuntime runtime;

    @Inject
    ObjectMapper mapper;

    @Inject
    MeterRegistry registry;

    @ConfigProperty(name = "eudiw.events.max-streams", defaultValue = "1000")
    int maxStreams;

    @ConfigProperty(name = "eudiw.events.max-streams-per-client", defaultValue = "100")
    int maxStreamsPerClient;

    private final Map<String, List<Stream>> bySession = new ConcurrentHashMap<>();

    private static final class Stream {
        final String tenantId;
        final String clientId;
        final String sessionId;
        final SseEventSink sink;
        final Sse sse;
        final Instant notAfter;
        String last;
        long nextId;
        Instant lastSent;

        Stream(String tenantId, String clientId, String sessionId, SseEventSink sink, Sse sse, Instant notAfter) {
            this.tenantId = tenantId;
            this.clientId = clientId;
            this.sessionId = sessionId;
            this.sink = sink;
            this.sse = sse;
            this.notAfter = notAfter;
        }
    }

    @PostConstruct
    void gauge() {
        registry.gauge("eudiw.session.event.streams", this, SessionEventStreams::open);
    }

    /** For tests: changes the caps. */
    public void limitForTests(int perNode, int perClient) {
        maxStreams = perNode;
        maxStreamsPerClient = perClient;
    }

    /** Streams open on this node. */
    public int open() {
        return bySession.values().stream().mapToInt(List::size).sum();
    }

    private int openFor(ClientBinding caller) {
        int n = 0;
        for (List<Stream> streams : bySession.values()) {
            for (Stream s : streams) {
                if (s.tenantId.equals(caller.tenant().id())
                        && s.clientId.equals(caller.client().clientId())) {
                    n++;
                }
            }
        }
        return n;
    }

    /** Refuses with 429 before anything is written, when this node or this client has too many streams open. */
    void checkCapacity(ClientBinding caller) {
        if (open() >= maxStreams || openFor(caller) >= maxStreamsPerClient) {
            throw new ApiException(429, "too_many_streams", "too many open event streams; poll instead", 5);
        }
    }

    /**
     * Sends the current status, then keeps the stream until the session leaves {@code pending}, the access token it
     * was opened with expires, or the client is removed from the configuration.
     */
    void watch(ClientBinding caller, SessionRow session, SseEventSink sink, Sse sse, Instant tokenExpiry) {
        Stream stream =
                new Stream(caller.tenant().id(), caller.client().clientId(), session.id(), sink, sse, tokenExpiry);
        Map<String, Object> view = SessionView.of(session, runtime.clock().instant());
        if (!send(stream, view) || SessionView.isFinal(view)) {
            close(stream);
            return;
        }
        bySession
                .computeIfAbsent(session.id(), k -> new CopyOnWriteArrayList<>())
                .add(stream);
    }

    @Scheduled(every = "{eudiw.events.interval:1s}", concurrentExecution = Scheduled.ConcurrentExecution.SKIP)
    void tick() {
        bySession.forEach((id, streams) -> streams.removeIf(s -> s.sink.isClosed()));
        bySession.entrySet().removeIf(e -> e.getValue().isEmpty());
        if (bySession.isEmpty()) {
            return;
        }
        Map<String, SessionRow> rows = new HashMap<>();
        try {
            for (SessionRow row : store.findByIds(new ArrayList<>(bySession.keySet()))) {
                rows.put(row.id(), row);
            }
        } catch (RuntimeException e) {
            LOG.warnf(
                    "session event streams: reading sessions failed, retrying next tick: %s",
                    e.getClass().getName());
            return;
        }
        Instant now = runtime.clock().instant();
        for (List<Stream> streams : bySession.values()) {
            for (Stream stream : streams) {
                SessionRow row = rows.get(stream.sessionId);
                if (row == null
                        || !row.tenantId().equals(stream.tenantId)
                        || !row.clientId().equals(stream.clientId)
                        || !now.isBefore(stream.notAfter)
                        || !stillRegistered(stream)) {
                    remove(stream);
                    continue;
                }
                Map<String, Object> view = SessionView.of(row, now);
                boolean sent = send(stream, view);
                if (!sent || SessionView.isFinal(view)) {
                    remove(stream);
                } else if (Duration.between(stream.lastSent, now).compareTo(HEARTBEAT) >= 0) {
                    heartbeat(stream, now);
                }
            }
        }
    }

    private boolean stillRegistered(Stream stream) {
        return runtime.config()
                .client(stream.clientId)
                .filter(b -> b.tenant().id().equals(stream.tenantId))
                .isPresent();
    }

    /** Sends the view if it differs from the last one sent. False when the stream is gone. */
    private boolean send(Stream stream, Map<String, Object> view) {
        if (stream.sink.isClosed()) {
            return false;
        }
        String json;
        try {
            json = mapper.writeValueAsString(view);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
        if (json.equals(stream.last)) {
            return true;
        }
        try {
            stream.sink.send(stream.sse
                    .newEventBuilder()
                    .name("status")
                    .id(Long.toString(++stream.nextId))
                    .mediaType(MediaType.TEXT_PLAIN_TYPE)
                    .data(String.class, json)
                    .build());
        } catch (RuntimeException e) {
            return false;
        }
        stream.last = json;
        stream.lastSent = runtime.clock().instant();
        return true;
    }

    private void heartbeat(Stream stream, Instant now) {
        try {
            stream.sink.send(stream.sse.newEventBuilder().comment("keep-alive").build());
            stream.lastSent = now;
        } catch (RuntimeException e) {
            remove(stream);
        }
    }

    private void remove(Stream stream) {
        List<Stream> streams = bySession.get(stream.sessionId);
        if (streams != null) {
            streams.remove(stream);
        }
        close(stream);
    }

    private static void close(Stream stream) {
        try {
            stream.sink.close();
        } catch (RuntimeException e) {
            // already closed by the client
        }
    }

    void closeAll(@Observes ShutdownEvent event) {
        bySession.values().forEach(streams -> streams.forEach(SessionEventStreams::close));
        bySession.clear();
    }
}
