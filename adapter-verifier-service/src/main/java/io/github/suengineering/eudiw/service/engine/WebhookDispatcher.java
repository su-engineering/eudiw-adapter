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

import io.github.suengineering.eudiw.core.json.Json;
import io.github.suengineering.eudiw.service.config.AdapterConfig.ClientApplication;
import io.github.suengineering.eudiw.service.config.AdapterConfig.Webhook;
import io.github.suengineering.eudiw.service.store.SessionStore;
import io.github.suengineering.eudiw.service.store.SessionStore.SessionRow;
import io.github.suengineering.eudiw.service.store.WebhookOutbox;
import io.github.suengineering.eudiw.service.store.WebhookOutbox.Delivery;
import io.quarkus.scheduler.Scheduled;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ThreadLocalRandom;
import org.jboss.logging.Logger;

/**
 * Delivers queued webhook notifications (Standard Webhooks). The body names the session, its final status, the
 * policy, the coarse reason and the caller's own reference: never claims. Retries follow the Standard Webhooks
 * example schedule with jitter and stop after the last step, or at once on {@code 410 Gone}. Redirects are not
 * followed.
 */
@ApplicationScoped
public class WebhookDispatcher {

    private static final Logger LOG = Logger.getLogger(WebhookDispatcher.class);

    /** Delay before each retry: 5 s, 5 min, 30 min, 2 h, 5 h, 10 h. */
    static final List<Duration> RETRIES = List.of(
            Duration.ofSeconds(5),
            Duration.ofMinutes(5),
            Duration.ofMinutes(30),
            Duration.ofHours(2),
            Duration.ofHours(5),
            Duration.ofHours(10));

    @Inject
    WebhookOutbox outbox;

    @Inject
    SessionStore sessions;

    @Inject
    AdapterRuntime runtime;

    private final HttpClient http = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    @Scheduled(every = "{eudiw.webhook.interval:5s}", concurrentExecution = Scheduled.ConcurrentExecution.SKIP)
    void scheduled() {
        dispatch();
    }

    /**
     * Sends due deliveries, claiming each one alone just before sending it, so a claim's lease (60 s) always covers
     * its single request (at most 25 s with connect and request timeouts) and other nodes can take the remaining
     * rows meanwhile. Stops after 50 deliveries or 30 s.
     */
    public void dispatch() {
        long deadline = System.nanoTime() + Duration.ofSeconds(30).toNanos();
        for (int sent = 0; sent < 50 && System.nanoTime() < deadline; sent++) {
            Instant now = runtime.clock().instant();
            List<Delivery> claimed = outbox.claim(now, Duration.ofSeconds(60), 1);
            if (claimed.isEmpty()) {
                return;
            }
            Delivery delivery = claimed.get(0);
            try {
                deliver(delivery, now);
            } catch (RuntimeException e) {
                LOG.warnf(
                        "webhook %s not delivered: %s",
                        delivery.id(), e.getClass().getSimpleName());
                reschedule(delivery, now, "error");
            }
        }
    }

    private void deliver(Delivery delivery, Instant now) {
        Optional<Webhook> webhook = runtime.config()
                .tenant(delivery.tenantId())
                .map(t -> t.clients().get(delivery.clientId()))
                .flatMap(ClientApplication::webhook);
        Optional<SessionRow> session = sessions.findById(delivery.sessionId());
        if (webhook.isEmpty() || session.isEmpty()) {
            outbox.failed(delivery.id(), "not_configured");
            return;
        }
        String body = body(delivery, session.get());
        long timestamp = now.getEpochSecond();
        HttpRequest request = HttpRequest.newBuilder(webhook.get().url())
                .timeout(Duration.ofSeconds(15))
                .header("content-type", "application/json")
                .header("webhook-id", delivery.id())
                .header("webhook-timestamp", Long.toString(timestamp))
                .header(
                        "webhook-signature",
                        WebhookSigner.signatureHeader(webhook.get().secrets(), delivery.id(), timestamp, body))
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        int status;
        try {
            status = http.send(request, HttpResponse.BodyHandlers.discarding()).statusCode();
        } catch (IOException e) {
            reschedule(delivery, now, "unreachable");
            return;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            reschedule(delivery, now, "interrupted");
            return;
        }
        String result = "http_" + status;
        if (status >= 200 && status < 300) {
            outbox.delivered(delivery.id(), result);
            audit(delivery, "delivered", result, now);
        } else if (status == 410) {
            outbox.failed(delivery.id(), result);
            audit(delivery, "failed", result, now);
        } else {
            reschedule(delivery, now, result);
        }
    }

    private void reschedule(Delivery delivery, Instant now, String result) {
        int retry = delivery.attempts() - 1;
        if (retry >= RETRIES.size()) {
            outbox.failed(delivery.id(), result);
            audit(delivery, "failed", result, now);
            return;
        }
        Duration delay = RETRIES.get(retry);
        long jitter = ThreadLocalRandom.current().nextLong(Math.max(1, delay.toMillis() / 10));
        outbox.retryAt(delivery.id(), now.plus(delay).plusMillis(jitter), result);
    }

    private void audit(Delivery delivery, String outcome, String result, Instant now) {
        sessions.audit(
                delivery.tenantId(),
                delivery.sessionId(),
                delivery.clientId(),
                "webhook",
                outcome,
                result,
                runtime.config().revision(),
                now);
    }

    static String body(Delivery delivery, SessionRow session) {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("id", session.id());
        data.put("status", delivery.eventStatus());
        data.put("policy_id", session.policyId());
        if (session.failureCode() != null) {
            data.put("reason", session.failureCode());
        }
        if (session.clientReference() != null) {
            data.put("client_reference", session.clientReference());
        }
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("type", "verification_session." + delivery.eventStatus());
        payload.put("timestamp", delivery.occurredAt().toString());
        payload.put("data", data);
        return Json.toJson(payload);
    }
}
