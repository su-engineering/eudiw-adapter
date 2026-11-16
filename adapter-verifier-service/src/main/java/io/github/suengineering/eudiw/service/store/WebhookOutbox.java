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
package io.github.suengineering.eudiw.service.store;

import io.agroal.api.AgroalDataSource;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * The webhook outbox. Due deliveries are claimed with {@code FOR UPDATE SKIP LOCKED} and a lease, so with several
 * nodes each delivery is attempted by one node at a time, and a node that dies mid-delivery releases it when the
 * lease ends.
 */
@ApplicationScoped
public class WebhookOutbox {

    @Inject
    AgroalDataSource dataSource;

    public record Delivery(
            String id,
            String sessionId,
            String tenantId,
            String clientId,
            String eventStatus,
            Instant occurredAt,
            int attempts) {}

    public List<Delivery> claim(Instant now, Duration lease, int limit) {
        String sql = "UPDATE webhook_delivery SET claimed_until = ?, attempts = attempts + 1 WHERE id IN ("
                + " SELECT id FROM webhook_delivery WHERE state = 'pending' AND next_attempt_at <= ?"
                + " AND (claimed_until IS NULL OR claimed_until <= ?)"
                + " ORDER BY next_attempt_at LIMIT ? FOR UPDATE SKIP LOCKED)"
                + " RETURNING id, session_id, tenant_id, client_id, event_status, occurred_at, attempts";
        try (Connection c = dataSource.getConnection();
                PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setTimestamp(1, Timestamp.from(now.plus(lease)));
            ps.setTimestamp(2, Timestamp.from(now));
            ps.setTimestamp(3, Timestamp.from(now));
            ps.setInt(4, limit);
            List<Delivery> result = new ArrayList<>();
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    result.add(new Delivery(
                            rs.getString(1),
                            rs.getString(2),
                            rs.getString(3),
                            rs.getString(4),
                            rs.getString(5),
                            rs.getTimestamp(6).toInstant(),
                            rs.getInt(7)));
                }
            }
            return result;
        } catch (SQLException e) {
            throw new SessionStore.StoreException(e);
        }
    }

    public void delivered(String id, String result) {
        update(
                "UPDATE webhook_delivery SET state = 'delivered', claimed_until = NULL, last_result = ? WHERE id = ?",
                result,
                id,
                null);
    }

    public void failed(String id, String result) {
        update(
                "UPDATE webhook_delivery SET state = 'failed', claimed_until = NULL, last_result = ? WHERE id = ?",
                result,
                id,
                null);
    }

    public void retryAt(String id, Instant next, String result) {
        update(
                "UPDATE webhook_delivery SET next_attempt_at = ?, claimed_until = NULL, last_result = ? WHERE id = ?",
                result,
                id,
                next);
    }

    /** Deliveries for a session, for tests and diagnostics. */
    public List<String> states(String sessionId) {
        try (Connection c = dataSource.getConnection();
                PreparedStatement ps = c.prepareStatement(
                        "SELECT state FROM webhook_delivery WHERE session_id = ? ORDER BY created_at")) {
            ps.setString(1, sessionId);
            List<String> result = new ArrayList<>();
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    result.add(rs.getString(1));
                }
            }
            return result;
        } catch (SQLException e) {
            throw new SessionStore.StoreException(e);
        }
    }

    private void update(String sql, String result, String id, Instant next) {
        try (Connection c = dataSource.getConnection();
                PreparedStatement ps = c.prepareStatement(sql)) {
            int i = 1;
            if (next != null) {
                ps.setTimestamp(i++, Timestamp.from(next));
            }
            ps.setString(i++, result);
            ps.setString(i, id);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new SessionStore.StoreException(e);
        }
    }
}
