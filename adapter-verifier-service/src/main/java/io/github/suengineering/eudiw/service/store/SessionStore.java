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
import java.time.Instant;
import java.util.Optional;

/**
 * PostgreSQL persistence for sessions, request instances and audit events. State changes are single conditional
 * {@code UPDATE} statements, so exactly one caller wins any race regardless of which node serves it. Every
 * application-facing read filters by tenant and client.
 */
@ApplicationScoped
public class SessionStore {

    @Inject
    AgroalDataSource dataSource;

    public record SessionRow(
            String id,
            String tenantId,
            String clientId,
            String policyId,
            String configRevision,
            String mode,
            String status,
            String requestHandle,
            String requestFingerprint,
            String clientReference,
            String failureCode,
            boolean hasResult,
            Instant createdAt,
            Instant expiresAt,
            Instant completedAt) {}

    public record InstanceRow(
            String kid,
            String sessionId,
            String tenantId,
            String state,
            String nonce,
            byte[] keyCiphertext,
            Instant expiresAt,
            Instant consumedAt) {}

    private static final String SESSION_COLUMNS =
            "id, tenant_id, client_id, policy_id, config_revision, mode, status, request_handle, request_fingerprint,"
                    + " client_reference, failure_code, (result_ciphertext IS NOT NULL) AS has_result, created_at,"
                    + " expires_at, completed_at";

    /** Inserts a session unless the same client already used the idempotency key; returns the stored session. */
    public SessionRow insertOrGetIdempotent(SessionRow row, String idempotencyKeyHash) {
        String sql = "INSERT INTO verification_session (id, tenant_id, client_id, policy_id, config_revision, mode,"
                + " status, request_handle, idempotency_key_hash, request_fingerprint, client_reference, created_at,"
                + " expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)"
                + " ON CONFLICT (tenant_id, client_id, idempotency_key_hash) DO NOTHING";
        try (Connection c = dataSource.getConnection();
                PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, row.id());
            ps.setString(2, row.tenantId());
            ps.setString(3, row.clientId());
            ps.setString(4, row.policyId());
            ps.setString(5, row.configRevision());
            ps.setString(6, row.mode());
            ps.setString(7, row.status());
            ps.setString(8, row.requestHandle());
            ps.setString(9, idempotencyKeyHash);
            ps.setString(10, row.requestFingerprint());
            ps.setString(11, row.clientReference());
            ps.setTimestamp(12, ts(row.createdAt()));
            ps.setTimestamp(13, ts(row.expiresAt()));
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new StoreException(e);
        }
        return queryOne(
                        "SELECT " + SESSION_COLUMNS
                                + " FROM verification_session WHERE tenant_id = ? AND client_id = ? AND idempotency_key_hash = ?",
                        row.tenantId(),
                        row.clientId(),
                        idempotencyKeyHash)
                .orElseThrow(() -> new StoreException(new SQLException("session not stored")));
    }

    public Optional<SessionRow> find(String tenantId, String clientId, String id) {
        return queryOne(
                "SELECT " + SESSION_COLUMNS
                        + " FROM verification_session WHERE id = ? AND tenant_id = ? AND client_id = ?",
                id,
                tenantId,
                clientId);
    }

    /** Wallet-facing lookup by the unguessable request handle. */
    public Optional<SessionRow> findByHandle(String handle) {
        return queryOne("SELECT " + SESSION_COLUMNS + " FROM verification_session WHERE request_handle = ?", handle);
    }

    public Optional<SessionRow> findById(String id) {
        return queryOne("SELECT " + SESSION_COLUMNS + " FROM verification_session WHERE id = ?", id);
    }

    /**
     * Stores a request instance unless the session already has {@code maxPerSession} of them.
     *
     * @return whether the instance was stored
     */
    public boolean insertInstance(InstanceRow row, Instant now, int maxPerSession) {
        String sql = "INSERT INTO request_instance (kid, session_id, tenant_id, state, nonce, key_ciphertext,"
                + " created_at, expires_at) SELECT ?,?,?,?,?,?,?,?"
                + " WHERE (SELECT count(*) FROM request_instance WHERE session_id = ?) < ?";
        try (Connection c = dataSource.getConnection();
                PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, row.kid());
            ps.setString(2, row.sessionId());
            ps.setString(3, row.tenantId());
            ps.setString(4, row.state());
            ps.setString(5, row.nonce());
            ps.setBytes(6, row.keyCiphertext());
            ps.setTimestamp(7, ts(now));
            ps.setTimestamp(8, ts(row.expiresAt()));
            ps.setString(9, row.sessionId());
            ps.setInt(10, maxPerSession);
            return ps.executeUpdate() == 1;
        } catch (SQLException e) {
            throw new StoreException(e);
        }
    }

    public Optional<InstanceRow> findInstanceByKid(String kid) {
        return queryInstance("SELECT * FROM request_instance WHERE kid = ?", kid);
    }

    public Optional<InstanceRow> findInstanceByState(String state) {
        return queryInstance("SELECT * FROM request_instance WHERE state = ?", state);
    }

    /** Marks a request instance used. Only one caller ever gets {@code true}. */
    public boolean consumeInstance(String kid, Instant now) {
        return update(
                        "UPDATE request_instance SET consumed_at = ? WHERE kid = ? AND consumed_at IS NULL AND expires_at > ?",
                        ts(now),
                        kid,
                        ts(now))
                == 1;
    }

    /**
     * Moves a pending, unexpired session to a terminal state. Only one caller ever gets {@code true}; a session in
     * any other state never changes.
     */
    public boolean complete(
            String sessionId,
            String status,
            String failureCode,
            byte[] resultCiphertext,
            String responseCodeHash,
            Instant resultExpiresAt,
            Instant now) {
        String sql = "UPDATE verification_session SET status = ?, failure_code = ?, result_ciphertext = ?,"
                + " response_code_hash = ?, result_expires_at = ?, completed_at = ?"
                + " WHERE id = ? AND status = 'pending' AND expires_at > ?";
        try (Connection c = dataSource.getConnection();
                PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, status);
            ps.setString(2, failureCode);
            ps.setBytes(3, resultCiphertext);
            ps.setString(4, responseCodeHash);
            ps.setTimestamp(5, resultExpiresAt == null ? null : ts(resultExpiresAt));
            ps.setTimestamp(6, ts(now));
            ps.setString(7, sessionId);
            ps.setTimestamp(8, ts(now));
            return ps.executeUpdate() == 1;
        } catch (SQLException e) {
            throw new StoreException(e);
        }
    }

    public boolean cancel(String tenantId, String clientId, String id, Instant now) {
        return update(
                        "UPDATE verification_session SET status = 'cancelled', completed_at = ?"
                                + " WHERE id = ? AND tenant_id = ? AND client_id = ? AND status = 'pending'",
                        ts(now),
                        id,
                        tenantId,
                        clientId)
                == 1;
    }

    /**
     * Returns the encrypted result once and deletes it. In same-device sessions the matching response code is
     * required.
     */
    public Optional<byte[]> consumeResult(
            String tenantId, String clientId, String id, String responseCodeHash, Instant now) {
        String sql = "UPDATE verification_session t SET status = 'consumed', result_ciphertext = NULL"
                + " FROM (SELECT id, result_ciphertext AS rc FROM verification_session WHERE id = ? FOR UPDATE) old"
                + " WHERE t.id = old.id AND t.tenant_id = ? AND t.client_id = ? AND t.status = 'verified'"
                + " AND t.result_expires_at > ? AND (t.response_code_hash IS NULL OR t.response_code_hash = ?)"
                + " RETURNING old.rc";
        try (Connection c = dataSource.getConnection();
                PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, id);
            ps.setString(2, tenantId);
            ps.setString(3, clientId);
            ps.setTimestamp(4, ts(now));
            ps.setString(5, responseCodeHash == null ? "" : responseCodeHash);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? Optional.ofNullable(rs.getBytes(1)) : Optional.empty();
            }
        } catch (SQLException e) {
            throw new StoreException(e);
        }
    }

    /** Expires overdue sessions, drops unretrieved results and stale per-request keys. */
    public int sweep(Instant now) {
        int expired = update(
                "UPDATE verification_session SET status = 'expired' WHERE status = 'pending' AND expires_at <= ?",
                ts(now));
        update(
                "UPDATE verification_session SET status = 'expired', result_ciphertext = NULL"
                        + " WHERE status = 'verified' AND result_expires_at <= ?",
                ts(now));
        update("DELETE FROM request_instance WHERE expires_at <= ?", ts(now.minusSeconds(3600)));
        return expired;
    }

    public void audit(
            String tenantId,
            String sessionId,
            String clientId,
            String action,
            String outcome,
            String code,
            String revision,
            Instant now) {
        String sql =
                "INSERT INTO audit_event (tenant_id, session_id, client_id, action, outcome, code, config_revision,"
                        + " occurred_at) VALUES (?,?,?,?,?,?,?,?)";
        try (Connection c = dataSource.getConnection();
                PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, tenantId);
            ps.setString(2, sessionId);
            ps.setString(3, clientId);
            ps.setString(4, action);
            ps.setString(5, outcome);
            ps.setString(6, code);
            ps.setString(7, revision);
            ps.setTimestamp(8, ts(now));
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new StoreException(e);
        }
    }

    private Optional<SessionRow> queryOne(String sql, String... params) {
        try (Connection c = dataSource.getConnection();
                PreparedStatement ps = c.prepareStatement(sql)) {
            for (int i = 0; i < params.length; i++) {
                ps.setString(i + 1, params[i]);
            }
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return Optional.empty();
                }
                return Optional.of(new SessionRow(
                        rs.getString("id"),
                        rs.getString("tenant_id"),
                        rs.getString("client_id"),
                        rs.getString("policy_id"),
                        rs.getString("config_revision"),
                        rs.getString("mode"),
                        rs.getString("status"),
                        rs.getString("request_handle"),
                        rs.getString("request_fingerprint"),
                        rs.getString("client_reference"),
                        rs.getString("failure_code"),
                        rs.getBoolean("has_result"),
                        instant(rs.getTimestamp("created_at")),
                        instant(rs.getTimestamp("expires_at")),
                        instant(rs.getTimestamp("completed_at"))));
            }
        } catch (SQLException e) {
            throw new StoreException(e);
        }
    }

    private Optional<InstanceRow> queryInstance(String sql, String param) {
        try (Connection c = dataSource.getConnection();
                PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, param);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return Optional.empty();
                }
                return Optional.of(new InstanceRow(
                        rs.getString("kid"),
                        rs.getString("session_id"),
                        rs.getString("tenant_id"),
                        rs.getString("state"),
                        rs.getString("nonce"),
                        rs.getBytes("key_ciphertext"),
                        instant(rs.getTimestamp("expires_at")),
                        instant(rs.getTimestamp("consumed_at"))));
            }
        } catch (SQLException e) {
            throw new StoreException(e);
        }
    }

    private int update(String sql, Object... params) {
        try (Connection c = dataSource.getConnection();
                PreparedStatement ps = c.prepareStatement(sql)) {
            for (int i = 0; i < params.length; i++) {
                ps.setObject(i + 1, params[i]);
            }
            return ps.executeUpdate();
        } catch (SQLException e) {
            throw new StoreException(e);
        }
    }

    private static Timestamp ts(Instant instant) {
        return Timestamp.from(instant);
    }

    private static Instant instant(Timestamp timestamp) {
        return timestamp == null ? null : timestamp.toInstant();
    }

    public static final class StoreException extends RuntimeException {
        public StoreException(Throwable cause) {
            super("database operation failed", cause);
        }
    }
}
