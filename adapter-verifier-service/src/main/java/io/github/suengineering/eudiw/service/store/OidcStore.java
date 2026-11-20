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
import io.github.suengineering.eudiw.service.store.SessionStore.StoreException;
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
 * Authorization requests to the wallet login provider (ADR-018). Every state change is one conditional statement,
 * so concurrent requests cannot both complete a login or both redeem a code.
 */
@ApplicationScoped
public class OidcStore {

    @Inject
    AgroalDataSource dataSource;

    /**
     * @param status {@code pending} (wallet presentation running), {@code completing} (one request is turning the
     *     verified result into a code), {@code code_issued}, {@code redeemed}, {@code failed} or {@code revoked}
     */
    public record AuthorizationRow(
            String id,
            String tenantId,
            String clientId,
            String sessionId,
            String status,
            String bindingHash,
            String redirectUri,
            String state,
            String nonce,
            String codeChallenge,
            String error,
            byte[] codeCiphertext,
            Instant codeExpiresAt,
            byte[] claimsCiphertext,
            Instant authTime,
            Instant expiresAt) {}

    private static final String COLUMNS = "id, tenant_id, client_id, session_id, status, binding_hash, redirect_uri,"
            + " state, nonce, code_challenge, error, code_ciphertext, code_expires_at, claims_ciphertext, auth_time,"
            + " expires_at";

    public void insert(AuthorizationRow row, Instant now) {
        String sql = "INSERT INTO oidc_authorization (id, tenant_id, client_id, session_id, status, binding_hash,"
                + " redirect_uri, state, nonce, code_challenge, created_at, expires_at)"
                + " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)";
        update(
                sql,
                row.id(),
                row.tenantId(),
                row.clientId(),
                row.sessionId(),
                row.status(),
                row.bindingHash(),
                row.redirectUri(),
                row.state(),
                row.nonce(),
                row.codeChallenge(),
                ts(now),
                ts(row.expiresAt()));
    }

    public Optional<AuthorizationRow> find(String tenantId, String id) {
        return queryOne("SELECT " + COLUMNS + " FROM oidc_authorization WHERE tenant_id = ? AND id = ?", tenantId, id);
    }

    public Optional<AuthorizationRow> findByCode(String tenantId, String codeHash) {
        return queryOne(
                "SELECT " + COLUMNS + " FROM oidc_authorization WHERE tenant_id = ? AND code_hash = ?",
                tenantId,
                codeHash);
    }

    /** Takes a pending authorization for completion; false when another request already took it. */
    public boolean startCompleting(String tenantId, String id) {
        return update(
                        "UPDATE oidc_authorization SET status = 'completing' WHERE tenant_id = ? AND id = ?"
                                + " AND status = 'pending'",
                        tenantId,
                        id)
                == 1;
    }

    /** Ends a pending or completing authorization with an error for the client. */
    public void fail(String tenantId, String id, String error) {
        update(
                "UPDATE oidc_authorization SET status = 'failed', error = ? WHERE tenant_id = ? AND id = ?"
                        + " AND status IN ('pending', 'completing')",
                error,
                tenantId,
                id);
    }

    public void issueCode(
            String tenantId,
            String id,
            String codeHash,
            byte[] codeCiphertext,
            Instant codeExpiresAt,
            byte[] claimsCiphertext,
            Instant authTime) {
        int updated = update(
                "UPDATE oidc_authorization SET status = 'code_issued', code_hash = ?, code_ciphertext = ?,"
                        + " code_expires_at = ?, claims_ciphertext = ?, auth_time = ?,"
                        + " expires_at = GREATEST(expires_at, ?) WHERE tenant_id = ? AND id = ? AND status = 'completing'",
                codeHash,
                codeCiphertext,
                ts(codeExpiresAt),
                claimsCiphertext,
                ts(authTime),
                ts(codeExpiresAt),
                tenantId,
                id);
        if (updated != 1) {
            throw new StoreException(new SQLException("authorization was not completing"));
        }
    }

    /**
     * Redeems an authorization code once and attaches the access token for userinfo.
     *
     * @return the authorization, empty when the code is unknown, used or expired
     */
    public Optional<AuthorizationRow> redeem(
            String tenantId, String codeHash, Instant now, String accessTokenHash, Instant accessExpiresAt) {
        return queryOne(
                "UPDATE oidc_authorization SET status = 'redeemed', code_ciphertext = NULL, access_token_hash = ?,"
                        + " access_expires_at = ?, expires_at = GREATEST(expires_at, ?)"
                        + " WHERE tenant_id = ? AND code_hash = ? AND status = 'code_issued' AND code_expires_at > ?"
                        + " RETURNING " + COLUMNS,
                accessTokenHash,
                ts(accessExpiresAt),
                ts(accessExpiresAt),
                tenantId,
                codeHash,
                ts(now));
    }

    /**
     * A code presented again after it was redeemed: revoke the access token it produced (RFC 6749 section 4.1.2).
     *
     * @return whether a redeemed authorization was revoked
     */
    public boolean revokeRedeemed(String tenantId, String codeHash) {
        return update(
                        "UPDATE oidc_authorization SET status = 'revoked', access_token_hash = NULL,"
                                + " claims_ciphertext = NULL WHERE tenant_id = ? AND code_hash = ?"
                                + " AND status = 'redeemed'",
                        tenantId,
                        codeHash)
                == 1;
    }

    /** The encrypted claims behind a live access token. */
    public Optional<AuthorizationRow> byAccessToken(String tenantId, String accessTokenHash, Instant now) {
        return queryOne(
                "SELECT " + COLUMNS + " FROM oidc_authorization WHERE tenant_id = ? AND access_token_hash = ?"
                        + " AND status = 'redeemed' AND access_expires_at > ?",
                tenantId,
                accessTokenHash,
                ts(now));
    }

    /** Deletes authorizations whose codes and tokens have all expired. */
    public int sweep(Instant now) {
        return update("DELETE FROM oidc_authorization WHERE expires_at <= ?", ts(now));
    }

    private int update(String sql, Object... params) {
        try (Connection c = dataSource.getConnection();
                PreparedStatement ps = c.prepareStatement(sql)) {
            bind(ps, params);
            return ps.executeUpdate();
        } catch (SQLException e) {
            throw new StoreException(e);
        }
    }

    private Optional<AuthorizationRow> queryOne(String sql, Object... params) {
        try (Connection c = dataSource.getConnection();
                PreparedStatement ps = c.prepareStatement(sql)) {
            bind(ps, params);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return Optional.empty();
                }
                return Optional.of(new AuthorizationRow(
                        rs.getString("id"),
                        rs.getString("tenant_id"),
                        rs.getString("client_id"),
                        rs.getString("session_id"),
                        rs.getString("status"),
                        rs.getString("binding_hash"),
                        rs.getString("redirect_uri"),
                        rs.getString("state"),
                        rs.getString("nonce"),
                        rs.getString("code_challenge"),
                        rs.getString("error"),
                        rs.getBytes("code_ciphertext"),
                        instant(rs.getTimestamp("code_expires_at")),
                        rs.getBytes("claims_ciphertext"),
                        instant(rs.getTimestamp("auth_time")),
                        instant(rs.getTimestamp("expires_at"))));
            }
        } catch (SQLException e) {
            throw new StoreException(e);
        }
    }

    private static void bind(PreparedStatement ps, Object... params) throws SQLException {
        for (int i = 0; i < params.length; i++) {
            Object p = params[i];
            if (p instanceof byte[] bytes) {
                ps.setBytes(i + 1, bytes);
            } else if (p instanceof Timestamp t) {
                ps.setTimestamp(i + 1, t);
            } else if (p == null) {
                ps.setNull(i + 1, java.sql.Types.NULL);
            } else {
                ps.setString(i + 1, p.toString());
            }
        }
    }

    private static Timestamp ts(Instant instant) {
        return instant == null ? null : Timestamp.from(instant);
    }

    private static Instant instant(Timestamp t) {
        return t == null ? null : t.toInstant();
    }
}
