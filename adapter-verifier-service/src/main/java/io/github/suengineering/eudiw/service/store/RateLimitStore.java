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

/** Counts requests per client in one-minute windows in PostgreSQL, so the limit holds across replicas. */
@ApplicationScoped
public class RateLimitStore {

    @Inject
    AgroalDataSource dataSource;

    /** Adds one request to the client's current window and returns the window's count, including this one. */
    public int increment(String clientId, Instant windowStart) {
        String sql = "INSERT INTO rate_limit_window (client_id, window_start, count) VALUES (?, ?, 1)"
                + " ON CONFLICT (client_id, window_start) DO UPDATE SET count = rate_limit_window.count + 1"
                + " RETURNING count";
        try (Connection c = dataSource.getConnection();
                PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, clientId);
            ps.setTimestamp(2, Timestamp.from(windowStart));
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getInt(1);
            }
        } catch (SQLException e) {
            throw new SessionStore.StoreException(e);
        }
    }

    /** Deletes windows that ended before {@code before}. */
    public void sweep(Instant before) {
        try (Connection c = dataSource.getConnection();
                PreparedStatement ps = c.prepareStatement("DELETE FROM rate_limit_window WHERE window_start < ?")) {
            ps.setTimestamp(1, Timestamp.from(before));
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new SessionStore.StoreException(e);
        }
    }
}
