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
import io.github.suengineering.eudiw.core.trust.TrustedLists;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;

/**
 * Keeps the highest accepted sequence number of each trusted list in PostgreSQL, shared by all nodes, so neither a
 * restart nor another node accepts an older list. A database error is reported as a refusal by the list loader.
 */
@ApplicationScoped
public class TrustedListSequenceStore implements TrustedLists.SequenceStore {

    @Inject
    AgroalDataSource dataSource;

    @Override
    public long highest(String identifier) {
        try (Connection c = dataSource.getConnection();
                PreparedStatement s =
                        c.prepareStatement("SELECT sequence FROM trusted_list_sequence WHERE identifier = ?")) {
            s.setString(1, identifier);
            try (ResultSet r = s.executeQuery()) {
                return r.next() ? r.getLong(1) : -1;
            }
        } catch (SQLException e) {
            throw new IllegalStateException("trusted list sequence unavailable", e);
        }
    }

    /**
     * One conditional upsert: the row is locked while the stored number is compared, so two nodes cannot both
     * accept against the same old value. No row is returned when a higher number is already stored.
     */
    @Override
    public boolean advance(String identifier, long sequenceNumber) {
        try (Connection c = dataSource.getConnection();
                PreparedStatement s = c.prepareStatement(
                        "INSERT INTO trusted_list_sequence (identifier, sequence, updated_at) VALUES (?, ?, ?) "
                                + "ON CONFLICT (identifier) DO UPDATE SET sequence = EXCLUDED.sequence, "
                                + "updated_at = EXCLUDED.updated_at "
                                + "WHERE trusted_list_sequence.sequence <= EXCLUDED.sequence RETURNING sequence")) {
            s.setString(1, identifier);
            s.setLong(2, sequenceNumber);
            s.setTimestamp(3, Timestamp.from(Instant.now()));
            try (ResultSet r = s.executeQuery()) {
                return r.next();
            }
        } catch (SQLException e) {
            throw new IllegalStateException("trusted list sequence unavailable", e);
        }
    }

    @Override
    public void record(String identifier, long sequenceNumber) {
        try (Connection c = dataSource.getConnection();
                PreparedStatement s = c.prepareStatement(
                        "INSERT INTO trusted_list_sequence (identifier, sequence, updated_at) VALUES (?, ?, ?) "
                                + "ON CONFLICT (identifier) DO UPDATE SET sequence = GREATEST(trusted_list_sequence.sequence, EXCLUDED.sequence), "
                                + "updated_at = EXCLUDED.updated_at")) {
            s.setString(1, identifier);
            s.setLong(2, sequenceNumber);
            s.setTimestamp(3, Timestamp.from(Instant.now()));
            s.executeUpdate();
        } catch (SQLException e) {
            throw new IllegalStateException("trusted list sequence unavailable", e);
        }
    }
}
