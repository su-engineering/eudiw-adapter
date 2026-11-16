-- Highest accepted sequence number per trusted list, so a restarted node refuses an older list.
CREATE TABLE trusted_list_sequence (
    identifier  TEXT        PRIMARY KEY,
    sequence    BIGINT      NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL
);
