-- Per-client request counts in fixed one-minute windows, shared by every node. Old windows are swept.
CREATE TABLE rate_limit_window (
    client_id    TEXT        NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    count        INTEGER     NOT NULL,
    PRIMARY KEY (client_id, window_start)
);
