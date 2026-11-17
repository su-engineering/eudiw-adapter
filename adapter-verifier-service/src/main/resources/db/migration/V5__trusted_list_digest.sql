-- Content digest accepted under a sequence number, so a list that reuses the number with other content is refused.
-- digest_sequence is the number the digest was recorded for. A digest counts only while that is still the stored
-- sequence: a row whose number was raised without a digest (by a node of an earlier version, or a path that keeps
-- no digest) takes the next digest offered instead of refusing it. Rows written before these columns existed have
-- no digest and take the first one offered.
ALTER TABLE trusted_list_sequence ADD COLUMN digest TEXT;
ALTER TABLE trusted_list_sequence ADD COLUMN digest_sequence BIGINT;
