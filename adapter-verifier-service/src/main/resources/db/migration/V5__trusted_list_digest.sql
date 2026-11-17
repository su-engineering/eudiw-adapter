-- Content digest accepted under the highest sequence number, so a list that reuses the number with other content
-- is refused. Rows written before this column existed have no digest; the next accepted list fills it in.
ALTER TABLE trusted_list_sequence ADD COLUMN digest TEXT;
