-- The transaction_data a client sent with a session (OpenID4VP 1.0 section 5.1), encrypted with the data key. It is
-- needed while the session is pending, to build request objects and check the Key Binding JWT, and is cleared when
-- the session ends: the result keeps the confirmed copy.
ALTER TABLE verification_session ADD COLUMN transaction_data_ciphertext BYTEA;
