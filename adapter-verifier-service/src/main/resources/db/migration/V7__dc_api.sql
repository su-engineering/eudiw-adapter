-- Sessions over the W3C Digital Credentials API (OpenID4VP 1.0 appendix A): a third mode, and the Origin the
-- browser calls the API from, which the presentation is bound to.
ALTER TABLE verification_session DROP CONSTRAINT verification_session_mode_check;
ALTER TABLE verification_session ADD CONSTRAINT verification_session_mode_check
    CHECK (mode IN ('same_device', 'cross_device', 'dc_api'));
ALTER TABLE verification_session ADD COLUMN dc_api_origin TEXT;
