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
package io.github.suengineering.eudiw.service.oidc;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.github.suengineering.eudiw.core.json.Json;
import io.github.suengineering.eudiw.core.oid4vp.AuthorizationRequests;
import io.github.suengineering.eudiw.service.api.ApiException;
import io.github.suengineering.eudiw.service.config.AdapterConfig;
import io.github.suengineering.eudiw.service.config.AdapterConfig.ClientBinding;
import io.github.suengineering.eudiw.service.config.AdapterConfig.OidcClient;
import io.github.suengineering.eudiw.service.config.AdapterConfig.Tenant;
import io.github.suengineering.eudiw.service.crypto.DataProtection;
import io.github.suengineering.eudiw.service.engine.AdapterRuntime;
import io.github.suengineering.eudiw.service.engine.AuditTrail;
import io.github.suengineering.eudiw.service.engine.VerificationEngine;
import io.github.suengineering.eudiw.service.store.OidcStore;
import io.github.suengineering.eudiw.service.store.OidcStore.AuthorizationRow;
import io.github.suengineering.eudiw.service.store.SessionStore.SessionRow;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * The tenant's OpenID Connect provider for wallet login (ADR-018): the authorization code flow only. Each
 * authorization runs one cross-device verification session; the browser that started it, identified by a cookie,
 * follows it and, once the wallet presentation is verified, receives the authorization code. The provider holds no
 * login session, so every authorization is a fresh wallet presentation.
 */
@ApplicationScoped
public class OidcProvider {

    static final Duration CODE_TTL = Duration.ofSeconds(60);
    static final Duration TOKEN_TTL = Duration.ofMinutes(5);
    private static final Pattern PKCE_VALUE = Pattern.compile("[A-Za-z0-9._~-]{43,128}");
    private static final int MAX_PARAMETER = 2048;

    @Inject
    AdapterRuntime runtime;

    @Inject
    VerificationEngine engine;

    @Inject
    OidcStore store;

    @Inject
    AuditTrail audit;

    /** An authorization request the provider cannot redirect back from: shown to the user as a page. */
    public static final class PageError extends RuntimeException {
        public final int status;

        PageError(int status, String message) {
            super(message);
            this.status = status;
        }
    }

    /** An OAuth error at the token or userinfo endpoint. */
    public static final class OAuthError extends RuntimeException {
        public final int status;
        public final String error;

        OAuthError(int status, String error, String description) {
            super(description);
            this.status = status;
            this.error = error;
        }
    }

    /**
     * What {@code /authorize} does next.
     *
     * @param redirect where to send the browser with an error, or null when the login page is shown
     * @param page the login page's data, when the request is valid
     */
    public record AuthorizeOutcome(URI redirect, LoginPage page) {}

    /**
     * @param attemptId identifies the authorization in the status URL
     * @param binding the random value for the browser's cookie; only its hash is stored
     */
    public record LoginPage(
            String tenantId,
            String attemptId,
            String binding,
            String launchUri,
            Instant expiresAt,
            String requestLabel,
            String clientId) {}

    public String issuer(String tenantId) {
        return runtime.publicBaseUrl().resolve("oidc/" + tenantId).toString();
    }

    Tenant tenant(String tenantId) {
        return runtime.config()
                .tenant(tenantId)
                .filter(t -> t.oidcProvider().isPresent())
                .orElseThrow(() -> new PageError(404, "This login provider does not exist."));
    }

    /** The OpenID Provider Metadata (OpenID Connect Discovery 1.0 section 3). */
    public Map<String, Object> discovery(String tenantId) {
        Tenant tenant = tenant(tenantId);
        String issuer = issuer(tenantId);
        Set<String> claims = new LinkedHashSet<>(List.of("sub", "iss", "aud", "exp", "iat", "auth_time", "nonce"));
        tenant.clients().values().stream()
                .flatMap(c -> c.oidc().stream())
                .forEach(c -> claims.addAll(c.idTokenClaims().keySet()));
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("issuer", issuer);
        m.put("authorization_endpoint", issuer + "/authorize");
        m.put("token_endpoint", issuer + "/token");
        m.put("userinfo_endpoint", issuer + "/userinfo");
        m.put("jwks_uri", issuer + "/jwks");
        m.put("response_types_supported", List.of("code"));
        m.put("response_modes_supported", List.of("query"));
        m.put("grant_types_supported", List.of("authorization_code"));
        m.put("subject_types_supported", List.of("pairwise"));
        m.put("id_token_signing_alg_values_supported", List.of("RS256"));
        m.put("scopes_supported", List.of("openid"));
        m.put("token_endpoint_auth_methods_supported", List.of("client_secret_basic", "client_secret_post"));
        m.put("code_challenge_methods_supported", List.of("S256"));
        m.put("claims_supported", List.copyOf(claims));
        m.put("claims_parameter_supported", false);
        m.put("request_parameter_supported", false);
        m.put("request_uri_parameter_supported", false);
        // RFC 9207: the authorization response names the issuer, against mix-up attacks.
        m.put("authorization_response_iss_parameter_supported", true);
        return m;
    }

    public Map<String, Object> jwks(String tenantId) {
        AdapterConfig.OidcProvider keys = tenant(tenantId).oidcProvider().orElseThrow();
        RSAKey jwk = new RSAKey.Builder(keys.publicKey())
                .keyID(keys.keyId())
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .build();
        return new JWKSet(jwk).toJSONObject(true);
    }

    /**
     * Validates an authorization request (OpenID Connect Core 1.0 section 3.1.2), then starts the wallet
     * presentation. An unknown client or redirect URI is a page; every later error goes back to the client.
     *
     * @param params every request parameter with all its values, to refuse repeated parameters
     */
    public AuthorizeOutcome authorize(String tenantId, Map<String, List<String>> params) {
        Tenant tenant = tenant(tenantId);
        String clientId = single(params, "client_id");
        String redirectUri = single(params, "redirect_uri");
        if (clientId == null) {
            throw new PageError(400, "The request does not name a client.");
        }
        ClientBinding binding = runtime.config()
                .client(clientId)
                .filter(b ->
                        b.tenant().id().equals(tenant.id()) && b.client().oidc().isPresent())
                .orElseThrow(() -> new PageError(400, "The application that sent you here is not registered."));
        OidcClient client = binding.client().oidc().orElseThrow();
        if (redirectUri == null || !client.redirectUris().contains(redirectUri)) {
            throw new PageError(400, "The application that sent you here gave an address that is not registered.");
        }
        String state;
        try {
            state = single(params, "state");
        } catch (PageError e) {
            return new AuthorizeOutcome(errorRedirect(tenant.id(), redirectUri, "invalid_request", null), null);
        }
        try {
            String responseType = single(params, "response_type");
            String scope = single(params, "scope");
            String responseMode = single(params, "response_mode");
            String nonce = single(params, "nonce");
            String prompt = single(params, "prompt");
            String challenge = single(params, "code_challenge");
            String challengeMethod = single(params, "code_challenge_method");
            if (params.containsKey("request")) {
                return new AuthorizeOutcome(
                        errorRedirect(tenant.id(), redirectUri, "request_not_supported", state), null);
            }
            if (params.containsKey("request_uri")) {
                return new AuthorizeOutcome(
                        errorRedirect(tenant.id(), redirectUri, "request_uri_not_supported", state), null);
            }
            if (params.containsKey("registration")) {
                return new AuthorizeOutcome(
                        errorRedirect(tenant.id(), redirectUri, "registration_not_supported", state), null);
            }
            if (!"code".equals(responseType)) {
                return new AuthorizeOutcome(
                        errorRedirect(tenant.id(), redirectUri, "unsupported_response_type", state), null);
            }
            if (scope == null || !List.of(scope.split(" ")).contains("openid")) {
                return new AuthorizeOutcome(errorRedirect(tenant.id(), redirectUri, "invalid_scope", state), null);
            }
            if (responseMode != null && !responseMode.equals("query")) {
                return new AuthorizeOutcome(errorRedirect(tenant.id(), redirectUri, "invalid_request", state), null);
            }
            if (prompt != null && List.of(prompt.split(" ")).contains("none")) {
                // No provider session: a login always needs the wallet.
                return new AuthorizeOutcome(errorRedirect(tenant.id(), redirectUri, "login_required", state), null);
            }
            if (challenge == null) {
                if (client.pkceRequired() || challengeMethod != null) {
                    return new AuthorizeOutcome(
                            errorRedirect(tenant.id(), redirectUri, "invalid_request", state), null);
                }
            } else if (!"S256".equals(challengeMethod)
                    || !PKCE_VALUE.matcher(challenge).matches()) {
                return new AuthorizeOutcome(errorRedirect(tenant.id(), redirectUri, "invalid_request", state), null);
            }

            String attemptId = AuthorizationRequests.randomValue();
            VerificationEngine.Created created;
            try {
                created = engine.create(
                        binding,
                        new VerificationEngine.CreateRequest(client.policyId(), "cross_device", null),
                        "oidc-" + attemptId);
            } catch (ApiException e) {
                String error = e.status() == 429 ? "temporarily_unavailable" : "server_error";
                return new AuthorizeOutcome(errorRedirect(tenant.id(), redirectUri, error, state), null);
            }
            String cookieValue = AuthorizationRequests.randomValue();
            Instant now = runtime.clock().instant();
            store.insert(
                    new AuthorizationRow(
                            attemptId,
                            tenant.id(),
                            clientId,
                            created.session().id(),
                            "pending",
                            DataProtection.hash(cookieValue),
                            redirectUri,
                            state,
                            nonce,
                            challenge,
                            null,
                            null,
                            null,
                            null,
                            null,
                            created.session().expiresAt()),
                    now);
            return new AuthorizeOutcome(
                    null,
                    new LoginPage(
                            tenant.id(),
                            attemptId,
                            cookieValue,
                            created.launchUri(),
                            created.session().expiresAt(),
                            "your identity",
                            clientId));
        } catch (PageError e) {
            return new AuthorizeOutcome(errorRedirect(tenant.id(), redirectUri, "invalid_request", state), null);
        }
    }

    /**
     * Where the login stands, for the page that started it. Once the presentation is verified, the first request to
     * see it consumes the result, derives the subject and issues the authorization code; this and later requests
     * from the same browser get the redirect to the client until the code expires.
     *
     * @param cookieValue the binding cookie, or null when the browser sent none
     * @return {@code status} as the {@code <eudiw-request>} component knows it, and {@code redirect} once the
     *     login has ended
     */
    public Map<String, Object> status(String tenantId, String attemptId, String cookieValue) {
        tenant(tenantId);
        AuthorizationRow row = store.find(tenantId, attemptId)
                .filter(r -> cookieValue != null
                        && MessageDigest.isEqual(
                                r.bindingHash().getBytes(StandardCharsets.US_ASCII),
                                DataProtection.hash(cookieValue).getBytes(StandardCharsets.US_ASCII)))
                .orElseThrow(() -> new PageError(404, "unknown login"));
        if (row.status().equals("pending")) {
            row = advance(row);
        }
        return switch (row.status()) {
            case "code_issued" -> Map.of("status", "verified", "redirect", codeRedirect(row));
            case "failed" ->
                Map.of(
                        "status",
                        "expired".equals(row.error()) ? "expired" : "rejected",
                        "redirect",
                        errorRedirect(row.tenantId(), row.redirectUri(), "access_denied", row.state())
                                .toString());
            case "redeemed", "revoked" -> Map.of("status", "expired");
            default -> Map.of("status", "pending");
        };
    }

    private AuthorizationRow advance(AuthorizationRow row) {
        Optional<ClientBinding> binding = runtime.config().client(row.clientId());
        if (binding.isEmpty() || binding.get().client().oidc().isEmpty()) {
            store.fail(row.tenantId(), row.id(), "client_removed");
            return reload(row);
        }
        SessionRow session = engine.status(binding.get(), row.sessionId());
        Instant now = runtime.clock().instant();
        switch (session.status()) {
            case "pending" -> {
                if (!now.isBefore(session.expiresAt())) {
                    fail(row, session, "expired", now);
                }
                return reload(row);
            }
            case "verified" -> {
                if (store.startCompleting(row.tenantId(), row.id())) {
                    complete(row, binding.get(), session, now);
                }
                return reload(row);
            }
            default -> {
                fail(row, session, session.status().equals("expired") ? "expired" : session.status(), now);
                return reload(row);
            }
        }
    }

    private void complete(AuthorizationRow row, ClientBinding binding, SessionRow session, Instant now) {
        OidcClient client = binding.client().oidc().orElseThrow();
        Map<String, Object> result;
        try {
            result = engine.result(binding, row.sessionId(), null);
        } catch (ApiException e) {
            fail(row, session, "result_not_available", now);
            return;
        }
        Map<?, ?> claims = result.get("claims") instanceof Map<?, ?> m ? m : Map.of();
        Optional<String> subject = subject(binding.tenant(), row.clientId(), client, claims);
        if (subject.isEmpty()) {
            fail(row, session, "subject_claims_missing", now);
            return;
        }
        Map<String, Object> idClaims = new LinkedHashMap<>();
        client.idTokenClaims().forEach((name, source) -> {
            Object value = claims.get(source);
            if (value != null) {
                idClaims.put(name, value);
            }
        });
        Instant authTime = session.completedAt() == null ? now : session.completedAt();
        Map<String, Object> stored = new LinkedHashMap<>();
        stored.put("sub", subject.get());
        stored.put("claims", idClaims);
        String code = AuthorizationRequests.randomValue();
        byte[] claimsCiphertext = runtime.dataProtection()
                .encrypt(
                        row.tenantId(),
                        "oidc-claims:" + row.id(),
                        Json.toJson(stored).getBytes(StandardCharsets.UTF_8));
        byte[] codeCiphertext = runtime.dataProtection()
                .encrypt(row.tenantId(), "oidc-code:" + row.id(), code.getBytes(StandardCharsets.US_ASCII));
        store.issueCode(
                row.tenantId(),
                row.id(),
                DataProtection.hash(code),
                codeCiphertext,
                now.plus(CODE_TTL),
                claimsCiphertext,
                authTime);
        audit.record(
                row.tenantId(),
                row.sessionId(),
                row.clientId(),
                session.policyId(),
                "oidc_code_issued",
                "ok",
                null,
                session.configRevision(),
                now);
    }

    private void fail(AuthorizationRow row, SessionRow session, String reason, Instant now) {
        store.fail(row.tenantId(), row.id(), reason);
        audit.record(
                row.tenantId(),
                row.sessionId(),
                row.clientId(),
                session.policyId(),
                "oidc_login_failed",
                "rejected",
                reason,
                session.configRevision(),
                now);
    }

    private AuthorizationRow reload(AuthorizationRow row) {
        return store.find(row.tenantId(), row.id()).orElse(row);
    }

    /**
     * The pairwise subject: HMAC-SHA256 under the tenant's subject key over the client id and the configured claims,
     * by name, in order. Empty when any of the claims is missing.
     */
    static Optional<String> subject(Tenant tenant, String clientId, OidcClient client, Map<?, ?> claims) {
        StringBuilder input =
                new StringBuilder("eudiw-oidc-sub\n").append(clientId).append('\n');
        for (String name : client.subjectClaims()) {
            Object value = claims.get(name);
            if (value == null || (value instanceof String s && s.isBlank())) {
                return Optional.empty();
            }
            input.append(name)
                    .append('=')
                    .append(Json.toJson(Map.of("v", value)))
                    .append('\n');
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(tenant.oidcProvider().orElseThrow().subjectKey(), "HmacSHA256"));
            byte[] digest = mac.doFinal(input.toString().getBytes(StandardCharsets.UTF_8));
            return Optional.of(Base64.getUrlEncoder().withoutPadding().encodeToString(digest));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * The link back to the client for a user who wants another way to sign in: the client receives
     * {@code access_denied}. The verification session is left to expire.
     */
    public URI cancelRedirect(String tenantId, String attemptId) {
        AuthorizationRow row = store.find(tenantId, attemptId).orElseThrow();
        return errorRedirect(row.tenantId(), row.redirectUri(), "access_denied", row.state());
    }

    private String codeRedirect(AuthorizationRow row) {
        String code = new String(
                runtime.dataProtection().decrypt(row.tenantId(), "oidc-code:" + row.id(), row.codeCiphertext()),
                StandardCharsets.US_ASCII);
        Map<String, String> params = new LinkedHashMap<>();
        params.put("code", code);
        if (row.state() != null) {
            params.put("state", row.state());
        }
        params.put("iss", issuer(row.tenantId()));
        return withQuery(row.redirectUri(), params).toString();
    }

    URI errorRedirect(String tenantId, String redirectUri, String error, String state) {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("error", error);
        if (state != null) {
            params.put("state", state);
        }
        params.put("iss", issuer(tenantId));
        return withQuery(redirectUri, params);
    }

    private static URI withQuery(String base, Map<String, String> params) {
        StringBuilder b = new StringBuilder(base);
        char sep = base.contains("?") ? '&' : '?';
        for (Map.Entry<String, String> e : params.entrySet()) {
            b.append(sep)
                    .append(e.getKey())
                    .append('=')
                    .append(URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8));
            sep = '&';
        }
        return URI.create(b.toString());
    }

    /**
     * The token request (OpenID Connect Core 1.0 section 3.1.3): client authentication, then the code, redirect URI
     * and PKCE verifier are checked before the code is redeemed. A code presented after it was redeemed revokes the
     * access token it produced.
     *
     * @param basicAuthorization the {@code Authorization} header, or null
     */
    public Map<String, Object> token(String tenantId, String basicAuthorization, Map<String, List<String>> form) {
        Tenant tenant;
        try {
            tenant = tenant(tenantId);
        } catch (PageError e) {
            throw new OAuthError(404, "invalid_request", "unknown issuer");
        }
        String clientId = formValue(form, "client_id");
        String secret = formValue(form, "client_secret");
        boolean basic = basicAuthorization != null && basicAuthorization.regionMatches(true, 0, "Basic ", 0, 6);
        if (basic) {
            if (secret != null) {
                throw new OAuthError(400, "invalid_request", "use one client authentication method");
            }
            String decoded;
            try {
                decoded = new String(
                        Base64.getDecoder()
                                .decode(basicAuthorization.substring(6).strip()),
                        StandardCharsets.UTF_8);
            } catch (IllegalArgumentException e) {
                throw new OAuthError(401, "invalid_client", "malformed client authentication");
            }
            int colon = decoded.indexOf(':');
            if (colon < 0) {
                throw new OAuthError(401, "invalid_client", "malformed client authentication");
            }
            String headerClient = java.net.URLDecoder.decode(decoded.substring(0, colon), StandardCharsets.UTF_8);
            if (clientId != null && !clientId.equals(headerClient)) {
                throw new OAuthError(400, "invalid_request", "client_id does not match the authenticated client");
            }
            clientId = headerClient;
            secret = java.net.URLDecoder.decode(decoded.substring(colon + 1), StandardCharsets.UTF_8);
        }
        final String authenticatedId = clientId;
        OidcClient client = authenticatedId == null || secret == null
                ? null
                : runtime.config()
                        .client(authenticatedId)
                        .filter(b -> b.tenant().id().equals(tenant.id()))
                        .flatMap(b -> b.client().oidc())
                        .orElse(null);
        if (client == null || !secretMatches(client.secret(), secret)) {
            throw new OAuthError(401, "invalid_client", "client authentication failed");
        }
        if (!"authorization_code".equals(formValue(form, "grant_type"))) {
            throw new OAuthError(400, "unsupported_grant_type", "only authorization_code is supported");
        }
        String code = formValue(form, "code");
        if (code == null) {
            throw new OAuthError(400, "invalid_request", "code is required");
        }
        String codeHash = DataProtection.hash(code);
        Instant now = runtime.clock().instant();
        AuthorizationRow row = store.findByCode(tenantId, codeHash).orElse(null);
        if (row == null || !row.status().equals("code_issued") || !now.isBefore(row.codeExpiresAt())) {
            if (row != null && store.revokeRedeemed(tenantId, codeHash)) {
                audit.record(
                        tenantId,
                        row.sessionId(),
                        row.clientId(),
                        null,
                        "oidc_code_replayed",
                        "rejected",
                        "code_reused",
                        null,
                        now);
            }
            throw new OAuthError(400, "invalid_grant", "the code is not valid");
        }
        if (!row.clientId().equals(authenticatedId)
                || !row.redirectUri().equals(formValue(form, "redirect_uri"))
                || !pkceMatches(row.codeChallenge(), formValue(form, "code_verifier"))) {
            throw new OAuthError(400, "invalid_grant", "the code is not valid for this request");
        }
        String accessToken = AuthorizationRequests.randomValue();
        Instant accessExpires = now.plus(TOKEN_TTL);
        AuthorizationRow redeemed = store.redeem(
                        tenantId, codeHash, now, DataProtection.hash(accessToken), accessExpires)
                .orElseThrow(() -> new OAuthError(400, "invalid_grant", "the code is not valid"));
        Map<?, ?> stored = claims(redeemed);
        String idToken = idToken(tenant, redeemed, stored, now);
        audit.record(
                tenantId, redeemed.sessionId(), redeemed.clientId(), null, "oidc_token_issued", "ok", null, null, now);
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("access_token", accessToken);
        response.put("token_type", "Bearer");
        response.put("expires_in", TOKEN_TTL.toSeconds());
        response.put("id_token", idToken);
        response.put("scope", "openid");
        return response;
    }

    /** The userinfo response (OpenID Connect Core 1.0 section 5.3): the same claims as the ID token. */
    public Map<String, Object> userinfo(String tenantId, String bearer) {
        try {
            tenant(tenantId);
        } catch (PageError e) {
            throw new OAuthError(404, "invalid_request", "unknown issuer");
        }
        if (bearer == null) {
            throw new OAuthError(401, "invalid_token", "a bearer token is required");
        }
        AuthorizationRow row = store.byAccessToken(
                        tenantId, DataProtection.hash(bearer), runtime.clock().instant())
                .orElseThrow(() -> new OAuthError(401, "invalid_token", "the access token is not valid"));
        Map<?, ?> stored = claims(row);
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("sub", stored.get("sub"));
        if (stored.get("claims") instanceof Map<?, ?> c) {
            c.forEach((k, v) -> response.put(String.valueOf(k), v));
        }
        return response;
    }

    private Map<?, ?> claims(AuthorizationRow row) {
        return Json.parseObject(
                new String(
                        runtime.dataProtection()
                                .decrypt(row.tenantId(), "oidc-claims:" + row.id(), row.claimsCiphertext()),
                        StandardCharsets.UTF_8),
                "internal");
    }

    private String idToken(Tenant tenant, AuthorizationRow row, Map<?, ?> stored, Instant now) {
        AdapterConfig.OidcProvider keys = tenant.oidcProvider().orElseThrow();
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .issuer(issuer(tenant.id()))
                .subject(String.valueOf(stored.get("sub")))
                .audience(row.clientId())
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(TOKEN_TTL)))
                .claim("auth_time", row.authTime().getEpochSecond());
        if (row.nonce() != null) {
            claims.claim("nonce", row.nonce());
        }
        if (stored.get("claims") instanceof Map<?, ?> c) {
            c.forEach((k, v) -> claims.claim(String.valueOf(k), v));
        }
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(keys.keyId())
                        .type(JOSEObjectType.JWT)
                        .build(),
                claims.build());
        try {
            jwt.sign(new RSASSASigner(keys.signingKey()));
        } catch (JOSEException e) {
            throw new IllegalStateException("ID token signing failed", e);
        }
        return jwt.serialize();
    }

    static boolean secretMatches(byte[] expected, String presented) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            byte[] a = sha.digest(expected);
            byte[] b = MessageDigest.getInstance("SHA-256").digest(presented.getBytes(StandardCharsets.US_ASCII));
            return MessageDigest.isEqual(a, b);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** RFC 7636: with a challenge, the verifier must match it; without one, a verifier is refused (downgrade). */
    static boolean pkceMatches(String challenge, String verifier) {
        if (challenge == null) {
            return verifier == null;
        }
        if (verifier == null || !PKCE_VALUE.matcher(verifier).matches()) {
            return false;
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
            String computed = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
            return MessageDigest.isEqual(
                    computed.getBytes(StandardCharsets.US_ASCII), challenge.getBytes(StandardCharsets.US_ASCII));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * One value of a parameter. A repeated parameter is an error (RFC 6749 section 3.1); an oversized one too. The
     * caller decides whether that error is a page or goes back to the client.
     */
    private static String single(Map<String, List<String>> params, String name) {
        List<String> values = params.get(name);
        if (values == null || values.isEmpty()) {
            return null;
        }
        if (values.size() > 1 || values.get(0).length() > MAX_PARAMETER) {
            throw new PageError(400, "The request repeats or oversizes " + name + ".");
        }
        String value = values.get(0);
        return value.isEmpty() ? null : value;
    }

    private static String formValue(Map<String, List<String>> form, String name) {
        List<String> values = form.get(name);
        if (values == null || values.isEmpty()) {
            return null;
        }
        if (values.size() > 1) {
            throw new OAuthError(400, "invalid_request", "repeated parameter " + name);
        }
        String value = values.get(0);
        return value == null || value.isEmpty() ? null : value;
    }
}
