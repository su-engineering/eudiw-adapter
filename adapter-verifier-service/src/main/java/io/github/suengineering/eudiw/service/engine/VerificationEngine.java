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
package io.github.suengineering.eudiw.service.engine;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import io.github.suengineering.eudiw.core.ConformanceWarning;
import io.github.suengineering.eudiw.core.VerificationFailure;
import io.github.suengineering.eudiw.core.dcql.DcqlEvaluator.DisclosedClaim;
import io.github.suengineering.eudiw.core.dcql.DcqlEvaluator.SelectedCredential;
import io.github.suengineering.eudiw.core.json.Json;
import io.github.suengineering.eudiw.core.oid4vp.AuthorizationRequests;
import io.github.suengineering.eudiw.core.oid4vp.AuthorizationResponses;
import io.github.suengineering.eudiw.core.oid4vp.VpTokenVerifier;
import io.github.suengineering.eudiw.service.api.ApiException;
import io.github.suengineering.eudiw.service.config.AdapterConfig.ClientBinding;
import io.github.suengineering.eudiw.service.config.AdapterConfig.OutputClaim;
import io.github.suengineering.eudiw.service.config.AdapterConfig.Policy;
import io.github.suengineering.eudiw.service.config.AdapterConfig.Tenant;
import io.github.suengineering.eudiw.service.crypto.DataProtection;
import io.github.suengineering.eudiw.service.store.SessionStore;
import io.github.suengineering.eudiw.service.store.SessionStore.InstanceRow;
import io.github.suengineering.eudiw.service.store.SessionStore.SessionRow;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import org.jboss.logging.Logger;

/**
 * The verification session lifecycle: creation by an authenticated client, the wallet fetching a freshly signed
 * request, the wallet posting its encrypted response, and one-time retrieval of the minimized result.
 */
@ApplicationScoped
public class VerificationEngine {

    private static final Logger LOG = Logger.getLogger(VerificationEngine.class);
    private static final Pattern CLIENT_REFERENCE = Pattern.compile("[A-Za-z0-9._:-]{1,128}");
    private static final Pattern IDEMPOTENCY_KEY = Pattern.compile("[A-Za-z0-9._-]{8,128}");
    private static final Pattern HANDLE = Pattern.compile("[A-Za-z0-9_-]{43}");
    /** A wallet fetches the request once or twice; more means the request is being replayed. */
    static final int MAX_REQUEST_FETCHES = 5;

    @Inject
    AdapterRuntime runtime;

    @Inject
    SessionStore store;

    @Inject
    AuditTrail audit;

    @Inject
    io.github.suengineering.eudiw.service.store.RateLimitStore rateLimits;

    @Inject
    io.micrometer.core.instrument.MeterRegistry registry;

    /**
     * Requests per minute that one source address may make to the wallet endpoints, counted across nodes; 0 turns
     * the limit off. The address is the one Quarkus resolves: behind a proxy, enable proxy address forwarding, or
     * every wallet shares the proxy's address.
     */
    @org.eclipse.microprofile.config.inject.ConfigProperty(
            name = "eudiw.wallet.requests-per-minute",
            defaultValue = "0")
    int walletRequestsPerMinute;

    public record CreateRequest(String policyId, String mode, String clientReference) {}

    public record Created(SessionRow session, String requestUri, String launchUri) {}

    public Created create(ClientBinding caller, CreateRequest request, String idempotencyKey) {
        if (idempotencyKey == null || !IDEMPOTENCY_KEY.matcher(idempotencyKey).matches()) {
            throw new ApiException(
                    400, "invalid_idempotency_key", "Idempotency-Key header is required (8 to 128 safe characters)");
        }
        if (request == null || request.policyId() == null) {
            throw new ApiException(400, "invalid_request", "policy_id is required");
        }
        Tenant tenant = caller.tenant();
        if (!caller.client().policies().contains(request.policyId())) {
            throw new ApiException(403, "policy_not_granted", "the client may not use this policy");
        }
        enforceRateLimit(caller);
        Policy policy = tenant.policies().get(request.policyId());
        String mode = request.mode() == null ? "cross_device" : request.mode();
        if (!mode.equals("cross_device") && !mode.equals("same_device")) {
            throw new ApiException(400, "invalid_request", "mode must be same_device or cross_device");
        }
        if (mode.equals("same_device") && caller.client().completionUri().isEmpty()) {
            throw new ApiException(400, "same_device_not_configured", "the client has no registered completion_uri");
        }
        if (request.clientReference() != null
                && !CLIENT_REFERENCE.matcher(request.clientReference()).matches()) {
            throw new ApiException(400, "invalid_request", "client_reference must be 1 to 128 safe characters");
        }

        Instant now = runtime.clock().instant();
        String fingerprint = DataProtection.hash(request.policyId() + "\n" + mode + "\n" + request.clientReference());
        SessionRow candidate = new SessionRow(
                "vrs_" + AuthorizationRequests.randomValue(),
                tenant.id(),
                caller.client().clientId(),
                policy.id(),
                caller.revision(),
                mode,
                "pending",
                AuthorizationRequests.randomValue(),
                fingerprint,
                request.clientReference(),
                null,
                false,
                now,
                now.plus(policy.sessionTtl()),
                null);
        SessionRow stored = store.insertOrGetIdempotent(candidate, DataProtection.hash(idempotencyKey));
        if (!stored.requestFingerprint().equals(fingerprint)) {
            throw new ApiException(
                    422, "idempotency_key_reused", "the Idempotency-Key was used for a different request");
        }
        if (stored.id().equals(candidate.id())) {
            audit.record(
                    tenant.id(),
                    stored.id(),
                    stored.clientId(),
                    stored.policyId(),
                    "session_created",
                    "ok",
                    null,
                    stored.configRevision(),
                    now);
        }
        String requestUri = requestUri(stored.requestHandle());
        String launch = AuthorizationRequests.walletInvocationUri(
                tenant.walletInvocation(), tenant.verifier().clientId(), URI.create(requestUri));
        return new Created(stored, requestUri, launch);
    }

    /**
     * Counts this creation in the client's current one-minute window, shared by every node, and refuses it with
     * 429 and {@code Retry-After} once the window is full.
     */
    private void enforceRateLimit(ClientBinding caller) {
        Instant now = runtime.clock().instant();
        Instant window = now.truncatedTo(java.time.temporal.ChronoUnit.MINUTES);
        int count = rateLimits.increment(caller.client().clientId(), window);
        if (count > caller.client().sessionsPerMinute()) {
            registry.counter(
                            "eudiw.rate.limited",
                            "tenant",
                            caller.tenant().id(),
                            "client",
                            caller.client().clientId())
                    .increment();
            long retryAfter = Math.max(
                    1, java.time.Duration.between(now, window.plusSeconds(60)).toSeconds());
            throw new ApiException(
                    429, "rate_limited", "too many sessions created by this client; retry later", retryAfter);
        }
    }

    /**
     * Counts one wallet request from {@code address} in its current one-minute window.
     *
     * @return seconds until the window ends when the address is over its limit, or empty when the request may go on
     */
    public Optional<Long> walletRequestRefused(String address) {
        int limit = walletRequestsPerMinute;
        if (limit <= 0) {
            return Optional.empty();
        }
        Instant now = runtime.clock().instant();
        Instant window = now.truncatedTo(java.time.temporal.ChronoUnit.MINUTES);
        // The space keeps these keys apart from client ids, which cannot contain one.
        if (rateLimits.increment("wallet " + sourceKey(address), window) <= limit) {
            return Optional.empty();
        }
        registry.counter("eudiw.wallet.rate.limited").increment();
        return Optional.of(Math.max(
                1, java.time.Duration.between(now, window.plusSeconds(60)).toSeconds()));
    }

    /**
     * IPv4 addresses count alone; IPv6 addresses count by their /64, which one host usually holds whole. Anything
     * that is not an address (none known, or a forwarded value such as {@code unknown} or an obfuscated identifier)
     * shares one bucket, so a client cannot pick a fresh key for every request.
     */
    static String sourceKey(String address) {
        if (address == null || !address.matches("\\d{1,3}(\\.\\d{1,3}){3}|[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*")) {
            return "unparsed"; // never a host name: getByName below must not resolve anything
        }
        try {
            java.net.InetAddress parsed = java.net.InetAddress.getByName(address);
            if (parsed instanceof java.net.Inet6Address) {
                byte[] prefix = java.util.Arrays.copyOf(parsed.getAddress(), 16);
                java.util.Arrays.fill(prefix, 8, 16, (byte) 0);
                return java.net.InetAddress.getByAddress(prefix).getHostAddress() + "/64";
            }
            return parsed.getHostAddress();
        } catch (IllegalArgumentException | java.net.UnknownHostException e) {
            return "unparsed";
        }
    }

    /** For tests: changes the wallet request limit, 0 for none. */
    public void limitWalletRequestsForTests(int perMinute) {
        walletRequestsPerMinute = perMinute;
    }

    public SessionRow status(ClientBinding caller, String id) {
        return store.find(caller.tenant().id(), caller.client().clientId(), id).orElseThrow(ApiException::notFound);
    }

    public void cancel(ClientBinding caller, String id) {
        SessionRow session = status(caller, id);
        Instant now = runtime.clock().instant();
        if (store.cancel(caller.tenant().id(), caller.client().clientId(), id, now)) {
            audit.record(
                    session.tenantId(),
                    id,
                    session.clientId(),
                    session.policyId(),
                    "session_cancelled",
                    "ok",
                    null,
                    session.configRevision(),
                    now);
        }
    }

    /** Returns the minimized result once; same-device sessions also need the response code from the redirect. */
    public Map<String, Object> result(ClientBinding caller, String id, String responseCode) {
        SessionRow session = status(caller, id);
        Instant now = runtime.clock().instant();
        if (session.mode().equals("same_device") && (responseCode == null || responseCode.isEmpty())) {
            throw new ApiException(400, "response_code_required", "same-device sessions require the response_code");
        }
        String codeHash = responseCode == null ? null : DataProtection.hash(responseCode);
        // Decrypting and the audit row share the transaction that consumes the result: if either fails, the result
        // stays available for the next attempt.
        Map<String, Object> result = store.consumeResult(
                        caller.tenant().id(),
                        caller.client().clientId(),
                        id,
                        codeHash,
                        now,
                        ciphertext -> Json.parseObject(
                                new String(
                                        runtime.dataProtection()
                                                .decrypt(session.tenantId(), "result:" + id, ciphertext),
                                        StandardCharsets.UTF_8),
                                "internal"),
                        new SessionStore.AuditEvent(
                                session.tenantId(),
                                id,
                                session.clientId(),
                                "result_retrieved",
                                "ok",
                                null,
                                session.configRevision(),
                                now))
                .orElseThrow(
                        () -> new ApiException(404, "result_not_available", "no result is available for this session"));
        audit.announce(
                session.tenantId(),
                id,
                session.clientId(),
                session.policyId(),
                "result_retrieved",
                "ok",
                null,
                session.configRevision(),
                now);
        return result;
    }

    /**
     * Builds a fresh signed request for the wallet. Every fetch gets its own nonce, state and encryption key.
     *
     * @return the signed Request Object, or empty when the handle is unknown or the session is no longer pending
     */
    public Optional<String> requestObject(String handle, String walletNonce) {
        if (handle == null || !HANDLE.matcher(handle).matches()) {
            return Optional.empty();
        }
        Instant now = runtime.clock().instant();
        Optional<SessionRow> found = store.findByHandle(handle);
        if (found.isEmpty()
                || !found.get().status().equals("pending")
                || !now.isBefore(found.get().expiresAt())) {
            return Optional.empty();
        }
        SessionRow session = found.get();
        Optional<Tenant> sessionTenant = sessionTenant(session);
        if (sessionTenant.isEmpty()) {
            // This node no longer holds the configuration the session started under; never serve other rules.
            return Optional.empty();
        }
        Tenant tenant = sessionTenant.get();
        Policy policy = tenant.policies().get(session.policyId());
        ECKey key = AuthorizationRequests.newResponseEncryptionKey();
        String state = AuthorizationRequests.randomValue();
        String nonce = AuthorizationRequests.randomValue();
        byte[] keyCiphertext = runtime.dataProtection()
                .encrypt(
                        session.tenantId(),
                        "request-key:" + key.getKeyID(),
                        key.toJSONString().getBytes(StandardCharsets.UTF_8));
        boolean stored = store.insertInstance(
                new InstanceRow(
                        key.getKeyID(),
                        session.id(),
                        session.tenantId(),
                        state,
                        nonce,
                        keyCiphertext,
                        session.expiresAt(),
                        null),
                now,
                MAX_REQUEST_FETCHES);
        if (!stored) {
            audit.record(
                    session.tenantId(),
                    session.id(),
                    session.clientId(),
                    session.policyId(),
                    "request_fetched",
                    "refused",
                    "fetch_limit",
                    session.configRevision(),
                    now);
            return Optional.empty();
        }
        String walletNonceValue = walletNonce != null && walletNonce.length() <= 256 ? walletNonce : null;
        return Optional.of(AuthorizationRequests.signRequestObject(
                tenant.verifier(),
                new AuthorizationRequests.Parameters(
                        responseUri(),
                        nonce,
                        state,
                        policy.query(),
                        key,
                        walletNonceValue,
                        java.time.Duration.between(now, session.expiresAt()),
                        policy.registration().map(r -> r.verifierInfo(now)).orElse(List.of())),
                now));
    }

    /** The JSON body returned to the wallet after it posts to the Response URI. */
    public record WalletReply(int status, Map<String, Object> body) {}

    public WalletReply handleResponse(Map<String, String> form) {
        Instant now = runtime.clock().instant();
        String response = form.get("response");
        if (response != null) {
            return handleEncrypted(response, now);
        }
        String error = form.get("error");
        String state = form.get("state");
        if (error != null && state != null) {
            return handleWalletError(error, state, now);
        }
        return new WalletReply(400, Map.of("error", "invalid_request"));
    }

    private WalletReply handleEncrypted(String response, Instant now) {
        String kid;
        try {
            kid = AuthorizationResponses.keyId(response);
        } catch (VerificationFailure f) {
            return new WalletReply(400, Map.of("error", "invalid_request"));
        }
        Optional<InstanceRow> instance = store.findInstanceByKid(kid);
        if (instance.isEmpty()) {
            return new WalletReply(400, Map.of("error", "invalid_request"));
        }
        InstanceRow row = instance.get();
        SessionRow session = store.findById(row.sessionId()).orElseThrow();
        // Cheap checks first: a used request instance, or a session that is finished or past its expiry, never
        // reaches decryption or credential verification. Expiry is enforced again when the session completes.
        // Anyone who holds the response can repeat it without authentication, so only the first refusal per request
        // instance writes an audit row: it uses the instance up, and later repeats are only counted. A session has at
        // most five instances, so it gets at most five such rows.
        if (row.consumedAt() != null) {
            registry.counter("eudiw.wallet.response.ignored", "code", "request_already_used")
                    .increment();
            return new WalletReply(400, Map.of("error", "invalid_request"));
        }
        if (!session.status().equals("pending") || !now.isBefore(session.expiresAt())) {
            if (store.consumeInstance(kid, now)) {
                audit.record(
                        session.tenantId(),
                        session.id(),
                        session.clientId(),
                        session.policyId(),
                        "response_received",
                        "ignored",
                        "session_not_pending",
                        session.configRevision(),
                        now);
            }
            registry.counter("eudiw.wallet.response.ignored", "code", "session_not_pending")
                    .increment();
            return new WalletReply(400, Map.of("error", "invalid_request"));
        }
        Optional<Tenant> sessionTenant = sessionTenant(session);
        if (sessionTenant.isEmpty()) {
            // Never verify under rules other than those the session started with.
            store.consumeInstance(kid, now);
            store.complete(
                    session.id(),
                    "rejected",
                    "configuration_changed",
                    null,
                    null,
                    null,
                    now,
                    runtime.notifies(session.tenantId(), session.clientId()));
            return new WalletReply(400, Map.of("error", "invalid_request"));
        }
        Tenant tenant = sessionTenant.get();
        Policy policy = tenant.policies().get(session.policyId());

        Map<String, Object> payload;
        byte[] keyThumbprint;
        try {
            ECKey key = (ECKey) JWK.parse(new String(
                    runtime.dataProtection().decrypt(session.tenantId(), "request-key:" + kid, row.keyCiphertext()),
                    StandardCharsets.UTF_8));
            payload = AuthorizationResponses.decrypt(response, key);
            keyThumbprint = key.toPublicJWK().computeThumbprint("SHA-256").decode();
        } catch (VerificationFailure
                | ParseException
                | ClassCastException
                | IllegalStateException
                | com.nimbusds.jose.JOSEException e) {
            // IllegalStateException: the request key does not decrypt, for example because the data key that wrote
            // it was removed. The wallet gets the same answer as for any response that cannot be read.
            return new WalletReply(400, Map.of("error", "invalid_request"));
        }
        if (!row.state().equals(payload.get("state"))) {
            return new WalletReply(400, Map.of("error", "invalid_request"));
        }
        // One response per request instance, whatever its outcome.
        if (!store.consumeInstance(kid, now)) {
            return new WalletReply(400, Map.of("error", "invalid_request"));
        }

        if (payload.get("error") instanceof String walletError) {
            return finish(
                    session,
                    tenant,
                    policy,
                    walletError.equals("access_denied") ? "denied" : "rejected",
                    walletError.equals("access_denied") ? "wallet_denied" : "wallet_error",
                    null,
                    now);
        }
        io.micrometer.core.instrument.Timer.Sample timing = io.micrometer.core.instrument.Timer.start(registry);
        String outcome = "internal_error";
        try {
            VpTokenVerifier.Result result = runtime.verifier(
                            session.configRevision(), session.tenantId(), session.policyId())
                    .verify(
                            payload.get("vp_token"),
                            policy.query(),
                            new VpTokenVerifier.Context(
                                    tenant.verifier().clientId(),
                                    row.nonce(),
                                    session.tenantId() + "/" + session.policyId() + "/" + session.configRevision(),
                                    responseUri().toString(),
                                    java.util.Optional.of(keyThumbprint)));
            for (List<SelectedCredential> credentials : result.credentials().values()) {
                for (SelectedCredential credential : credentials) {
                    if (!policy.allowedIssuers().isEmpty() && !credential.issuerIn(policy.allowedIssuers())) {
                        throw new VerificationFailure("issuer_not_allowed", "issuer not allowed by policy");
                    }
                }
            }
            List<ConformanceWarning> warnings = new ArrayList<>();
            result.credentials().values().forEach(list -> list.forEach(c -> warnings.addAll(c.warnings())));
            outcome = "verified";
            return finish(
                    session,
                    tenant,
                    policy,
                    "verified",
                    null,
                    buildResult(session, policy, result, now),
                    now,
                    warnings);
        } catch (VerificationFailure failure) {
            outcome = "rejected";
            return rejectPresentation(finish(session, tenant, policy, "rejected", failure.code(), null, now), session);
        } catch (RuntimeException e) {
            // The request instance is already used; leave no session pending after an unexpected error.
            LOG.errorf(
                    "session %s: unexpected %s during verification",
                    session.id(), e.getClass().getName());
            return finish(session, tenant, policy, "rejected", "internal_error", null, now);
        } finally {
            timing.stop(registry.timer(
                    "eudiw.presentation.verification",
                    "tenant",
                    session.tenantId(),
                    "policy",
                    session.policyId(),
                    "outcome",
                    outcome));
        }
    }

    /**
     * A presentation that fails verification is answered with 400 in cross-device sessions, so the wallet can tell
     * the user (OpenID4VP 1.0 section 8.2 lets the response endpoint reject). Same-device sessions keep the 200
     * with {@code redirect_uri}, so the user returns to the application, which then sees {@code rejected}.
     */
    private static WalletReply rejectPresentation(WalletReply reply, SessionRow session) {
        if (reply.status() != 200 || session.mode().equals("same_device")) {
            return reply;
        }
        return new WalletReply(400, Map.of("error", "invalid_request"));
    }

    /**
     * The tenant as configured when the session started, if this node still holds that configuration and it has
     * the session's policy and client. A reload keeps the replaced configuration for the longest session lifetime.
     */
    private Optional<Tenant> sessionTenant(SessionRow session) {
        return runtime.config(session.configRevision())
                .flatMap(c -> c.tenant(session.tenantId()))
                .filter(t -> t.policies().containsKey(session.policyId())
                        && t.clients().containsKey(session.clientId()));
    }

    private WalletReply handleWalletError(String error, String state, Instant now) {
        Optional<InstanceRow> instance = store.findInstanceByState(state);
        if (instance.isEmpty() || !store.consumeInstance(instance.get().kid(), now)) {
            return new WalletReply(400, Map.of("error", "invalid_request"));
        }
        SessionRow session = store.findById(instance.get().sessionId()).orElseThrow();
        Optional<Tenant> sessionTenant = sessionTenant(session);
        if (sessionTenant.isEmpty()) {
            store.complete(
                    session.id(),
                    "rejected",
                    "configuration_changed",
                    null,
                    null,
                    null,
                    now,
                    runtime.notifies(session.tenantId(), session.clientId()));
            return new WalletReply(400, Map.of("error", "invalid_request"));
        }
        Tenant tenant = sessionTenant.get();
        boolean denied = "access_denied".equals(error);
        return finish(
                session,
                tenant,
                tenant.policies().get(session.policyId()),
                denied ? "denied" : "rejected",
                denied ? "wallet_denied" : "wallet_error",
                null,
                now);
    }

    private WalletReply finish(
            SessionRow session,
            Tenant tenant,
            Policy policy,
            String status,
            String code,
            Map<String, Object> result,
            Instant now) {
        return finish(session, tenant, policy, status, code, result, now, List.of());
    }

    /**
     * @param warnings tolerated departures from a standard, recorded one audit event each (without claims) only when
     *     this response completes the session
     */
    private WalletReply finish(
            SessionRow session,
            Tenant tenant,
            Policy policy,
            String status,
            String code,
            Map<String, Object> result,
            Instant now,
            List<ConformanceWarning> warnings) {
        String responseCode = session.mode().equals("same_device") ? AuthorizationRequests.randomValue() : null;
        byte[] ciphertext = result == null
                ? null
                : runtime.dataProtection()
                        .encrypt(
                                session.tenantId(),
                                "result:" + session.id(),
                                Json.toJson(result).getBytes(StandardCharsets.UTF_8));
        boolean completed = store.complete(
                session.id(),
                status,
                code,
                ciphertext,
                responseCode == null ? null : DataProtection.hash(responseCode),
                result == null ? null : now.plus(policy.resultTtl()),
                now,
                runtime.notifies(session.tenantId(), session.clientId()));
        if (!completed) {
            audit.record(
                    session.tenantId(),
                    session.id(),
                    session.clientId(),
                    session.policyId(),
                    "response_received",
                    "ignored",
                    "session_not_pending",
                    session.configRevision(),
                    now);
            return new WalletReply(400, Map.of("error", "invalid_request"));
        }
        audit.record(
                session.tenantId(),
                session.id(),
                session.clientId(),
                session.policyId(),
                "response_received",
                status,
                code,
                session.configRevision(),
                now);
        for (ConformanceWarning warning : warnings) {
            audit.record(
                    session.tenantId(),
                    session.id(),
                    session.clientId(),
                    session.policyId(),
                    "conformance_warning",
                    "accepted",
                    warning.code(),
                    session.configRevision(),
                    now);
        }
        LOG.infof("session %s completed: %s %s", session.id(), status, code == null ? "" : code);
        Map<String, Object> body = new LinkedHashMap<>();
        if (responseCode != null) {
            URI completion =
                    tenant.clients().get(session.clientId()).completionUri().orElseThrow();
            body.put("redirect_uri", completion + "#response_code=" + responseCode);
        }
        return new WalletReply(200, body);
    }

    private static Map<String, Object> buildResult(
            SessionRow session, Policy policy, VpTokenVerifier.Result result, Instant now) {
        Map<String, Object> claims = new LinkedHashMap<>();
        for (Map.Entry<String, OutputClaim> output : policy.output().entrySet()) {
            List<SelectedCredential> credentials =
                    result.credentials().get(output.getValue().credentialId());
            if (credentials == null) {
                continue; // optional credential set not presented
            }
            for (DisclosedClaim claim : credentials.get(0).claims()) {
                if (claim.path().equals(output.getValue().path())) {
                    claims.put(
                            output.getKey(),
                            claim.values().size() == 1 ? claim.values().get(0) : claim.values());
                }
            }
        }
        List<Map<String, Object>> evidence = new ArrayList<>();
        for (List<SelectedCredential> credentials : result.credentials().values()) {
            for (SelectedCredential credential : credentials) {
                evidence.add(Map.of(
                        "format",
                        credential.format(),
                        "credential_type",
                        credential.type(),
                        "issuer",
                        credential.issuer()));
            }
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("id", session.id());
        out.put("status", "verified");
        out.put("policy_id", session.policyId());
        out.put("verified_at", now.toString());
        out.put("claims", claims);
        out.put("credential_evidence", evidence);
        return out;
    }

    private String requestUri(String handle) {
        return runtime.publicBaseUrl().resolve("oid4vp/requests/" + handle).toString();
    }

    private URI responseUri() {
        return runtime.publicBaseUrl().resolve("oid4vp/responses");
    }
}
