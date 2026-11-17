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
package io.github.suengineering.eudiw.service.config;

import io.github.suengineering.eudiw.core.dcql.ClaimsPath;
import io.github.suengineering.eudiw.core.dcql.DcqlQuery;
import io.github.suengineering.eudiw.core.json.Json;
import io.github.suengineering.eudiw.core.keys.Pkcs11Keys;
import io.github.suengineering.eudiw.core.oid4vp.RelyingPartyRegistration;
import io.github.suengineering.eudiw.core.oid4vp.VerifierIdentity;
import io.github.suengineering.eudiw.core.oid4vp.VpTokenVerifier.StatusPolicy;
import io.github.suengineering.eudiw.core.trust.TrustedList;
import io.github.suengineering.eudiw.core.trust.TrustedListSource;
import io.github.suengineering.eudiw.service.config.AdapterConfig.ClientApplication;
import io.github.suengineering.eudiw.service.config.AdapterConfig.OutputClaim;
import io.github.suengineering.eudiw.service.config.AdapterConfig.Policy;
import io.github.suengineering.eudiw.service.config.AdapterConfig.Tenant;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reads and validates the declarative configuration file. Any inconsistency stops startup: a policy that names an
 * unknown credential, a result claim the DCQL query does not request, a client granted an unknown policy, or a
 * TTL above the hard limits.
 */
public final class ConfigLoader {

    private static final org.jboss.logging.Logger LOG = org.jboss.logging.Logger.getLogger(ConfigLoader.class);

    private static final Pattern ID = Pattern.compile("[a-z0-9][a-z0-9._-]{0,63}");
    private static final Pattern PEM_KEY =
            Pattern.compile("-----BEGIN PRIVATE KEY-----(.*?)-----END PRIVATE KEY-----", Pattern.DOTALL);

    private ConfigLoader() {}

    public static AdapterConfig load(Path file, boolean production) {
        byte[] bytes;
        try {
            bytes = Files.readAllBytes(file);
        } catch (IOException e) {
            throw new ConfigException("cannot read configuration file " + file, e);
        }
        Path base = file.toAbsolutePath().getParent();
        Map<String, Object> json = Json.parseObject(new String(bytes, StandardCharsets.UTF_8), "invalid_configuration");
        Map<String, Tenant> tenants = new LinkedHashMap<>();
        Set<String> clientIds = new LinkedHashSet<>();
        for (Object item : list(json, "tenants")) {
            Tenant tenant = tenant(object(item, "tenant"), base, production);
            if (tenants.put(tenant.id(), tenant) != null) {
                throw new ConfigException("duplicate tenant id " + tenant.id());
            }
            for (String clientId : tenant.clients().keySet()) {
                if (!clientIds.add(clientId)) {
                    throw new ConfigException("client id " + clientId + " is used by more than one tenant");
                }
            }
        }
        if (tenants.isEmpty()) {
            throw new ConfigException("no tenants configured");
        }
        return new AdapterConfig(revision(bytes, tenants), Map.copyOf(tenants));
    }

    private static Tenant tenant(Map<String, Object> json, Path base, boolean production) {
        String id = id(json.get("id"), "tenant id");
        Map<String, Object> verifier = object(json.get("verifier"), "verifier");
        List<X509Certificate> chain = certificates(read(base, string(verifier, "certificate_chain_file")));
        if (verifier.containsKey("private_key_file") == verifier.containsKey("pkcs11")) {
            throw new ConfigException(
                    "tenant " + id + ": set exactly one of verifier.private_key_file and verifier.pkcs11");
        }
        VerifierIdentity identity;
        try {
            if (verifier.containsKey("pkcs11")) {
                Map<String, Object> hsm = object(verifier.get("pkcs11"), "pkcs11");
                int slot = hsm.containsKey("slot_list_index") && hsm.get("slot_list_index") instanceof Number n
                        ? n.intValue()
                        : 0;
                char[] pin = read(base, string(hsm, "pin_file")).strip().toCharArray();
                Pkcs11Keys.Loaded loaded =
                        Pkcs11Keys.load(Path.of(string(hsm, "library")), slot, string(hsm, "key_label"), pin);
                java.util.Arrays.fill(pin, '\0');
                identity = new VerifierIdentity(loaded.key(), chain, Optional.of(loaded.provider()));
            } else {
                PrivateKey key = privateKey(read(base, string(verifier, "private_key_file")));
                identity = new VerifierIdentity(key, chain);
            }
        } catch (IllegalArgumentException e) {
            throw new ConfigException("tenant " + id + ": " + e.getMessage(), e);
        }
        String walletInvocation =
                json.containsKey("wallet_invocation") ? string(json, "wallet_invocation") : "openid4vp://";

        Map<String, Policy> policies = new LinkedHashMap<>();
        for (Object item : list(json, "policies")) {
            Policy policy = policy(object(item, "policy"), base, id, production, chain.get(0));
            if (policies.put(policy.id(), policy) != null) {
                throw new ConfigException("tenant " + id + ": duplicate policy " + policy.id());
            }
        }
        Map<String, ClientApplication> clients = new LinkedHashMap<>();
        for (Object item : list(json, "clients")) {
            Map<String, Object> c = object(item, "client");
            String clientId = string(c, "client_id");
            Set<String> granted = new LinkedHashSet<>();
            for (Object p : list(c, "policies")) {
                if (!(p instanceof String policyId) || !policies.containsKey(policyId)) {
                    throw new ConfigException(
                            "tenant " + id + ": client " + clientId + " is granted an unknown policy");
                }
                granted.add(policyId);
            }
            Optional<URI> completion = Optional.empty();
            if (c.containsKey("completion_uri")) {
                URI uri = URI.create(string(c, "completion_uri"));
                if (production && !"https".equals(uri.getScheme())) {
                    throw new ConfigException("tenant " + id + ": completion_uri must use https");
                }
                if (uri.getFragment() != null) {
                    throw new ConfigException("tenant " + id + ": completion_uri must not have a fragment");
                }
                completion = Optional.of(uri);
            }
            Optional<AdapterConfig.Webhook> webhook = Optional.empty();
            if (c.containsKey("webhook")) {
                webhook = Optional.of(webhook(object(c.get("webhook"), "webhook"), base, id, production));
            }
            int perMinute = AdapterConfig.DEFAULT_SESSIONS_PER_MINUTE;
            if (c.containsKey("rate_limit")) {
                Map<String, Object> limit = object(c.get("rate_limit"), "rate_limit");
                if (!(limit.get("sessions_per_minute") instanceof Number n)
                        || n.doubleValue() != n.intValue()
                        || n.intValue() < 1
                        || n.intValue() > 100_000) {
                    throw new ConfigException("tenant " + id + ": client " + clientId
                            + ": rate_limit.sessions_per_minute must be an integer from 1 to 100000");
                }
                perMinute = n.intValue();
            }
            if (clients.put(
                            clientId,
                            new ClientApplication(clientId, Set.copyOf(granted), completion, webhook, perMinute))
                    != null) {
                throw new ConfigException("tenant " + id + ": duplicate client " + clientId);
            }
        }
        return new Tenant(id, identity, walletInvocation, Map.copyOf(clients), Map.copyOf(policies));
    }

    private static AdapterConfig.Webhook webhook(
            Map<String, Object> json, Path base, String tenantId, boolean production) {
        String where = "tenant " + tenantId + " webhook";
        URI url;
        try {
            url = URI.create(string(json, "url"));
        } catch (IllegalArgumentException e) {
            throw new ConfigException(where + ": invalid url", e);
        }
        if (!"https".equals(url.getScheme()) && (production || !"http".equals(url.getScheme()))) {
            throw new ConfigException(where + ": url must use https");
        }
        List<byte[]> secrets = new ArrayList<>();
        secrets.add(webhookSecret(read(base, string(json, "secret_file")).strip(), where));
        if (json.containsKey("previous_secret_file")) {
            secrets.add(webhookSecret(
                    read(base, string(json, "previous_secret_file")).strip(), where));
        }
        return new AdapterConfig.Webhook(url, secrets);
    }

    /** A {@code whsec_} prefixed base64 secret of 24 to 64 bytes (Standard Webhooks). */
    static byte[] webhookSecret(String value, String where) {
        if (!value.startsWith("whsec_")) {
            throw new ConfigException(where + ": secret must start with whsec_");
        }
        byte[] secret;
        try {
            secret = Base64.getDecoder().decode(value.substring("whsec_".length()));
        } catch (IllegalArgumentException e) {
            throw new ConfigException(where + ": secret is not base64", e);
        }
        if (secret.length < 24 || secret.length > 64) {
            throw new ConfigException(where + ": secret must be 24 to 64 bytes");
        }
        return secret;
    }

    private static Policy policy(
            Map<String, Object> json,
            Path base,
            String tenantId,
            boolean production,
            X509Certificate accessCertificate) {
        String id = id(json.get("id"), "policy id");
        String where = "tenant " + tenantId + " policy " + id;
        DcqlQuery query;
        try {
            query = DcqlQuery.parse(object(json.get("dcql"), "dcql"));
        } catch (IllegalArgumentException e) {
            throw new ConfigException(where + ": invalid DCQL: " + e.getMessage(), e);
        }

        Map<String, OutputClaim> output = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : object(json.get("output"), "output").entrySet()) {
            Map<String, Object> o = object(e.getValue(), "output claim");
            String credentialId = string(o, "credential");
            ClaimsPath path;
            try {
                path = new ClaimsPath(list(o, "path"));
            } catch (IllegalArgumentException ex) {
                throw new ConfigException(where + ": invalid output path for " + e.getKey(), ex);
            }
            DcqlQuery.CredentialQuery credential = query.credential(credentialId)
                    .orElseThrow(
                            () -> new ConfigException(where + ": output refers to unknown credential " + credentialId));
            boolean requested =
                    credential.claims().stream().anyMatch(c -> c.path().equals(path));
            if (!requested) {
                throw new ConfigException(
                        where + ": output claim " + e.getKey() + " is not requested by the DCQL query");
            }
            output.put(e.getKey(), new OutputClaim(credentialId, path));
        }

        Set<TrustAnchor> anchors = new LinkedHashSet<>();
        if (json.containsKey("trust_anchors_file")) {
            for (X509Certificate certificate : certificates(read(base, string(json, "trust_anchors_file")))) {
                anchors.add(new TrustAnchor(certificate, null));
            }
        }
        List<TrustedListSource> trustedLists = new ArrayList<>();
        if (json.containsKey("trusted_lists")) {
            for (Object entry : list(json, "trusted_lists")) {
                trustedLists.add(trustedList(object(entry, "trusted list"), base, where, production));
            }
        }
        if (anchors.isEmpty() && trustedLists.isEmpty()) {
            throw new ConfigException(where + ": set trust_anchors_file, trusted_lists or both");
        }
        Set<String> allowedIssuers = new LinkedHashSet<>();
        if (json.containsKey("allowed_issuers")) {
            for (Object issuer : list(json, "allowed_issuers")) {
                if (!(issuer instanceof String s) || s.isEmpty()) {
                    throw new ConfigException(where + ": allowed_issuers must be strings");
                }
                allowedIssuers.add(s);
            }
        }
        StatusPolicy statusPolicy = StatusPolicy.REQUIRE_VALID;
        if (json.containsKey("status_policy")) {
            try {
                statusPolicy =
                        StatusPolicy.valueOf(string(json, "status_policy").toUpperCase(Locale.ROOT));
            } catch (IllegalArgumentException e) {
                throw new ConfigException(where + ": unknown status_policy", e);
            }
        }
        if (production && statusPolicy == StatusPolicy.IGNORE) {
            throw new ConfigException(where + ": status_policy ignore is not allowed in production");
        }
        boolean checkRevocation = false;
        if (json.containsKey("certificate_revocation")) {
            checkRevocation = switch (string(json, "certificate_revocation")) {
                case "crl" -> true;
                case "off" -> false;
                default -> throw new ConfigException(where + ": certificate_revocation must be crl or off");
            };
        }
        boolean enforceAuthorities = !json.containsKey("enforce_trusted_authorities")
                || Boolean.TRUE.equals(json.get("enforce_trusted_authorities"));
        Duration sessionTtl =
                seconds(json, "session_ttl_seconds", Duration.ofMinutes(5), AdapterConfig.MAX_SESSION_TTL, where);
        Duration resultTtl =
                seconds(json, "result_ttl_seconds", Duration.ofMinutes(15), AdapterConfig.MAX_RESULT_TTL, where);
        Optional<RelyingPartyRegistration> registration = json.containsKey("registration")
                ? Optional.of(registration(
                        object(json.get("registration"), "registration"), base, where, query, accessCertificate))
                : Optional.empty();
        return new Policy(
                id,
                query,
                Map.copyOf(output),
                Set.copyOf(anchors),
                List.copyOf(trustedLists),
                Set.copyOf(allowedIssuers),
                checkRevocation,
                statusPolicy,
                enforceAuthorities,
                sessionTtl,
                resultTtl,
                registration);
    }

    /**
     * Reads a policy's registration (ETSI TS 119 472-2 clause 6.3.2.2). A missing required dataset member, a query
     * that asks for more than the dataset declares, and a certificate that cannot be parsed or has expired stop
     * startup. A query that asks for more than the certificate declares, or a certificate that names neither this
     * relying party nor its intermediary, is logged: the wallet decides, and the certificate is the registrar's.
     */
    private static RelyingPartyRegistration registration(
            Map<String, Object> json, Path base, String where, DcqlQuery query, X509Certificate accessCertificate) {
        if (json.containsKey("registrar_dataset") == json.containsKey("registrar_dataset_file")) {
            throw new ConfigException(where + ": set exactly one of registration.registrar_dataset and "
                    + "registration.registrar_dataset_file");
        }
        Map<String, Object> dataset;
        if (json.containsKey("registrar_dataset")) {
            dataset = object(json.get("registrar_dataset"), "registrar_dataset");
        } else {
            try {
                dataset = Json.parseObject(readUtf8(base, string(json, "registrar_dataset_file")), "invalid");
            } catch (RuntimeException e) {
                throw new ConfigException(where + ": registrar_dataset_file is not a JSON object", e);
            }
        }
        Optional<RelyingPartyRegistration.RegistrationCertificate> certificate = Optional.empty();
        if (json.containsKey("certificate_file")) {
            RelyingPartyRegistration.RegistrationCertificate parsed;
            try {
                parsed = RelyingPartyRegistration.RegistrationCertificate.parse(
                        read(base, string(json, "certificate_file")));
            } catch (IllegalArgumentException e) {
                throw new ConfigException(where + ": " + e.getMessage(), e);
            }
            java.time.Instant now = java.time.Instant.now();
            if (parsed.expiresAt().map(exp -> !exp.isAfter(now)).orElse(false)) {
                // Not fatal: a restart after expiry must not stop every tenant. It is not sent, and
                // /health/well reports it until the file is replaced.
                LOG.errorf(
                        "%s: the registration certificate expired at %s; requests carry only the registrar dataset",
                        where, parsed.expiresAt().get());
            }
            if (!parsed.missingMembers().isEmpty()) {
                LOG.warnf(
                        "%s: the registration certificate lacks members ETSI TS 119 475 requires; wallets may refuse "
                                + "it: %s",
                        where, String.join(", ", parsed.missingMembers()));
            }
            if (!parsed.names(accessCertificate)) {
                LOG.warnf(
                        "%s: the registration certificate sub %s matches neither the organizationIdentifier nor the "
                                + "serialNumber of the access certificate, nor an intermediary in the certificate",
                        where, parsed.subject());
            }
            List<String> overAsking = RelyingPartyRegistration.undeclared(query, parsed.credentials());
            if (!overAsking.isEmpty()) {
                LOG.warnf(
                        "%s: the DCQL query asks for more than the registration certificate declares; wallets may "
                                + "refuse the request: %s",
                        where, String.join("; ", overAsking));
            }
            certificate = Optional.of(parsed);
        }
        RelyingPartyRegistration registration;
        try {
            registration = RelyingPartyRegistration.of(dataset, certificate);
        } catch (IllegalArgumentException e) {
            throw new ConfigException(where + ": " + e.getMessage(), e);
        }
        List<String> undeclared = registration.undeclaredByDataset(query);
        if (!undeclared.isEmpty()) {
            throw new ConfigException(where + ": the DCQL query asks for more than the registrar dataset declares: "
                    + String.join("; ", undeclared));
        }
        return registration;
    }

    private static String readUtf8(Path base, String relative) {
        Path path = base.resolve(relative).normalize();
        try {
            return Files.readString(path, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new ConfigException("cannot read " + path, e);
        }
    }

    private static TrustedListSource trustedList(
            Map<String, Object> json, Path base, String where, boolean production) {
        String location = string(json, "location");
        URI uri;
        try {
            uri = location.startsWith("https://") || location.startsWith("http://")
                    ? URI.create(location)
                    : base.resolve(location).normalize().toUri();
        } catch (IllegalArgumentException e) {
            throw new ConfigException(where + ": invalid trusted list location", e);
        }
        if (production && "http".equalsIgnoreCase(uri.getScheme())) {
            throw new ConfigException(where + ": trusted list locations must use HTTPS in production");
        }
        TrustedList.Format format =
                switch (string(json, "format")) {
                    case "tsl_xml" -> TrustedList.Format.TSL_XML;
                    case "lote_json" -> TrustedList.Format.LOTE_JSON;
                    default -> throw new ConfigException(where + ": trusted list format must be tsl_xml or lote_json");
                };
        List<X509Certificate> signers = certificates(read(base, string(json, "signer_certificates_file")));
        Set<String> accepted = json.containsKey("accepted_statuses")
                ? strings(json, "accepted_statuses", where)
                : TrustedListSource.DEFAULT_ACCEPTED_STATUSES;
        try {
            return new TrustedListSource(
                    json.containsKey("identifier") ? string(json, "identifier") : uri.toString(),
                    uri,
                    format,
                    signers,
                    Boolean.TRUE.equals(json.get("follow_pointers")),
                    json.containsKey("territories") ? strings(json, "territories", where) : Set.of(),
                    strings(json, "issuance_service_types", where),
                    json.containsKey("status_service_types") ? strings(json, "status_service_types", where) : Set.of(),
                    accepted);
        } catch (IllegalArgumentException e) {
            throw new ConfigException(where + ": " + e.getMessage(), e);
        }
    }

    private static Set<String> strings(Map<String, Object> json, String key, String where) {
        Set<String> values = new LinkedHashSet<>();
        for (Object value : list(json, key)) {
            if (!(value instanceof String s) || s.isEmpty()) {
                throw new ConfigException(where + ": " + key + " must be non-empty strings");
            }
            values.add(s);
        }
        return values;
    }

    private static Duration seconds(
            Map<String, Object> json, String key, Duration fallback, Duration max, String where) {
        if (!json.containsKey(key)) {
            return fallback;
        }
        if (!(json.get(key) instanceof Number n) || n.longValue() <= 0) {
            throw new ConfigException(where + ": " + key + " must be a positive number");
        }
        Duration value = Duration.ofSeconds(n.longValue());
        if (value.compareTo(max) > 0) {
            throw new ConfigException(where + ": " + key + " exceeds the limit of " + max.toSeconds() + " seconds");
        }
        return value;
    }

    static PrivateKey privateKey(String pem) {
        Matcher m = PEM_KEY.matcher(pem);
        if (!m.find()) {
            throw new ConfigException("private key must be a PKCS#8 PEM (BEGIN PRIVATE KEY)");
        }
        byte[] der = Base64.getMimeDecoder().decode(m.group(1));
        try {
            return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (GeneralSecurityException e) {
            throw new ConfigException("private key is not an EC PKCS#8 key", e);
        }
    }

    static List<X509Certificate> certificates(String pem) {
        try {
            List<X509Certificate> out = new ArrayList<>();
            for (var c : CertificateFactory.getInstance("X.509")
                    .generateCertificates(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)))) {
                out.add((X509Certificate) c);
            }
            if (out.isEmpty()) {
                throw new ConfigException("no certificates found");
            }
            return out;
        } catch (GeneralSecurityException e) {
            throw new ConfigException("certificates cannot be parsed", e);
        }
    }

    private static String read(Path base, String relative) {
        Path path = base.resolve(relative).normalize();
        try {
            return Files.readString(path, StandardCharsets.US_ASCII);
        } catch (IOException e) {
            throw new ConfigException("cannot read " + path, e);
        }
    }

    private static String revision(byte[] config, Map<String, Tenant> tenants) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(config);
            for (Tenant t : tenants.values()) {
                for (X509Certificate c : t.verifier().certificateChain()) {
                    digest.update(c.getEncoded());
                }
                for (Policy p : t.policies().values()) {
                    for (TrustAnchor a : p.trustAnchors()) {
                        digest.update(a.getTrustedCert().getEncoded());
                    }
                    if (p.registration().isPresent()) {
                        digest.update(Json.toJson(p.registration().get().registrarDataset())
                                .getBytes(StandardCharsets.UTF_8));
                        p.registration()
                                .get()
                                .certificate()
                                .ifPresent(c -> digest.update(c.serialized().getBytes(StandardCharsets.US_ASCII)));
                    }
                    for (TrustedListSource list : p.trustedLists()) {
                        for (X509Certificate signer : list.signers()) {
                            digest.update(signer.getEncoded());
                        }
                    }
                }
            }
            return HexFormat.of().formatHex(digest.digest()).substring(0, 16);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String id(Object value, String what) {
        if (!(value instanceof String s) || !ID.matcher(s).matches()) {
            throw new ConfigException(what + " must match " + ID.pattern());
        }
        return s;
    }

    private static String string(Map<String, Object> json, String key) {
        if (!(json.get(key) instanceof String s) || s.isEmpty()) {
            throw new ConfigException(key + " must be a non-empty string");
        }
        return s;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> object(Object value, String what) {
        if (!(value instanceof Map<?, ?>)) {
            throw new ConfigException(what + " must be an object");
        }
        return (Map<String, Object>) value;
    }

    @SuppressWarnings("unchecked")
    private static List<Object> list(Map<String, Object> json, String key) {
        if (!(json.get(key) instanceof List<?> l)) {
            throw new ConfigException(key + " must be an array");
        }
        return (List<Object>) l;
    }

    /** Raised for any configuration error; startup must fail. */
    public static final class ConfigException extends RuntimeException {
        public ConfigException(String message) {
            super(message);
        }

        public ConfigException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
