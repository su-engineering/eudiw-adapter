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
import io.github.suengineering.eudiw.core.keys.VaultTransitSigner;
import io.github.suengineering.eudiw.core.oid4vp.RelyingPartyRegistration;
import io.github.suengineering.eudiw.core.oid4vp.VerifierIdentity;
import io.github.suengineering.eudiw.core.oid4vp.VpTokenVerifier.StatusPolicy;
import io.github.suengineering.eudiw.core.oid4vp.VpTokenVerifier.StatusSigner;
import io.github.suengineering.eudiw.core.trust.TrustedList;
import io.github.suengineering.eudiw.core.trust.TrustedListSource;
import io.github.suengineering.eudiw.kms.aws.AwsKmsSigner;
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
import java.util.Collections;
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

    private static final Pattern TRANSACTION_DATA_TYPE = Pattern.compile("[\\x21-\\x7e]{1,256}");
    private static final Pattern ID = Pattern.compile("[a-z0-9][a-z0-9._-]{0,63}");
    private static final Pattern OID = Pattern.compile("[0-2](\\.(0|[1-9][0-9]*))+");
    /** An OAuth client id (RFC 6749 VSCHAR) without space, quote or backslash, so it is compared verbatim. */
    private static final Pattern CLIENT_ID = Pattern.compile("[\\x21\\x23-\\x5B\\x5D-\\x7E]{1,255}");

    private static final Pattern PEM_KEY =
            Pattern.compile("-----BEGIN PRIVATE KEY-----(.*?)-----END PRIVATE KEY-----", Pattern.DOTALL);

    /** The files read by the load running on this thread, with the SHA-256 of what was read. */
    private static final ThreadLocal<Map<Path, String>> SOURCES = new ThreadLocal<>();

    private ConfigLoader() {}

    public static AdapterConfig load(Path file, boolean production) {
        return load(file, production, new LinkedHashMap<>());
    }

    /**
     * Loads like {@link #load(Path, boolean)} and also fills {@code sources} with every file read, with the SHA-256
     * of its content, even when the configuration turns out invalid.
     */
    public static AdapterConfig load(Path file, boolean production, Map<Path, String> sources) {
        SOURCES.set(sources);
        try {
            return read(file, production, sources);
        } finally {
            SOURCES.remove();
        }
    }

    /** The SHA-256 of a file's current content, as hex, or {@code "missing"} when it cannot be read. */
    public static String contentHash(Path file) {
        try {
            return sha256(Files.readAllBytes(file));
        } catch (IOException e) {
            return "missing";
        }
    }

    private static String sha256(byte[] content) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(content));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static void track(Path path, byte[] content) {
        track(path, sha256(content));
    }

    /**
     * Records a file the configuration names, with its content hash, or {@code "missing"} as {@link
     * #contentHash(Path)} reports it when it cannot be read. A file that is missing at a failed load is therefore
     * watched too, and creating it later triggers another attempt.
     */
    private static void track(Path path, String hash) {
        Map<Path, String> sources = SOURCES.get();
        if (sources != null) {
            sources.put(path.toAbsolutePath().normalize(), hash);
        }
    }

    private static AdapterConfig read(Path file, boolean production, Map<Path, String> sources) {
        byte[] bytes;
        try {
            bytes = Files.readAllBytes(file);
        } catch (IOException e) {
            track(file, "missing");
            throw new ConfigException("cannot read configuration file " + file, e);
        }
        track(file, bytes);
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
        return new AdapterConfig(
                revision(bytes, tenants, sources),
                Map.copyOf(tenants),
                java.util.Collections.unmodifiableMap(new LinkedHashMap<>(sources)));
    }

    private static Tenant tenant(Map<String, Object> json, Path base, boolean production) {
        String id = id(json.get("id"), "tenant id");
        Map<String, Object> verifier = object(json.get("verifier"), "verifier");
        List<X509Certificate> chain = certificates(read(base, string(verifier, "certificate_chain_file")));
        long keySources = java.util.stream.Stream.of("private_key_file", "pkcs11", "vault_transit", "aws_kms")
                .filter(verifier::containsKey)
                .count();
        if (keySources != 1) {
            throw new ConfigException("tenant " + id
                    + ": set exactly one of verifier.private_key_file, verifier.pkcs11, verifier.vault_transit"
                    + " and verifier.aws_kms");
        }
        VerifierIdentity identity;
        try {
            if (verifier.containsKey("aws_kms")) {
                identity = new VerifierIdentity(
                        new AwsKmsSigner(awsKms(object(verifier.get("aws_kms"), "aws_kms"), production)), chain);
            } else if (verifier.containsKey("vault_transit")) {
                identity = new VerifierIdentity(
                        new VaultTransitSigner(
                                vaultTransit(object(verifier.get("vault_transit"), "vault_transit"), base, production)),
                        chain);
            } else if (verifier.containsKey("pkcs11")) {
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
            if (!CLIENT_ID.matcher(clientId).matches()) {
                throw new ConfigException("tenant " + id + ": client_id must be 1 to 255 printable ASCII characters"
                        + " without spaces, quotes or backslashes");
            }
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
            List<String> dcApiOrigins = new ArrayList<>();
            if (c.containsKey("dc_api_origins")) {
                for (Object origin : list(c, "dc_api_origins")) {
                    dcApiOrigins.add(dcApiOrigin(origin, production, "tenant " + id + ": client " + clientId));
                }
                if (dcApiOrigins.isEmpty()) {
                    throw new ConfigException(
                            "tenant " + id + ": client " + clientId + ": dc_api_origins must not be empty");
                }
            }
            Optional<AdapterConfig.OidcClient> oidc = Optional.empty();
            if (c.containsKey("oidc")) {
                oidc = Optional.of(oidcClient(
                        object(c.get("oidc"), "oidc"),
                        base,
                        production,
                        "tenant " + id + ": client " + clientId,
                        granted,
                        policies));
            }
            if (clients.put(
                            clientId,
                            new ClientApplication(
                                    clientId,
                                    Set.copyOf(granted),
                                    completion,
                                    webhook,
                                    perMinute,
                                    List.copyOf(dcApiOrigins),
                                    oidc))
                    != null) {
                throw new ConfigException("tenant " + id + ": duplicate client " + clientId);
            }
        }
        Optional<AdapterConfig.OidcProvider> oidcProvider = Optional.empty();
        if (json.containsKey("oidc_provider")) {
            oidcProvider =
                    Optional.of(oidcProvider(object(json.get("oidc_provider"), "oidc_provider"), base, "tenant " + id));
        }
        if (oidcProvider.isEmpty()
                && clients.values().stream().anyMatch(c -> c.oidc().isPresent())) {
            throw new ConfigException("tenant " + id + ": clients with oidc need the tenant's oidc_provider");
        }
        return new Tenant(id, identity, walletInvocation, Map.copyOf(clients), Map.copyOf(policies), oidcProvider);
    }

    /** OIDC claim names that identity providers link or match accounts on; a wallet login never sends them. */
    static final Set<String> OIDC_FORBIDDEN_CLAIMS =
            Set.of("email", "email_verified", "preferred_username", "phone_number", "phone_number_verified");

    /** Claims the provider sets itself. */
    static final Set<String> OIDC_RESERVED_CLAIMS = Set.of(
            "iss",
            "sub",
            "aud",
            "exp",
            "iat",
            "nbf",
            "auth_time",
            "nonce",
            "azp",
            "at_hash",
            "c_hash",
            "acr",
            "amr",
            "sid",
            "jti",
            "cnf");

    private static final Pattern OIDC_CLAIM_NAME = Pattern.compile("[a-z][a-z0-9_]{0,63}");

    /** Policy claims that identify a person persistently; a subject from anything else can join two people. */
    static final Set<String> PERSISTENT_IDENTIFIERS = Set.of("personal_administrative_number");

    private static AdapterConfig.OidcProvider oidcProvider(Map<String, Object> json, Path base, String where) {
        java.security.interfaces.RSAPrivateKey key = rsaPrivateKey(read(base, string(json, "signing_key_file")), where);
        java.security.interfaces.RSAPublicKey publicKey;
        String keyId;
        try {
            var crt = (java.security.interfaces.RSAPrivateCrtKey) key;
            publicKey = (java.security.interfaces.RSAPublicKey) KeyFactory.getInstance("RSA")
                    .generatePublic(new java.security.spec.RSAPublicKeySpec(crt.getModulus(), crt.getPublicExponent()));
            keyId = new com.nimbusds.jose.jwk.RSAKey.Builder(publicKey)
                    .build()
                    .computeThumbprint()
                    .toString();
        } catch (ClassCastException | GeneralSecurityException | com.nimbusds.jose.JOSEException e) {
            throw new ConfigException(where + ": oidc_provider.signing_key_file must hold an RSA PKCS#8 key", e);
        }
        if (publicKey.getModulus().bitLength() < 2048) {
            throw new ConfigException(where + ": the ID token signing key must be RSA of at least 2048 bits");
        }
        byte[] subjectKey;
        try {
            subjectKey = Base64.getDecoder()
                    .decode(read(base, string(json, "subject_key_file")).strip());
        } catch (IllegalArgumentException e) {
            throw new ConfigException(where + ": oidc_provider.subject_key_file must hold base64", e);
        }
        if (subjectKey.length < 32) {
            throw new ConfigException(where + ": the subject key must be at least 32 random bytes, base64-encoded"
                    + " (openssl rand -base64 32)");
        }
        return new AdapterConfig.OidcProvider(key, publicKey, keyId, subjectKey);
    }

    private static java.security.interfaces.RSAPrivateKey rsaPrivateKey(String pem, String where) {
        Matcher m = PEM_KEY.matcher(pem);
        if (!m.find()) {
            throw new ConfigException(
                    where + ": oidc_provider.signing_key_file must be a PKCS#8 PEM (BEGIN PRIVATE KEY)");
        }
        try {
            return (java.security.interfaces.RSAPrivateKey) KeyFactory.getInstance("RSA")
                    .generatePrivate(
                            new PKCS8EncodedKeySpec(Base64.getMimeDecoder().decode(m.group(1))));
        } catch (GeneralSecurityException e) {
            throw new ConfigException(where + ": oidc_provider.signing_key_file is not an RSA PKCS#8 key", e);
        }
    }

    private static AdapterConfig.OidcClient oidcClient(
            Map<String, Object> json,
            Path base,
            boolean production,
            String where,
            Set<String> granted,
            Map<String, Policy> policies) {
        byte[] secret = read(base, string(json, "client_secret_file")).strip().getBytes(StandardCharsets.US_ASCII);
        if (secret.length < 32) {
            throw new ConfigException(
                    where + ": the OIDC client secret must be at least 32 characters" + " (openssl rand -base64 32)");
        }
        List<String> redirectUris = new ArrayList<>();
        for (Object item : list(json, "redirect_uris")) {
            if (!(item instanceof String value)) {
                throw new ConfigException(where + ": redirect_uris must be strings");
            }
            URI uri;
            try {
                uri = new URI(value);
            } catch (java.net.URISyntaxException e) {
                throw new ConfigException(where + ": redirect URI is not a URI: " + value);
            }
            if (!uri.isAbsolute() || uri.getFragment() != null || uri.getHost() == null) {
                throw new ConfigException(where + ": redirect URIs must be absolute, without a fragment: " + value);
            }
            if (!"https".equals(uri.getScheme()) && !(!production && "http".equals(uri.getScheme()))) {
                throw new ConfigException(where + ": redirect URIs must use https" + (production ? "" : " or http"));
            }
            redirectUris.add(value);
        }
        if (redirectUris.isEmpty()) {
            throw new ConfigException(where + ": oidc.redirect_uris must not be empty");
        }
        String policyId = string(json, "policy_id");
        if (!granted.contains(policyId)) {
            throw new ConfigException(where + ": oidc.policy_id must be one of the client's policies");
        }
        Policy policy = policies.get(policyId);
        List<String> subjectClaims = new ArrayList<>();
        for (Object item : list(json, "subject_claims")) {
            if (!(item instanceof String name) || !policy.output().containsKey(name)) {
                throw new ConfigException(where + ": subject_claims must name output claims of policy " + policyId);
            }
            subjectClaims.add(name);
        }
        if (subjectClaims.isEmpty()) {
            throw new ConfigException(where + ": oidc.subject_claims must not be empty");
        }
        boolean persistent = subjectClaims.stream().anyMatch(name -> {
            List<Object> path = policy.output().get(name).path().components();
            return !path.isEmpty() && PERSISTENT_IDENTIFIERS.contains(String.valueOf(path.get(path.size() - 1)));
        });
        if (!persistent && !flag(json, "subject_from_personal_attributes", where)) {
            throw new ConfigException(where + ": subject_claims include no persistent identifier (such as"
                    + " personal_administrative_number), so two people with the same values would share one account."
                    + " Set subject_from_personal_attributes to true to accept that (see docs/oidc-provider.md)");
        }
        Map<String, String> idTokenClaims = new LinkedHashMap<>();
        if (json.containsKey("id_token_claims")) {
            for (Map.Entry<String, Object> e :
                    object(json.get("id_token_claims"), "id_token_claims").entrySet()) {
                String name = e.getKey();
                if (OIDC_FORBIDDEN_CLAIMS.contains(name)) {
                    throw new ConfigException(where + ": id_token_claims must not contain " + name
                            + ": identity providers link accounts on it");
                }
                if (OIDC_RESERVED_CLAIMS.contains(name)
                        || !OIDC_CLAIM_NAME.matcher(name).matches()) {
                    throw new ConfigException(where + ": id_token_claims cannot set " + name);
                }
                if (!(e.getValue() instanceof String source) || !policy.output().containsKey(source)) {
                    throw new ConfigException(
                            where + ": id_token_claims." + name + " must name an output claim of policy " + policyId);
                }
                idTokenClaims.put(name, source);
            }
        }
        String pkce = json.containsKey("pkce") ? string(json, "pkce") : "required";
        if (!pkce.equals("required") && !pkce.equals("optional")) {
            throw new ConfigException(where + ": oidc.pkce must be required or optional");
        }
        return new AdapterConfig.OidcClient(
                secret,
                List.copyOf(redirectUris),
                policyId,
                List.copyOf(subjectClaims),
                java.util.Collections.unmodifiableMap(idTokenClaims),
                pkce.equals("required"));
    }

    /**
     * An Origin a client's pages call the Digital Credentials API from: scheme, host and port only, in the form a
     * browser reports it (lower case, no default port, no path), so it can be compared exactly. https in production.
     */
    public static String dcApiOrigin(Object value, boolean production, String where) {
        if (!(value instanceof String origin)) {
            throw new ConfigException(where + ": dc_api_origins must be strings");
        }
        URI uri;
        try {
            uri = new URI(origin);
        } catch (java.net.URISyntaxException e) {
            throw new ConfigException(where + ": dc_api_origins entry is not an origin: " + origin);
        }
        String scheme = uri.getScheme();
        boolean defaultPort = uri.getPort() == -1;
        String canonical = scheme + "://" + uri.getHost() + (defaultPort ? "" : ":" + uri.getPort());
        if (scheme == null
                || !(scheme.equals("https") || scheme.equals("http"))
                || uri.getHost() == null
                || !canonical.equals(origin)
                || !canonical.equals(canonical.toLowerCase(java.util.Locale.ROOT))
                || (scheme.equals("https") && uri.getPort() == 443)
                || (scheme.equals("http") && uri.getPort() == 80)) {
            throw new ConfigException(where + ": dc_api_origins entries must be origins such as https://shop.example,"
                    + " lower case, without a path or a default port: " + origin);
        }
        if (production && !scheme.equals("https")) {
            throw new ConfigException(where + ": dc_api_origins must use https in production");
        }
        return origin;
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
        boolean requireStatus = flag(json, "require_status", where);
        if (requireStatus && statusPolicy == StatusPolicy.IGNORE) {
            throw new ConfigException(where + ": require_status needs a status_policy other than ignore");
        }
        StatusSigner statusSigner = StatusSigner.ANY_ANCHOR;
        if (json.containsKey("status_signer")) {
            statusSigner = switch (string(json, "status_signer")) {
                case "any_anchor" -> StatusSigner.ANY_ANCHOR;
                case "credential_issuer" -> StatusSigner.CREDENTIAL_ISSUER;
                default -> throw new ConfigException(where + ": status_signer must be any_anchor or credential_issuer");
            };
        }
        Set<String> issuerUsages = new LinkedHashSet<>();
        if (json.containsKey("issuer_extended_key_usages")) {
            for (Object oid : list(json, "issuer_extended_key_usages")) {
                if (!(oid instanceof String s) || !OID.matcher(s).matches()) {
                    throw new ConfigException(where + ": issuer_extended_key_usages must be dotted OID strings");
                }
                issuerUsages.add(s);
            }
            if (issuerUsages.isEmpty()) {
                throw new ConfigException(where + ": issuer_extended_key_usages must not be empty");
            }
        }
        boolean enforceAuthorities = flag(json, "enforce_trusted_authorities", true, where);
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
                registration,
                flag(json, "mdoc_strict_conformance", where),
                requireStatus,
                statusSigner,
                Collections.unmodifiableSet(issuerUsages),
                transactionDataTypes(json, query, where));
    }

    /**
     * Which {@code transaction_data} types clients may send with this policy (OpenID4VP 1.0 section 5.1). Absent means
     * none. Transaction data is bound through the Key Binding JWT, so the policy needs an SD-JWT VC query that requires
     * holder binding and returns one presentation.
     */
    private static Set<String> transactionDataTypes(Map<String, Object> json, DcqlQuery query, String where) {
        if (!json.containsKey("transaction_data_types")) {
            return Set.of();
        }
        Set<String> types = new LinkedHashSet<>();
        for (Object type : list(json, "transaction_data_types")) {
            if (!(type instanceof String s) || !TRANSACTION_DATA_TYPE.matcher(s).matches()) {
                throw new ConfigException(
                        where + ": transaction_data_types must be strings of 1 to 256 printable characters");
            }
            types.add(s);
        }
        if (types.isEmpty()) {
            throw new ConfigException(where + ": transaction_data_types must not be empty");
        }
        boolean bindable = query.credentials().stream()
                .anyMatch(c ->
                        DcqlQuery.FORMAT_SD_JWT_VC.equals(c.format()) && c.requireHolderBinding() && !c.multiple());
        if (!bindable) {
            throw new ConfigException(where + ": transaction_data_types needs a dc+sd-jwt credential query with holder"
                    + " binding and without multiple");
        }
        return Collections.unmodifiableSet(types);
    }

    private static boolean flag(Map<String, Object> json, String name, String where) {
        return flag(json, name, false, where);
    }

    private static boolean flag(Map<String, Object> json, String name, boolean absent, String where) {
        Object value = json.get(name);
        if (value == null) {
            return absent;
        }
        if (!(value instanceof Boolean b)) {
            throw new ConfigException(where + ": " + name + " must be true or false");
        }
        return b;
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
            byte[] content = Files.readAllBytes(path);
            track(path, content);
            return new String(content, StandardCharsets.UTF_8);
        } catch (IOException e) {
            track(path, "missing");
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
        TrustedList.Format format = switch (string(json, "format")) {
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
                    flag(json, "follow_pointers", false, where),
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

    /** Credentials are never configured here: the AWS SDK takes them from its default chain. */
    private static AwsKmsSigner.Settings awsKms(Map<String, Object> json, boolean production) {
        Optional<URI> endpoint = Optional.empty();
        if (json.containsKey("endpoint")) {
            try {
                URI uri = new URI(string(json, "endpoint"));
                if (!("https".equals(uri.getScheme()) || "http".equals(uri.getScheme())) || uri.getHost() == null) {
                    throw new ConfigException("aws_kms.endpoint must be an http or https URL");
                }
                if (production && !"https".equals(uri.getScheme())) {
                    throw new ConfigException("aws_kms.endpoint must use https in production");
                }
                endpoint = Optional.of(uri);
            } catch (java.net.URISyntaxException e) {
                throw new ConfigException("aws_kms.endpoint is not a URL");
            }
        }
        return new AwsKmsSigner.Settings(
                string(json, "key_id"),
                json.containsKey("region") ? Optional.of(string(json, "region")) : Optional.empty(),
                endpoint);
    }

    /**
     * The token file is checked here but not tracked: Vault Agent rewrites it on every renewal, and each replica has
     * its own token, so it must not change the configuration revision. The signer reads it on every signature.
     */
    private static VaultTransitSigner.Settings vaultTransit(Map<String, Object> json, Path base, boolean production) {
        URI address;
        try {
            address = new URI(string(json, "address"));
        } catch (java.net.URISyntaxException e) {
            throw new ConfigException("vault_transit.address is not a URL");
        }
        if (production && !"https".equals(address.getScheme())) {
            throw new ConfigException("vault_transit.address must use https in production");
        }
        java.util.OptionalInt version = java.util.OptionalInt.empty();
        if (json.containsKey("key_version")) {
            if (!(json.get("key_version") instanceof Number n) || n.doubleValue() != n.intValue()) {
                throw new ConfigException("vault_transit.key_version must be an integer");
            }
            version = java.util.OptionalInt.of(n.intValue());
        }
        Path tokenFile = base.resolve(string(json, "token_file")).normalize();
        if (!Files.isReadable(tokenFile)) {
            throw new ConfigException("cannot read the Vault token file " + tokenFile);
        }
        return new VaultTransitSigner.Settings(
                address,
                json.containsKey("mount") ? string(json, "mount") : "transit",
                string(json, "key_name"),
                version,
                json.containsKey("namespace") ? Optional.of(string(json, "namespace")) : Optional.empty(),
                tokenFile);
    }

    private static String read(Path base, String relative) {
        Path path = base.resolve(relative).normalize();
        try {
            byte[] content = Files.readAllBytes(path);
            track(path, content);
            return new String(content, StandardCharsets.US_ASCII);
        } catch (IOException e) {
            track(path, "missing");
            throw new ConfigException("cannot read " + path, e);
        }
    }

    /**
     * The full SHA-256 over the tenants file, every file it references and the parsed key material, as 64 hex
     * characters. Referenced files count, so rotating a webhook secret or a signing key is a new revision.
     */
    private static String revision(byte[] config, Map<String, Tenant> tenants, Map<Path, String> sources) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(config);
            // Sorted everywhere: Map.copyOf and Set.copyOf iterate in a per-JVM order, and every replica must
            // compute the same revision from the same files.
            for (Tenant t : tenants.values().stream()
                    .sorted(java.util.Comparator.comparing(Tenant::id))
                    .toList()) {
                for (X509Certificate c : t.verifier().certificateChain()) {
                    digest.update(c.getEncoded());
                }
                for (Policy p : t.policies().values().stream()
                        .sorted(java.util.Comparator.comparing(Policy::id))
                        .toList()) {
                    List<byte[]> anchors = new ArrayList<>();
                    for (TrustAnchor a : p.trustAnchors()) {
                        anchors.add(a.getTrustedCert().getEncoded());
                    }
                    anchors.sort(java.util.Arrays::compare);
                    anchors.forEach(digest::update);
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
            // By content, not by path: replicas mount the same files at different paths.
            sources.values().stream()
                    .skip(1)
                    .sorted()
                    .forEach(hash -> digest.update(hash.getBytes(StandardCharsets.US_ASCII)));
            return HexFormat.of().formatHex(digest.digest());
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
