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

import io.github.suengineering.eudiw.core.dcql.DcqlQuery;
import io.github.suengineering.eudiw.core.jose.AlgorithmPolicy;
import io.github.suengineering.eudiw.core.mdoc.MdocDeviceAuthentication;
import io.github.suengineering.eudiw.core.mdoc.MdocIssuerVerifier;
import io.github.suengineering.eudiw.core.mdoc.MdocPresentationVerifier;
import io.github.suengineering.eudiw.core.net.EgressPolicy;
import io.github.suengineering.eudiw.core.net.HttpFetcher;
import io.github.suengineering.eudiw.core.net.JdkHttpFetcher;
import io.github.suengineering.eudiw.core.oid4vp.VpTokenVerifier;
import io.github.suengineering.eudiw.core.oid4vp.VpTokenVerifier.StatusPolicy;
import io.github.suengineering.eudiw.core.sdjwt.SdJwtVcVerifier;
import io.github.suengineering.eudiw.core.sdjwt.X5cIssuerKeyResolver;
import io.github.suengineering.eudiw.core.status.StatusListChecker;
import io.github.suengineering.eudiw.core.trust.TrustedLists;
import io.github.suengineering.eudiw.core.x509.CrlRevocationChecker;
import io.github.suengineering.eudiw.core.x509.TrustStore;
import io.github.suengineering.eudiw.service.config.AdapterConfig;
import io.github.suengineering.eudiw.service.config.AdapterConfig.Policy;
import io.github.suengineering.eudiw.service.config.AdapterConfig.Tenant;
import io.github.suengineering.eudiw.service.config.ConfigLoader;
import io.github.suengineering.eudiw.service.crypto.DataProtection;
import io.quarkus.runtime.Startup;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import java.net.URI;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

/**
 * Loads the configuration once at startup, refuses unsafe settings in production, and holds one verifier per
 * policy so that trust anchors and status caches never cross policy or tenant boundaries.
 */
@Startup
@ApplicationScoped
public class AdapterRuntime {

    @ConfigProperty(name = "eudiw.config-file")
    String configFile;

    @ConfigProperty(name = "eudiw.public-base-url")
    String publicBaseUrl;

    @ConfigProperty(name = "eudiw.data-key")
    String dataKey;

    @ConfigProperty(name = "eudiw.production", defaultValue = "true")
    boolean production;

    @ConfigProperty(name = "eudiw.egress.allow-private-addresses", defaultValue = "false")
    boolean allowPrivateAddresses;

    @ConfigProperty(name = "eudiw.egress.allow-http", defaultValue = "false")
    boolean allowHttp;

    /** If set, list, status list and CRL fetches may reach only these hosts. */
    @ConfigProperty(name = "eudiw.egress.allowed-hosts")
    java.util.Optional<java.util.List<String>> allowedHosts;

    /** Verify mdoc signatures on brainpool curves, with BouncyCastle (ADR-012). Off unless set. */
    @ConfigProperty(name = "eudiw.crypto.brainpool", defaultValue = "false")
    boolean brainpool;

    @jakarta.inject.Inject
    io.github.suengineering.eudiw.service.store.TrustedListSequenceStore sequenceStore;

    @jakarta.inject.Inject
    io.micrometer.core.instrument.MeterRegistry registry;

    /** One loaded configuration with the verifiers and trusted lists built for it. */
    private record Generation(
            AdapterConfig config, Map<String, VpTokenVerifier> verifiers, Map<String, TrustedLists> trustedLists) {}

    private record Retained(Generation generation, java.time.Instant until) {}

    private volatile Generation current;
    /** Replaced configurations, kept until every session started under them has expired. */
    private final Map<String, Retained> retained = new ConcurrentHashMap<>();

    private String fingerprint;
    private String failedFingerprint;
    private HttpFetcher listFetcher;
    private HttpFetcher crlFetcher;
    private volatile boolean trustedListsAttempted;
    private DataProtection dataProtection;
    private static final Logger LOG = Logger.getLogger(AdapterRuntime.class);

    private Clock clock = Clock.systemUTC();
    private HttpFetcher fetcher;

    @PostConstruct
    void init() {
        if (brainpool) {
            io.github.suengineering.eudiw.crypto.brainpool.BrainpoolSupport.enable();
            LOG.info("brainpool curves enabled for mdoc signatures (eudiw.crypto.brainpool)");
        }
        URI base = URI.create(publicBaseUrl);
        if (production) {
            if (!"https".equals(base.getScheme())) {
                throw new ConfigLoader.ConfigException("eudiw.public-base-url must use https in production");
            }
            if (allowPrivateAddresses || allowHttp) {
                throw new ConfigLoader.ConfigException("development egress settings are not allowed in production");
            }
            var settings = org.eclipse.microprofile.config.ConfigProvider.getConfig();
            for (String required : new String[] {"quarkus.oidc.auth-server-url", "quarkus.oidc.token.audience"}) {
                String value = settings.getOptionalValue(required, String.class).orElse("");
                if (value.isBlank()) {
                    throw new ConfigLoader.ConfigException(
                            required + " must be set in production (EUDIW_OIDC_ISSUER, EUDIW_OIDC_AUDIENCE)");
                }
            }
        }
        byte[] key;
        try {
            key = Base64.getDecoder().decode(dataKey);
        } catch (IllegalArgumentException e) {
            throw new ConfigLoader.ConfigException("eudiw.data-key must be base64", e);
        }
        dataProtection = new DataProtection(key);
        fingerprint = fingerprint();
        AdapterConfig loaded = ConfigLoader.load(Path.of(configFile), production);
        if (fetcher == null) {
            Set<String> hosts = allowedHosts.orElse(java.util.List.of()).stream()
                    .map(String::strip)
                    .filter(h -> !h.isEmpty())
                    .map(h -> h.toLowerCase(java.util.Locale.ROOT))
                    .collect(java.util.stream.Collectors.toUnmodifiableSet());
            fetcher = new JdkHttpFetcher(
                    new EgressPolicy(allowHttp, allowPrivateAddresses, hosts), Duration.ofSeconds(5));
            // National trusted lists run to several megabytes.
            listFetcher = new JdkHttpFetcher(
                    new EgressPolicy(allowHttp, allowPrivateAddresses, hosts), Duration.ofSeconds(30));
            // CRLs are signed and usually published over plain HTTP; private addresses stay blocked.
            crlFetcher =
                    new JdkHttpFetcher(new EgressPolicy(true, allowPrivateAddresses, hosts), Duration.ofSeconds(10));
        }
        current = build(loaded);
    }

    private Generation build(AdapterConfig config) {
        Map<String, VpTokenVerifier> verifiers = new ConcurrentHashMap<>();
        Map<String, TrustedLists> trustedLists = new ConcurrentHashMap<>();
        for (Tenant tenant : config.tenants().values()) {
            for (Policy policy : tenant.policies().values()) {
                TrustStore configured = TrustStore.ofAnchors(policy.trustAnchors());
                TrustedLists lists = new TrustedLists(
                        policy.trustedLists(),
                        listFetcher == null ? fetcher : listFetcher,
                        clock,
                        configured,
                        sequenceStore);
                trustedLists.put(key(tenant.id(), policy.id()), lists);
                Supplier<TrustStore> issuance = lists::issuance;
                Supplier<TrustStore> status = lists::status;
                StatusListChecker checker = new StatusListChecker(
                        fetcher,
                        () -> status.get().anchors(),
                        AlgorithmPolicy.DEFAULT,
                        clock,
                        Duration.ofSeconds(60),
                        Duration.ofMinutes(15),
                        1000);
                CrlRevocationChecker crls = policy.checkCertificateRevocation()
                        ? new CrlRevocationChecker(crlFetcher == null ? fetcher : crlFetcher, clock, 256)
                        : null;
                Optional<MdocPresentationVerifier> mdoc = Optional.empty();
                if (policy.query().credentials().stream().anyMatch(c -> DcqlQuery.FORMAT_MDOC.equals(c.format()))) {
                    mdoc = Optional.of(new MdocPresentationVerifier(
                            new MdocIssuerVerifier(
                                    issuance, clock, Duration.ofSeconds(60), crls, MdocIssuerVerifier.mdlOnly()),
                            policy.mdocStrictConformance()
                                    ? MdocDeviceAuthentication.STRICT_SIGNATURE
                                    : MdocDeviceAuthentication.SIGNATURE));
                }
                X5cIssuerKeyResolver issuerKeys = (policy.checkCertificateRevocation()
                                ? X5cIssuerKeyResolver.withTrustStore(
                                        issuance,
                                        clock,
                                        new CrlRevocationChecker(crlFetcher == null ? fetcher : crlFetcher, clock, 256))
                                : X5cIssuerKeyResolver.withTrustStore(issuance, clock))
                        .requiringExtendedKeyUsage(policy.issuerExtendedKeyUsages());
                VpTokenVerifier verifier = new VpTokenVerifier(
                        new SdJwtVcVerifier(issuerKeys, false),
                        mdoc,
                        policy.statusPolicy() == StatusPolicy.IGNORE ? Optional.empty() : Optional.of(checker),
                        new VpTokenVerifier.Settings(
                                clock,
                                Duration.ofMinutes(5),
                                Duration.ofSeconds(60),
                                AlgorithmPolicy.DEFAULT,
                                policy.enforceTrustedAuthorities(),
                                policy.statusPolicy(),
                                policy.requireStatus(),
                                policy.statusSigner()));
                verifiers.put(key(tenant.id(), policy.id()), verifier);
            }
        }
        return new Generation(config, Map.copyOf(verifiers), Map.copyOf(trustedLists));
    }

    /**
     * Reloads the configuration when the tenants file or any file under its directory changed. A configuration
     * that fails validation is logged and ignored: the running one stays. The replaced configuration is kept for
     * the longest session lifetime, so sessions started under it finish under the same rules. Safe to call often;
     * an unchanged directory costs one walk over file sizes and modification times.
     *
     * @return whether a new configuration became active
     */
    public synchronized boolean reloadIfChanged() {
        String now = fingerprint();
        if (now.equals(fingerprint) || now.equals(failedFingerprint)) {
            return false;
        }
        AdapterConfig loaded;
        try {
            loaded = ConfigLoader.load(Path.of(configFile), production);
        } catch (RuntimeException e) {
            failedFingerprint = now;
            count("failed");
            LOG.errorf(
                    "configuration not reloaded, keeping revision %s: %s",
                    current.config().revision(), e.getMessage());
            return false;
        }
        fingerprint = now;
        failedFingerprint = null;
        if (loaded.revision().equals(current.config().revision())) {
            return false;
        }
        Generation next = build(loaded);
        refresh(next);
        Generation previous = current;
        current = next;
        java.time.Instant until = clock.instant().plus(AdapterConfig.MAX_SESSION_TTL);
        retained.put(previous.config().revision(), new Retained(previous, until));
        retained.values().removeIf(r -> !r.until().isAfter(clock.instant()));
        count("ok");
        LOG.infof(
                "configuration reloaded: revision %s replaces %s",
                loaded.revision(), previous.config().revision());
        return true;
    }

    private void count(String outcome) {
        if (registry != null) {
            registry.counter("eudiw.config.reloads", "outcome", outcome).increment();
        }
    }

    /** Sizes and modification times of the tenants file's directory tree, plus the tenants file's content. */
    private String fingerprint() {
        Path file = Path.of(configFile).toAbsolutePath();
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            digest.update(java.nio.file.Files.readAllBytes(file));
            try (var paths = java.nio.file.Files.walk(file.getParent(), 4)) {
                for (Path path : paths.filter(java.nio.file.Files::isRegularFile)
                        .sorted()
                        .limit(2000)
                        .toList()) {
                    digest.update((path + "\n" + java.nio.file.Files.size(path) + "\n"
                                    + java.nio.file.Files.getLastModifiedTime(path)
                                            .toMillis() + "\n")
                            .getBytes(java.nio.charset.StandardCharsets.UTF_8));
                }
            }
            return java.util.HexFormat.of().formatHex(digest.digest());
        } catch (java.io.IOException | java.security.NoSuchAlgorithmException e) {
            return "unreadable";
        }
    }

    private Generation generation(String revision) {
        Generation active = current;
        if (active.config().revision().equals(revision)) {
            return active;
        }
        Retained old = retained.get(revision);
        if (old != null && old.until().isAfter(clock.instant())) {
            return old.generation();
        }
        // Another node may have reloaded first: pick up a changed file before failing the session.
        if (reloadIfChanged() && current.config().revision().equals(revision)) {
            return current;
        }
        return null;
    }

    /** The configuration a session started under, while this node still holds it. */
    public Optional<AdapterConfig> config(String revision) {
        return Optional.ofNullable(generation(revision)).map(Generation::config);
    }

    /** Fetches and verifies every configured trusted list. Failures are logged by location and code only. */
    public void refreshTrustedLists() {
        refresh(current);
    }

    private void refresh(Generation generation) {
        try {
            for (Map.Entry<String, TrustedLists> entry :
                    generation.trustedLists().entrySet()) {
                if (entry.getValue().isEmpty()) {
                    continue;
                }
                try {
                    for (TrustedLists.LoadResult result : entry.getValue().refresh()) {
                        if (registry != null) {
                            registry.counter(
                                            "eudiw.trusted.list.refreshes",
                                            "outcome",
                                            result.ok() ? "ok" : "failed",
                                            "code",
                                            result.ok() ? "none" : result.code())
                                    .increment();
                        }
                        if (!result.ok()) {
                            LOG.warnf("trusted list %s not updated: %s", result.location(), result.code());
                        }
                    }
                } catch (RuntimeException e) {
                    LOG.warnf(
                            "trusted lists of policy %s not updated: %s",
                            entry.getKey().replace('\n', '/'), e.getClass().getSimpleName());
                }
            }
        } finally {
            trustedListsAttempted = true;
        }
    }

    /** Whether the client has a webhook, so its finished sessions queue a notification. */
    public boolean notifies(String tenantId, String clientId) {
        return current.config()
                .tenant(tenantId)
                .map(t -> t.clients().get(clientId))
                .map(c -> c.webhook().isPresent())
                .orElse(false);
    }

    /** Client ids that have a webhook. */
    public Set<String> webhookClients() {
        Set<String> clients = new java.util.HashSet<>();
        for (Tenant tenant : current.config().tenants().values()) {
            tenant.clients().values().stream()
                    .filter(c -> c.webhook().isPresent())
                    .forEach(c -> clients.add(c.clientId()));
        }
        return clients;
    }

    /** Whether the first trusted list refresh has run (readiness waits for it). */
    public boolean trustedListsAttempted() {
        return trustedListsAttempted || current.trustedLists().values().stream().allMatch(TrustedLists::isEmpty);
    }

    /** Policies that use trusted lists, as {@code tenant/policy}. */
    public List<String> policiesUsingTrustedLists() {
        List<String> using = new ArrayList<>();
        current.trustedLists().forEach((key, lists) -> {
            if (!lists.isEmpty()) {
                using.add(key.replace('\n', '/'));
            }
        });
        return using;
    }

    /** Policies that use trusted lists but have no current list. Their verifications fail closed. */
    public List<String> policiesWithoutCurrentTrustedLists() {
        List<String> missing = new ArrayList<>();
        current.trustedLists().forEach((key, lists) -> {
            if (!lists.hasCurrentList()) {
                missing.add(key.replace('\n', '/'));
            }
        });
        return missing;
    }

    /** Test hook: replace the clock and network access, then rebuild the verifiers. */
    public void reconfigureForTests(Clock testClock, HttpFetcher testFetcher) {
        this.clock = testClock;
        this.fetcher = testFetcher;
        this.listFetcher = testFetcher;
        this.crlFetcher = testFetcher;
        retained.clear();
        current = build(current.config());
    }

    /** The active configuration. Sessions use {@link #config(String)} with the revision they started under. */
    public AdapterConfig config() {
        return current.config();
    }

    public DataProtection dataProtection() {
        return dataProtection;
    }

    public Clock clock() {
        return clock;
    }

    public URI publicBaseUrl() {
        return URI.create(publicBaseUrl.endsWith("/") ? publicBaseUrl : publicBaseUrl + "/");
    }

    /** The verifier of a policy as configured in {@code revision}. */
    public VpTokenVerifier verifier(String revision, String tenantId, String policyId) {
        Generation generation = generation(revision);
        VpTokenVerifier verifier =
                generation == null ? null : generation.verifiers().get(key(tenantId, policyId));
        if (verifier == null) {
            throw new IllegalStateException("no verifier for policy");
        }
        return verifier;
    }

    private static String key(String tenantId, String policyId) {
        return tenantId + "\n" + policyId;
    }
}
