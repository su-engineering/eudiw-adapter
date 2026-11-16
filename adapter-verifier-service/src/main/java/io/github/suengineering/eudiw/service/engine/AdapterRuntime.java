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

import io.github.suengineering.eudiw.core.jose.AlgorithmPolicy;
import io.github.suengineering.eudiw.core.net.EgressPolicy;
import io.github.suengineering.eudiw.core.net.HttpFetcher;
import io.github.suengineering.eudiw.core.net.JdkHttpFetcher;
import io.github.suengineering.eudiw.core.oid4vp.VpTokenVerifier;
import io.github.suengineering.eudiw.core.oid4vp.VpTokenVerifier.StatusPolicy;
import io.github.suengineering.eudiw.core.sdjwt.SdJwtVcVerifier;
import io.github.suengineering.eudiw.core.sdjwt.X5cIssuerKeyResolver;
import io.github.suengineering.eudiw.core.status.StatusListChecker;
import io.github.suengineering.eudiw.core.trust.TrustedLists;
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

    private AdapterConfig config;
    private DataProtection dataProtection;
    private static final Logger LOG = Logger.getLogger(AdapterRuntime.class);

    private final Map<String, VpTokenVerifier> verifiers = new ConcurrentHashMap<>();
    private final Map<String, TrustedLists> trustedLists = new ConcurrentHashMap<>();
    private Clock clock = Clock.systemUTC();
    private HttpFetcher fetcher;

    @PostConstruct
    void init() {
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
        config = ConfigLoader.load(Path.of(configFile), production);
        if (fetcher == null) {
            fetcher = new JdkHttpFetcher(
                    new EgressPolicy(allowHttp, allowPrivateAddresses, Set.of()), Duration.ofSeconds(5));
        }
        buildVerifiers();
    }

    private void buildVerifiers() {
        verifiers.clear();
        trustedLists.clear();
        for (Tenant tenant : config.tenants().values()) {
            for (Policy policy : tenant.policies().values()) {
                TrustStore configured = TrustStore.ofAnchors(policy.trustAnchors());
                TrustedLists lists = new TrustedLists(policy.trustedLists(), fetcher, clock);
                trustedLists.put(key(tenant.id(), policy.id()), lists);
                Supplier<TrustStore> issuance =
                        lists.isEmpty() ? () -> configured : () -> configured.merge(lists.issuance());
                Supplier<TrustStore> status =
                        lists.isEmpty() ? () -> configured : () -> configured.merge(lists.status());
                StatusListChecker checker = new StatusListChecker(
                        fetcher,
                        () -> status.get().anchors(),
                        AlgorithmPolicy.DEFAULT,
                        clock,
                        Duration.ofSeconds(60),
                        Duration.ofMinutes(15),
                        1000);
                VpTokenVerifier verifier = new VpTokenVerifier(
                        new SdJwtVcVerifier(X5cIssuerKeyResolver.withTrustStore(issuance, clock), false),
                        policy.statusPolicy() == StatusPolicy.IGNORE ? Optional.empty() : Optional.of(checker),
                        new VpTokenVerifier.Settings(
                                clock,
                                Duration.ofMinutes(5),
                                Duration.ofSeconds(60),
                                AlgorithmPolicy.DEFAULT,
                                policy.enforceTrustedAuthorities(),
                                policy.statusPolicy()));
                verifiers.put(key(tenant.id(), policy.id()), verifier);
            }
        }
    }

    /** Fetches and verifies every configured trusted list. Failures are logged by location and code only. */
    public void refreshTrustedLists() {
        for (Map.Entry<String, TrustedLists> entry : trustedLists.entrySet()) {
            if (entry.getValue().isEmpty()) {
                continue;
            }
            for (TrustedLists.LoadResult result : entry.getValue().refresh()) {
                if (!result.ok()) {
                    LOG.warnf("trusted list %s not updated: %s", result.location(), result.code());
                }
            }
        }
    }

    /** Policies that use trusted lists but currently trust no certificate from them. */
    public List<String> policiesWithoutCurrentTrustedLists() {
        List<String> missing = new ArrayList<>();
        trustedLists.forEach((key, lists) -> {
            if (!lists.isEmpty() && lists.issuance().isEmpty()) {
                missing.add(key.replace('\n', '/'));
            }
        });
        return missing;
    }

    /** Test hook: replace the clock and network access, then rebuild the verifiers. */
    public void reconfigureForTests(Clock testClock, HttpFetcher testFetcher) {
        this.clock = testClock;
        this.fetcher = testFetcher;
        buildVerifiers();
    }

    public AdapterConfig config() {
        return config;
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

    public VpTokenVerifier verifier(String tenantId, String policyId) {
        VpTokenVerifier verifier = verifiers.get(key(tenantId, policyId));
        if (verifier == null) {
            throw new IllegalStateException("no verifier for policy");
        }
        return verifier;
    }

    private static String key(String tenantId, String policyId) {
        return tenantId + "\n" + policyId;
    }
}
