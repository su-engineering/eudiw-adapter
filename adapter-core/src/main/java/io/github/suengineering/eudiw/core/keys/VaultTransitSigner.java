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
package io.github.suengineering.eudiw.core.keys;

import com.nimbusds.jose.JOSEException;
import io.github.suengineering.eudiw.core.json.Json;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.regex.Pattern;

/**
 * Signs with an {@code ecdsa-p256} key in HashiCorp Vault's Transit secrets engine. The SHA-256 digest is computed
 * here and sent with {@code prehashed=true}; Vault returns the signature in JWS form ({@code
 * marshaling_algorithm=jws}), already the {@code R || S} value. The key never leaves Vault.
 *
 * <p>The token is read from {@code tokenFile} on every signature, so an agent (Vault Agent, a CSI driver) can
 * renew or replace it without a configuration reload.
 */
public final class VaultTransitSigner implements RequestSigner {

    private static final Pattern NAME = Pattern.compile("[A-Za-z0-9_.-]{1,128}");
    private static final Pattern MOUNT = Pattern.compile("[A-Za-z0-9_.-]{1,128}(/[A-Za-z0-9_.-]{1,128}){0,7}");
    static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(5);
    static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(10);

    /**
     * @param address Vault's base address, for example {@code https://vault.example:8200}
     * @param mount path of the Transit engine, {@code transit} by default
     * @param keyName name of the {@code ecdsa-p256} Transit key
     * @param keyVersion the key version to sign with; empty signs with the latest version
     * @param namespace Vault Enterprise namespace ({@code X-Vault-Namespace}), if any
     * @param tokenFile file holding the Vault token
     */
    public record Settings(
            URI address,
            String mount,
            String keyName,
            OptionalInt keyVersion,
            Optional<String> namespace,
            Path tokenFile) {

        public Settings {
            Objects.requireNonNull(address, "address");
            Objects.requireNonNull(keyVersion, "keyVersion");
            Objects.requireNonNull(namespace, "namespace");
            Objects.requireNonNull(tokenFile, "tokenFile");
            if (!("https".equals(address.getScheme()) || "http".equals(address.getScheme()))
                    || address.getHost() == null
                    || address.getRawQuery() != null
                    || address.getRawFragment() != null) {
                throw new IllegalArgumentException("vault_transit.address must be an http or https URL");
            }
            if (mount == null || !MOUNT.matcher(mount).matches()) {
                throw new IllegalArgumentException("vault_transit.mount must be a Vault path such as transit");
            }
            if (keyName == null || !NAME.matcher(keyName).matches()) {
                throw new IllegalArgumentException(
                        "vault_transit.key_name must be 1 to 128 letters, digits, '_', '.' or '-'");
            }
            if (keyVersion.isPresent() && keyVersion.getAsInt() < 1) {
                throw new IllegalArgumentException("vault_transit.key_version must be 1 or more");
            }
        }
    }

    private final Settings settings;
    private final URI signUri;
    private final HttpClient client;

    public VaultTransitSigner(Settings settings) {
        this.settings = Objects.requireNonNull(settings, "settings");
        String base = settings.address().toString().replaceAll("/+$", "");
        this.signUri = URI.create(base + "/v1/" + settings.mount() + "/sign/" + settings.keyName() + "/sha2-256");
        this.client = HttpClient.newBuilder()
                .connectTimeout(CONNECT_TIMEOUT)
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    @Override
    public byte[] signEs256(byte[] data) throws JOSEException {
        String token = token();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("input", Base64.getEncoder().encodeToString(sha256(data)));
        body.put("prehashed", true);
        body.put("marshaling_algorithm", "jws");
        settings.keyVersion().ifPresent(v -> body.put("key_version", v));
        HttpRequest.Builder request = HttpRequest.newBuilder(signUri)
                .timeout(REQUEST_TIMEOUT)
                .header("X-Vault-Token", token)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(Json.toJson(body)));
        settings.namespace().ifPresent(ns -> request.header("X-Vault-Namespace", ns));
        HttpResponse<String> response;
        try {
            response = client.send(request.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new JOSEException("Vault Transit cannot be reached at " + settings.address() + ": "
                    + e.getClass().getSimpleName());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new JOSEException("interrupted while signing with Vault Transit");
        }
        if (response.statusCode() != 200) {
            throw new JOSEException("Vault Transit refused to sign with key " + settings.keyName() + ": HTTP "
                    + response.statusCode() + errors(response.body()));
        }
        return signature(response.body());
    }

    private String token() throws JOSEException {
        try {
            String token = Files.readString(settings.tokenFile(), StandardCharsets.US_ASCII)
                    .strip();
            if (token.isEmpty() || !token.chars().allMatch(c -> c > 0x20 && c < 0x7f)) {
                throw new JOSEException("the Vault token file is empty or not a token: " + settings.tokenFile());
            }
            return token;
        } catch (IOException e) {
            throw new JOSEException("cannot read the Vault token file " + settings.tokenFile());
        }
    }

    /** {@code data.signature} is {@code vault:v<version>:<base64url R || S>}. */
    private static byte[] signature(String body) throws JOSEException {
        try {
            Object data = Json.parseObject(body, "vault_response").get("data");
            Object value = data instanceof Map<?, ?> map ? map.get("signature") : null;
            if (!(value instanceof String signature) || !signature.startsWith("vault:v")) {
                throw new JOSEException("Vault Transit returned no signature");
            }
            byte[] concat = Base64.getUrlDecoder().decode(signature.substring(signature.lastIndexOf(':') + 1));
            if (concat.length != 64) {
                throw new JOSEException("Vault Transit returned a signature that is not ES256; is the key ecdsa-p256?");
            }
            return concat;
        } catch (RuntimeException e) {
            throw new JOSEException("Vault Transit returned an unreadable response");
        }
    }

    /** Vault's {@code errors} array, which names the problem (such as {@code permission denied}), shortened. */
    private static String errors(String body) {
        try {
            Object errors = Json.parseObject(body, "vault_response").get("errors");
            if (errors instanceof List<?> list && !list.isEmpty()) {
                String text =
                        String.join("; ", list.stream().map(String::valueOf).toList());
                return ": " + (text.length() > 200 ? text.substring(0, 200) + "..." : text);
            }
        } catch (RuntimeException e) {
            // not JSON; the status says enough
        }
        return "";
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
