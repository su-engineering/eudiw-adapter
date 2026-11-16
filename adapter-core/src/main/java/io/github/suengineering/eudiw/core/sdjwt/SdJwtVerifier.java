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
package io.github.suengineering.eudiw.core.sdjwt;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.jwk.JWK;
import io.github.suengineering.eudiw.core.VerificationFailure;
import io.github.suengineering.eudiw.core.jose.JwsSignatureVerifier;
import io.github.suengineering.eudiw.core.json.Json;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Verifies SD-JWT and SD-JWT+KB presentations as specified in RFC 9901 sections 7.1 and 7.3. Every check that
 * fails throws a {@link VerificationFailure} with a stable code; nothing partially verified is returned.
 */
public final class SdJwtVerifier {

    private static final String SD = "_sd";
    private static final String ELLIPSIS = "...";
    private static final String SD_ALG = "_sd_alg";
    private static final JOSEObjectType KB_JWT_TYPE = new JOSEObjectType("kb+jwt");
    // 9999-12-31T23:59:59Z; larger NumericDates are treated as malformed
    private static final double MAX_NUMERIC_DATE = 253_402_300_799d;

    private final IssuerKeyResolver issuerKeyResolver;

    public SdJwtVerifier(IssuerKeyResolver issuerKeyResolver) {
        this.issuerKeyResolver = Objects.requireNonNull(issuerKeyResolver, "issuerKeyResolver");
    }

    public VerifiedSdJwt verify(String serialized, SdJwtVerificationOptions options) {
        Objects.requireNonNull(options, "options");
        try {
            return verifyUnchecked(serialized, options);
        } catch (VerificationFailure failure) {
            throw failure;
        } catch (RuntimeException e) {
            // Hostile input must never surface as anything other than a rejection.
            throw new VerificationFailure("unprocessable_presentation", "presentation could not be processed", e);
        }
    }

    private VerifiedSdJwt verifyUnchecked(String serialized, SdJwtVerificationOptions options) {
        SdJwtPresentation presentation =
                SdJwtPresentation.parse(serialized, options.maxLength(), options.maxDisclosures());

        // RFC 9901 7.3 step 2: the policy, not the presentation, decides whether key binding is needed.
        if (options.keyBindingRequired() && presentation.keyBindingJwt().isEmpty()) {
            throw new VerificationFailure("key_binding_required", "key binding is required but absent");
        }

        // 7.1 step 2: validate the Issuer-signed JWT.
        JWSObject issuerJws = parseJws(presentation.issuerSignedJwt(), "malformed_sd_jwt");
        Map<String, Object> signedPayload =
                Json.parseObject(issuerJws.getPayload().toString(), "malformed_sd_jwt");
        IssuerKeyResolver.ResolvedIssuerKey issuerKey = issuerKeyResolver.resolve(issuerJws.getHeader(), signedPayload);
        if (issuerKey == null) {
            throw new VerificationFailure("issuer_untrusted", "no permitted issuer key");
        }
        JwsSignatureVerifier.verify(issuerJws, issuerKey.key(), options.algorithms());

        String hashAlgorithm = hashAlgorithm(signedPayload, options);

        // 7.1 step 3: match Disclosures to embedded digests.
        Map<String, Disclosure> disclosuresByDigest = new HashMap<>();
        for (String encoded : presentation.disclosures()) {
            Disclosure disclosure = Disclosure.decode(encoded);
            String digest = digest(hashAlgorithm, encoded);
            if (disclosuresByDigest.putIfAbsent(digest, disclosure) != null) {
                throw new VerificationFailure("duplicate_disclosure", "the same Disclosure was presented twice");
            }
        }
        Processor processor = new Processor(disclosuresByDigest);
        Map<String, Object> processed = processor.processObject(signedPayload, 1, true);

        // 7.1 step 5: every presented Disclosure must be referenced.
        if (processor.used.size() != disclosuresByDigest.size()) {
            throw new VerificationFailure(
                    "unreferenced_disclosure", "a Disclosure is not referenced by the Issuer-signed JWT");
        }

        // 7.1 step 6: validity-controlling claims.
        checkValidityWindow(processed, options);

        Optional<JWK> holderKey = holderKey(processed);
        boolean keyBindingVerified = false;
        if (options.keyBindingRequired()) {
            JWK key = holderKey.orElseThrow(() -> new VerificationFailure(
                    "holder_key_missing", "key binding is required but the credential has no cnf.jwk"));
            verifyKeyBinding(presentation, key, hashAlgorithm, options);
            keyBindingVerified = true;
        }

        return new VerifiedSdJwt(
                issuerJws.getHeader(),
                issuerKey.issuer(),
                deepUnmodifiable(processed),
                Collections.unmodifiableSet(processor.disclosedTopLevel),
                holderKey,
                keyBindingVerified,
                issuerKey.certificateChain());
    }

    private static String hashAlgorithm(Map<String, Object> payload, SdJwtVerificationOptions options) {
        Object value = payload.get(SD_ALG);
        String name;
        if (value == null) {
            name = "sha-256";
        } else if (value instanceof String s) {
            name = s;
        } else {
            throw new VerificationFailure("malformed_sd_jwt", "_sd_alg must be a string");
        }
        if (!options.hashAlgorithms().contains(name)) {
            throw new VerificationFailure("unsupported_hash_algorithm", "hash algorithm not allowed: " + name);
        }
        return name;
    }

    static String digest(String hashAlgorithm, String asciiInput) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digestBytes(hashAlgorithm, asciiInput));
    }

    private static byte[] digestBytes(String hashAlgorithm, String asciiInput) {
        String javaName =
                switch (hashAlgorithm) {
                    case "sha-256" -> "SHA-256";
                    case "sha-384" -> "SHA-384";
                    case "sha-512" -> "SHA-512";
                    default -> throw new VerificationFailure("unsupported_hash_algorithm", hashAlgorithm);
                };
        try {
            return MessageDigest.getInstance(javaName).digest(asciiInput.getBytes(StandardCharsets.US_ASCII));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(javaName + " not available", e);
        }
    }

    private static void checkValidityWindow(Map<String, Object> payload, SdJwtVerificationOptions options) {
        Instant now = options.clock().instant();
        Instant exp = numericDate(payload, "exp", "malformed_sd_jwt");
        if (exp != null && now.isAfter(exp.plus(options.clockSkew()))) {
            throw new VerificationFailure("credential_expired", "credential has expired");
        }
        Instant nbf = numericDate(payload, "nbf", "malformed_sd_jwt");
        if (nbf != null && now.plus(options.clockSkew()).isBefore(nbf)) {
            throw new VerificationFailure("credential_not_yet_valid", "credential is not yet valid");
        }
    }

    private static Optional<JWK> holderKey(Map<String, Object> payload) {
        Object cnf = payload.get("cnf");
        if (cnf == null) {
            return Optional.empty();
        }
        if (!(cnf instanceof Map<?, ?> cnfMap)) {
            throw new VerificationFailure("malformed_sd_jwt", "cnf must be an object");
        }
        Object jwk = cnfMap.get("jwk");
        if (jwk == null) {
            return Optional.empty();
        }
        if (!(jwk instanceof Map<?, ?>)) {
            throw new VerificationFailure("malformed_sd_jwt", "cnf.jwk must be an object");
        }
        try {
            @SuppressWarnings("unchecked")
            JWK key = JWK.parse((Map<String, Object>) jwk);
            if (key.isPrivate()) {
                throw new VerificationFailure("malformed_sd_jwt", "cnf.jwk contains private key material");
            }
            return Optional.of(key);
        } catch (ParseException e) {
            throw new VerificationFailure("malformed_sd_jwt", "cnf.jwk is not a valid JWK", e);
        }
    }

    private static void verifyKeyBinding(
            SdJwtPresentation presentation, JWK holderKey, String hashAlgorithm, SdJwtVerificationOptions options) {
        JWSObject kbJws = parseJws(presentation.keyBindingJwt().orElseThrow(), "invalid_key_binding");
        if (!KB_JWT_TYPE.equals(kbJws.getHeader().getType())) {
            throw new VerificationFailure("invalid_key_binding", "Key Binding JWT typ must be kb+jwt");
        }
        try {
            JwsSignatureVerifier.verify(kbJws, holderKey, options.algorithms());
        } catch (VerificationFailure failure) {
            throw new VerificationFailure(
                    "invalid_key_binding", "Key Binding JWT signature: " + failure.getMessage(), failure);
        }
        Map<String, Object> claims = Json.parseObject(kbJws.getPayload().toString(), "invalid_key_binding");

        Instant now = options.clock().instant();
        Instant iat = numericDate(claims, "iat", "invalid_key_binding");
        if (iat == null) {
            throw new VerificationFailure("invalid_key_binding", "Key Binding JWT has no iat");
        }
        if (iat.isAfter(now.plus(options.clockSkew()))) {
            throw new VerificationFailure("key_binding_stale", "Key Binding JWT iat is in the future");
        }
        if (iat.isBefore(now.minus(options.keyBindingMaxAge()).minus(options.clockSkew()))) {
            throw new VerificationFailure("key_binding_stale", "Key Binding JWT is too old");
        }
        if (!(claims.get("aud") instanceof String aud) || !aud.equals(options.expectedAudience())) {
            throw new VerificationFailure("key_binding_audience_mismatch", "Key Binding JWT aud does not match");
        }
        if (!(claims.get("nonce") instanceof String nonce) || !nonce.equals(options.expectedNonce())) {
            throw new VerificationFailure("key_binding_nonce_mismatch", "Key Binding JWT nonce does not match");
        }
        if (!(claims.get("sd_hash") instanceof String sdHash)) {
            throw new VerificationFailure("sd_hash_mismatch", "Key Binding JWT has no sd_hash");
        }
        byte[] expected = digestBytes(hashAlgorithm, presentation.sdJwtPart());
        byte[] actual;
        try {
            actual = Base64.getUrlDecoder().decode(sdHash);
        } catch (IllegalArgumentException e) {
            throw new VerificationFailure("sd_hash_mismatch", "sd_hash is not base64url", e);
        }
        if (!MessageDigest.isEqual(expected, actual)) {
            throw new VerificationFailure("sd_hash_mismatch", "sd_hash does not match the presented SD-JWT");
        }
    }

    private static Instant numericDate(Map<String, Object> claims, String name, String failureCode) {
        Object value = claims.get(name);
        if (value == null) {
            return null;
        }
        if (!(value instanceof Number number)) {
            throw new VerificationFailure(failureCode, name + " must be a NumericDate");
        }
        double seconds = number.doubleValue();
        if (!Double.isFinite(seconds) || seconds < 0 || seconds > MAX_NUMERIC_DATE) {
            throw new VerificationFailure(failureCode, name + " is out of range");
        }
        long whole = (long) Math.floor(seconds);
        return Instant.ofEpochSecond(whole, (long) ((seconds - whole) * 1_000_000_000L));
    }

    private static JWSObject parseJws(String compact, String failureCode) {
        try {
            return JWSObject.parse(compact);
        } catch (ParseException e) {
            throw new VerificationFailure(failureCode, "not a valid compact JWS", e);
        }
    }

    @SuppressWarnings("unchecked")
    private static <T> T deepUnmodifiable(T value) {
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> copy = new LinkedHashMap<>();
            map.forEach((k, v) -> copy.put((String) k, deepUnmodifiable(v)));
            return (T) Collections.unmodifiableMap(copy);
        }
        if (value instanceof List<?> list) {
            List<Object> copy = new ArrayList<>(list.size());
            list.forEach(v -> copy.add(deepUnmodifiable(v)));
            return (T) Collections.unmodifiableList(copy);
        }
        return value;
    }

    /** A decoded Disclosure: {@code [salt, name, value]} for object properties or {@code [salt, value]}. */
    record Disclosure(String name, Object value, boolean arrayElement) {

        static Disclosure decode(String encoded) {
            byte[] bytes;
            try {
                bytes = Base64.getUrlDecoder().decode(encoded);
            } catch (IllegalArgumentException e) {
                throw new VerificationFailure("invalid_disclosure", "Disclosure is not base64url", e);
            }
            String json;
            try {
                json = StandardCharsets.UTF_8
                        .newDecoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT)
                        .decode(ByteBuffer.wrap(bytes))
                        .toString();
            } catch (CharacterCodingException e) {
                throw new VerificationFailure("invalid_disclosure", "Disclosure is not UTF-8", e);
            }
            List<Object> array = Json.parseArray(json, "invalid_disclosure");
            if (array.size() != 2 && array.size() != 3) {
                throw new VerificationFailure("invalid_disclosure", "Disclosure must have two or three elements");
            }
            if (!(array.get(0) instanceof String)) {
                throw new VerificationFailure("invalid_disclosure", "Disclosure salt must be a string");
            }
            if (array.size() == 2) {
                return new Disclosure(null, array.get(1), true);
            }
            if (!(array.get(1) instanceof String name)) {
                throw new VerificationFailure("invalid_disclosure", "Disclosure claim name must be a string");
            }
            return new Disclosure(name, array.get(2), false);
        }
    }

    /** Implements steps (*) and (**) of RFC 9901 section 7.1 step 3, with the checks of steps 4 and 5. */
    private static final class Processor {

        private final Map<String, Disclosure> disclosuresByDigest;
        private final Set<String> seen = new HashSet<>();
        private final Set<String> used = new HashSet<>();
        private final Set<String> disclosedTopLevel = new LinkedHashSet<>();

        Processor(Map<String, Disclosure> disclosuresByDigest) {
            this.disclosuresByDigest = disclosuresByDigest;
        }

        Map<String, Object> processObject(Map<String, Object> in, int depth, boolean topLevel) {
            checkDepth(depth);
            if (in.containsKey(ELLIPSIS)) {
                throw new VerificationFailure("malformed_sd_jwt", "'...' is only allowed in array elements");
            }
            if (!topLevel && in.containsKey(SD_ALG)) {
                throw new VerificationFailure("malformed_sd_jwt", "_sd_alg is only allowed at the top level");
            }
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<String, Object> entry : in.entrySet()) {
                String name = entry.getKey();
                if (SD.equals(name) || (topLevel && SD_ALG.equals(name))) {
                    continue;
                }
                out.put(name, processValue(entry.getValue(), depth + 1));
            }

            Object sd = in.get(SD);
            if (sd == null) {
                return out;
            }
            if (!(sd instanceof List<?> digests)) {
                throw new VerificationFailure("malformed_sd_jwt", "_sd must be an array of strings");
            }
            for (Object item : digests) {
                if (!(item instanceof String digest)) {
                    throw new VerificationFailure("malformed_sd_jwt", "_sd must be an array of strings");
                }
                markSeen(digest);
                Disclosure disclosure = disclosuresByDigest.get(digest);
                if (disclosure == null) {
                    continue; // decoy or undisclosed claim
                }
                if (disclosure.arrayElement()) {
                    throw new VerificationFailure(
                            "invalid_disclosure", "object property digest refers to an array element Disclosure");
                }
                String name = disclosure.name();
                if (SD.equals(name) || ELLIPSIS.equals(name) || SD_ALG.equals(name)) {
                    throw new VerificationFailure("invalid_disclosure", "Disclosure uses a reserved claim name");
                }
                if (out.containsKey(name) || in.containsKey(name)) {
                    throw new VerificationFailure("claim_name_conflict", "Disclosure repeats an existing claim name");
                }
                used.add(digest);
                out.put(name, processValue(disclosure.value(), depth + 1));
                if (topLevel) {
                    disclosedTopLevel.add(name);
                }
            }
            return out;
        }

        private List<Object> processArray(List<Object> in, int depth) {
            checkDepth(depth);
            List<Object> out = new ArrayList<>(in.size());
            for (Object element : in) {
                if (element instanceof Map<?, ?> map && map.containsKey(ELLIPSIS)) {
                    if (map.size() != 1 || !(map.get(ELLIPSIS) instanceof String digest)) {
                        throw new VerificationFailure(
                                "malformed_sd_jwt", "array element digest must be {\"...\": \"<digest>\"}");
                    }
                    markSeen(digest);
                    Disclosure disclosure = disclosuresByDigest.get(digest);
                    if (disclosure == null) {
                        continue; // RFC 9901 7.1 step 3d: remove undisclosed elements
                    }
                    if (!disclosure.arrayElement()) {
                        throw new VerificationFailure(
                                "invalid_disclosure", "array element digest refers to an object property Disclosure");
                    }
                    used.add(digest);
                    out.add(processValue(disclosure.value(), depth + 1));
                } else {
                    out.add(processValue(element, depth + 1));
                }
            }
            return out;
        }

        @SuppressWarnings("unchecked")
        private Object processValue(Object value, int depth) {
            if (value instanceof Map<?, ?> map) {
                return processObject((Map<String, Object>) map, depth, false);
            }
            if (value instanceof List<?> list) {
                return processArray((List<Object>) list, depth);
            }
            return value;
        }

        private void markSeen(String digest) {
            if (!seen.add(digest)) {
                throw new VerificationFailure("duplicate_digest", "a digest appears more than once");
            }
        }

        private static void checkDepth(int depth) {
            if (depth > Json.MAX_DEPTH) {
                throw new VerificationFailure("malformed_sd_jwt", "payload nested too deeply");
            }
        }
    }
}
