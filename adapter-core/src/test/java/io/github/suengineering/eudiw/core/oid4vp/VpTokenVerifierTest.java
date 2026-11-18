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
package io.github.suengineering.eudiw.core.oid4vp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.JSONObjectUtils;
import io.github.suengineering.eudiw.core.VerificationFailure;
import io.github.suengineering.eudiw.core.dcql.DcqlEvaluator.DisclosedClaim;
import io.github.suengineering.eudiw.core.dcql.DcqlQuery;
import io.github.suengineering.eudiw.core.jose.AlgorithmPolicy;
import io.github.suengineering.eudiw.core.json.Json;
import io.github.suengineering.eudiw.core.net.HttpFetcher;
import io.github.suengineering.eudiw.core.oid4vp.VpTokenVerifier.StatusPolicy;
import io.github.suengineering.eudiw.core.oid4vp.VpTokenVerifier.StatusSigner;
import io.github.suengineering.eudiw.core.sdjwt.SdJwtVcVerifier;
import io.github.suengineering.eudiw.core.sdjwt.X5cIssuerKeyResolver;
import io.github.suengineering.eudiw.core.status.StatusListChecker;
import io.github.suengineering.eudiw.core.x509.CertificateIdentifiers;
import io.github.suengineering.eudiw.core.x509.TestPki;
import io.github.suengineering.eudiw.core.x509.TestPki.Issued;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.jupiter.api.Test;

class VpTokenVerifierTest {

    private static final String CLIENT_ID = "x509_hash:test-verifier";
    private static final String NONCE = "request-nonce-1";
    private static final String VCT = "https://credentials.test.example/age";
    private static final String STATUS_URI = "https://status.test.example/1";
    // statuses 1,0,0,1,... (index 1 valid, index 0 revoked)
    private static final String ONE_BIT = "eNrbuRgAAhcBXQ";

    private final Instant now = Instant.parse("2027-01-15T10:00:00Z");
    private final Clock clock = Clock.fixed(now, ZoneOffset.UTC);
    private final Issued root = TestPki.rootCa("CN=Root", now.minusSeconds(86400), now.plusSeconds(86400 * 365));
    private final Issued issuer = TestPki.endEntity(
            "CN=Issuer",
            root,
            now.minusSeconds(86400),
            now.plusSeconds(86400 * 30),
            KeyUsage.digitalSignature,
            List.of(TestPki.dns("issuer.test.example")));
    private final ECKey holder = generate();
    private final AtomicReference<String> statusToken = new AtomicReference<>();

    private final DcqlQuery query = DcqlQuery.parse(Json.parseObject("""
            {"credentials":[{"id":"age","format":"dc+sd-jwt","meta":{"vct_values":["%s"]},
              "claims":[{"path":["age_over_18"]}]}]}""".formatted(VCT), "test"));

    private VpTokenVerifier verifier(StatusPolicy policy, boolean enforceAuthorities) {
        return verifier(
                policy,
                enforceAuthorities,
                false,
                StatusSigner.ANY_ANCHOR,
                Set.of(new TrustAnchor(root.certificate(), null)));
    }

    private VpTokenVerifier verifier(
            StatusPolicy policy,
            boolean enforceAuthorities,
            boolean requireStatus,
            StatusSigner statusSigner,
            Set<TrustAnchor> anchors) {
        HttpFetcher fetcher = (uri, accept, max) -> {
            if (statusToken.get() == null) {
                throw new HttpFetcher.FetchException("unavailable");
            }
            return statusToken.get().getBytes(StandardCharsets.US_ASCII);
        };
        StatusListChecker checker = new StatusListChecker(
                fetcher,
                () -> anchors,
                AlgorithmPolicy.DEFAULT,
                clock,
                Duration.ofSeconds(60),
                Duration.ofMinutes(10),
                10);
        return new VpTokenVerifier(
                new SdJwtVcVerifier(new X5cIssuerKeyResolver(() -> anchors, clock), false),
                Optional.of(checker),
                new VpTokenVerifier.Settings(
                        clock,
                        Duration.ofMinutes(5),
                        Duration.ofSeconds(60),
                        AlgorithmPolicy.DEFAULT,
                        enforceAuthorities,
                        policy,
                        requireStatus,
                        statusSigner));
    }

    private final VpTokenVerifier.Context context = new VpTokenVerifier.Context(CLIENT_ID, NONCE, "tenant-1");

    @Test
    void returnsOnlyTheRequestedClaim() {
        statusToken.set(statusListToken());

        VpTokenVerifier.Result result = verifier(StatusPolicy.REQUIRE_VALID, true)
                .verify(Map.of("age", List.of(presentation(1, NONCE))), query, context);

        List<DisclosedClaim> claims = result.credentials().get("age").get(0).claims();
        assertThat(claims).singleElement().satisfies(c -> assertThat(c.values()).containsExactly(true));
        assertThat(result.discarded()).isEmpty();
    }

    @Test
    void revokedCredentialIsRejected() {
        statusToken.set(statusListToken());

        assertFailure(
                () -> verifier(StatusPolicy.REQUIRE_VALID, true)
                        .verify(Map.of("age", List.of(presentation(0, NONCE))), query, context),
                "credential_revoked");
    }

    @Test
    void unavailableStatusFailsClosedUnlessPolicyAllows() {
        statusToken.set(null);
        Map<String, Object> token = Map.of("age", List.of(presentation(1, NONCE)));

        assertFailure(
                () -> verifier(StatusPolicy.REQUIRE_VALID, true).verify(token, query, context),
                "credential_status_unknown");
        assertThat(verifier(StatusPolicy.REJECT_KNOWN_INVALID, true)
                        .verify(token, query, context)
                        .credentials())
                .containsKey("age");
    }

    @Test
    void replayedPresentationForAnotherRequestIsRejected() {
        statusToken.set(statusListToken());

        assertFailure(
                () -> verifier(StatusPolicy.REQUIRE_VALID, true)
                        .verify(Map.of("age", List.of(presentation(1, "other-nonce"))), query, context),
                "key_binding_nonce_mismatch");
        assertFailure(
                () -> verifier(StatusPolicy.REQUIRE_VALID, true)
                        .verify(
                                Map.of("age", List.of(presentation(1, NONCE))),
                                query,
                                new VpTokenVerifier.Context("x509_hash:other-verifier", NONCE, "tenant-1")),
                "key_binding_audience_mismatch");
    }

    @Test
    void malformedTokensAreRejected() {
        statusToken.set(statusListToken());
        VpTokenVerifier verifier = verifier(StatusPolicy.REQUIRE_VALID, true);

        assertFailure(() -> verifier.verify("not an object", query, context), "invalid_vp_token");
        assertFailure(() -> verifier.verify(Map.of(), query, context), "invalid_vp_token");
        assertFailure(() -> verifier.verify(Map.of("age", "x"), query, context), "invalid_vp_token");
        assertFailure(() -> verifier.verify(Map.of("age", List.of(1)), query, context), "invalid_vp_token");
        assertFailure(
                () -> verifier.verify(
                        Map.of("age", List.of(presentation(1, NONCE), presentation(1, NONCE))), query, context),
                "invalid_vp_token");
        assertFailure(
                () -> verifier.verify(Map.of("other", List.of(presentation(1, NONCE))), query, context),
                "unexpected_credential");
    }

    @Test
    void trustedAuthoritiesUseTheIssuerChain() {
        statusToken.set(statusListToken());
        String aki = CertificateIdentifiers.authorityKeyId(issuer.certificate()).orElseThrow();
        DcqlQuery withAuthority = DcqlQuery.parse(Json.parseObject("""
                {"credentials":[{"id":"age","format":"dc+sd-jwt","meta":{"vct_values":["%s"]},
                  "trusted_authorities":[{"type":"aki","values":["%s"]}],
                  "claims":[{"path":["age_over_18"]}]}]}""".formatted(VCT, aki), "test"));
        DcqlQuery otherAuthority = DcqlQuery.parse(
                Json.parseObject(Json.toJson(withAuthority.toJson()).replace(aki, "AAAA"), "test"));
        Map<String, Object> token = Map.of("age", List.of(presentation(1, NONCE)));

        assertThat(verifier(StatusPolicy.REQUIRE_VALID, true)
                        .verify(token, withAuthority, context)
                        .credentials())
                .containsKey("age");
        assertFailure(
                () -> verifier(StatusPolicy.REQUIRE_VALID, true).verify(token, otherAuthority, context),
                "untrusted_authority");
    }

    @Test
    void requireStatusRefusesACredentialWithoutStatus() {
        statusToken.set(statusListToken());
        Map<String, Object> withoutStatus = Map.of("age", List.of(presentation(-1, NONCE)));
        Set<TrustAnchor> anchors = Set.of(new TrustAnchor(root.certificate(), null));

        assertThat(verifier(StatusPolicy.REQUIRE_VALID, true)
                        .verify(withoutStatus, query, context)
                        .credentials())
                .containsKey("age");
        for (StatusPolicy policy : List.of(StatusPolicy.REQUIRE_VALID, StatusPolicy.REJECT_KNOWN_INVALID)) {
            VpTokenVerifier strict = verifier(policy, true, true, StatusSigner.ANY_ANCHOR, anchors);
            assertFailure(() -> strict.verify(withoutStatus, query, context), "credential_status_missing");
            assertThat(strict.verify(Map.of("age", List.of(presentation(1, NONCE))), query, context)
                            .credentials())
                    .containsKey("age");
        }
        assertThatThrownBy(() -> verifier(StatusPolicy.IGNORE, true, true, StatusSigner.ANY_ANCHOR, anchors))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void statusSignerCredentialIssuerRefusesAListSignedUnderAnotherAnchor() {
        Issued statusRoot = TestPki.rootCa("CN=Status Root", now.minusSeconds(86400), now.plusSeconds(86400 * 365));
        Issued statusProvider = TestPki.endEntity(
                "CN=Status Provider",
                statusRoot,
                now.minusSeconds(86400),
                now.plusSeconds(86400 * 30),
                KeyUsage.digitalSignature,
                List.of());
        Set<TrustAnchor> anchors =
                Set.of(new TrustAnchor(root.certificate(), null), new TrustAnchor(statusRoot.certificate(), null));
        Map<String, Object> token = Map.of("age", List.of(presentation(1, NONCE)));

        statusToken.set(statusListToken(statusProvider));
        assertThat(verifier(StatusPolicy.REQUIRE_VALID, true, false, StatusSigner.ANY_ANCHOR, anchors)
                        .verify(token, query, context)
                        .credentials())
                .containsKey("age");
        assertFailure(
                () -> verifier(StatusPolicy.REQUIRE_VALID, true, false, StatusSigner.CREDENTIAL_ISSUER, anchors)
                        .verify(token, query, context),
                "credential_status_unknown");
        // Under reject_known_invalid an unbound list is unusable, so like an unavailable one it is tolerated.
        assertThat(verifier(StatusPolicy.REJECT_KNOWN_INVALID, true, false, StatusSigner.CREDENTIAL_ISSUER, anchors)
                        .verify(token, query, context)
                        .credentials())
                .containsKey("age");

        statusToken.set(statusListToken(issuer));
        VpTokenVerifier bound =
                verifier(StatusPolicy.REQUIRE_VALID, true, false, StatusSigner.CREDENTIAL_ISSUER, anchors);
        assertThat(bound.verify(token, query, context).credentials()).containsKey("age");
        assertFailure(
                () -> bound.verify(Map.of("age", List.of(presentation(0, NONCE))), query, context),
                "credential_revoked");
    }

    /**
     * OpenID4VP 1.0 section 6.1.1.1: an {@code aki} value matches the AuthorityKeyIdentifier of any certificate in
     * the chain the credential presents. The chain may omit the root, so the root's key identifier matches through
     * the AuthorityKeyIdentifier of the certificate it issued.
     */
    @Test
    void akiMatchesTheAnchorKeyThroughTheCertificateItIssued() {
        statusToken.set(statusListToken());
        Issued unrelatedRoot = TestPki.rootCa("CN=Unrelated", now.minusSeconds(86400), now.plusSeconds(86400));
        Map<String, Object> token = Map.of("age", List.of(presentation(1, NONCE)));

        assertThat(verifier(StatusPolicy.REQUIRE_VALID, true)
                        .verify(token, akiQuery(subjectKeyId(root.certificate())), context)
                        .credentials())
                .containsKey("age");
        assertFailure(
                () -> verifier(StatusPolicy.REQUIRE_VALID, true)
                        .verify(token, akiQuery(subjectKeyId(unrelatedRoot.certificate())), context),
                "untrusted_authority");
    }

    private static String subjectKeyId(X509Certificate certificate) {
        byte[] id = org.bouncycastle.asn1.x509.SubjectKeyIdentifier.getInstance(
                        org.bouncycastle.asn1.ASN1OctetString.getInstance(certificate.getExtensionValue("2.5.29.14"))
                                .getOctets())
                .getKeyIdentifier();
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(id);
    }

    private static DcqlQuery akiQuery(String aki) {
        return DcqlQuery.parse(Json.parseObject("""
                {"credentials":[{"id":"age","format":"dc+sd-jwt","meta":{"vct_values":["%s"]},
                  "trusted_authorities":[{"type":"aki","values":["%s"]}],
                  "claims":[{"path":["age_over_18"]}]}]}""".formatted(VCT, aki), "test"));
    }

    private String presentation(int statusIndex, String nonce) {
        String disclosure = b64(Json.toJson(Map.of("a", List.of("salt-1", "age_over_18", true)))
                .replaceFirst("^\\{\"a\":", "")
                .replaceFirst("}$", ""));
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", "https://issuer.test.example");
        payload.put("vct", VCT);
        payload.put("exp", now.plusSeconds(3600).getEpochSecond());
        payload.put("_sd", List.of(sha256(disclosure)));
        payload.put("cnf", Map.of("jwk", holder.toPublicJWK().toJSONObject()));
        if (statusIndex >= 0) {
            payload.put("status", Map.of("status_list", Map.of("idx", statusIndex, "uri", STATUS_URI)));
        }
        String jwt = sign(payload, issuer.keyPair().getPrivate(), "dc+sd-jwt", List.of(issuer.certificate()));
        String sdJwt = jwt + "~" + disclosure + "~";
        Map<String, Object> kb = new LinkedHashMap<>();
        kb.put("aud", CLIENT_ID);
        kb.put("nonce", nonce);
        kb.put("iat", now.getEpochSecond());
        kb.put("sd_hash", sha256(sdJwt));
        try {
            JWSObject kbJws = new JWSObject(
                    new JWSHeader.Builder(JWSAlgorithm.ES256)
                            .type(new JOSEObjectType("kb+jwt"))
                            .build(),
                    new Payload(JSONObjectUtils.toJSONString(kb)));
            kbJws.sign(new ECDSASigner(holder));
            return sdJwt + kbJws.serialize();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private String statusListToken() {
        return statusListToken(issuer);
    }

    private String statusListToken(Issued signer) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("sub", STATUS_URI);
        claims.put("iat", now.getEpochSecond());
        claims.put("status_list", Map.of("bits", 1, "lst", ONE_BIT));
        return sign(claims, signer.keyPair().getPrivate(), "statuslist+jwt", List.of(signer.certificate()));
    }

    private static String sign(Map<String, Object> payload, PrivateKey key, String typ, List<X509Certificate> x5c) {
        try {
            List<Base64> chain = new ArrayList<>();
            for (X509Certificate c : x5c) {
                chain.add(Base64.encode(c.getEncoded()));
            }
            JWSObject jws = new JWSObject(
                    new JWSHeader.Builder(JWSAlgorithm.ES256)
                            .type(new JOSEObjectType(typ))
                            .x509CertChain(chain)
                            .build(),
                    new Payload(JSONObjectUtils.toJSONString(payload)));
            jws.sign(new ECDSASigner((ECPrivateKey) key));
            return jws.serialize();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static ECKey generate() {
        try {
            return new ECKeyGenerator(Curve.P_256).generate();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String b64(String s) {
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    private static String sha256(String ascii) {
        try {
            return java.util.Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(
                            MessageDigest.getInstance("SHA-256").digest(ascii.getBytes(StandardCharsets.US_ASCII)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static void assertFailure(org.assertj.core.api.ThrowableAssert.ThrowingCallable call, String code) {
        assertThatThrownBy(call)
                .isInstanceOfSatisfying(
                        VerificationFailure.class, f -> assertThat(f.code()).isEqualTo(code));
    }
}
