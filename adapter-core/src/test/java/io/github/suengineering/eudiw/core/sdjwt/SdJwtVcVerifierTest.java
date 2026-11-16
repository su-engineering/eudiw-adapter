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

import static io.github.suengineering.eudiw.core.sdjwt.Rfc9901ExamplesTest.assertFailure;
import static io.github.suengineering.eudiw.core.sdjwt.TestSdJwtIssuer.digest;
import static io.github.suengineering.eudiw.core.sdjwt.TestSdJwtIssuer.disclosure;
import static io.github.suengineering.eudiw.core.x509.TestPki.dns;
import static io.github.suengineering.eudiw.core.x509.TestPki.uri;
import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.JSONObjectUtils;
import io.github.suengineering.eudiw.core.x509.TestPki;
import io.github.suengineering.eudiw.core.x509.TestPki.Issued;
import java.security.PrivateKey;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.jupiter.api.Test;

class SdJwtVcVerifierTest {

    private static final String AUD = "https://verifier.test.example";
    private static final String NONCE = "vc-nonce";
    private static final Instant NOW = Instant.parse("2027-01-15T10:00:00Z");
    private static final String ISSUER = "https://issuer.test.example";
    private static final String VCT = "https://credentials.test.example/age";

    private final Instant from = NOW.minus(Duration.ofDays(30));
    private final Instant until = NOW.plus(Duration.ofDays(365));
    private final Issued root = TestPki.rootCa("CN=Test Root", from, until);
    private final Issued intermediate = TestPki.intermediateCa("CN=Test Issuing CA", root, from, until);
    private final Issued leaf = TestPki.endEntity(
            "CN=Test Issuer",
            intermediate,
            from,
            until,
            KeyUsage.digitalSignature,
            List.of(dns("issuer.test.example")));

    private final TestSdJwtIssuer holder = new TestSdJwtIssuer();
    private final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
    private final SdJwtVerificationOptions options =
            SdJwtVerificationOptions.keyBound(AUD, NONCE).withClock(clock);
    private final String ageOver18 = disclosure("salt-age", "age_over_18", true);

    private SdJwtVcVerifier verifier(Issued... anchors) {
        Set<TrustAnchor> trust = new java.util.HashSet<>();
        for (Issued anchor : anchors) {
            trust.add(new TrustAnchor(anchor.certificate(), null));
        }
        return new SdJwtVcVerifier(new X5cIssuerKeyResolver(() -> trust, clock), false);
    }

    private Map<String, Object> payload() {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", ISSUER);
        payload.put("vct", VCT);
        payload.put("exp", NOW.plusSeconds(3600).getEpochSecond());
        payload.put("_sd", List.of(digest(ageOver18)));
        payload.put("cnf", holder.cnf());
        return payload;
    }

    private static String sign(Map<String, Object> payload, PrivateKey key, String typ, List<X509Certificate> x5c) {
        try {
            JWSHeader.Builder header = new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType(typ));
            if (x5c != null) {
                List<Base64> encoded = new java.util.ArrayList<>();
                for (X509Certificate c : x5c) {
                    encoded.add(Base64.encode(c.getEncoded()));
                }
                header.x509CertChain(encoded);
            }
            JWSObject jws = new JWSObject(header.build(), new Payload(JSONObjectUtils.toJSONString(payload)));
            jws.sign(new ECDSASigner((ECPrivateKey) key));
            return jws.serialize();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private String present(String issuerJwt, List<String> disclosures) {
        return holder.present(issuerJwt, disclosures, AUD, NONCE, NOW.getEpochSecond());
    }

    private String validJwt(Map<String, Object> payload) {
        return sign(payload, leaf.keyPair().getPrivate(), "dc+sd-jwt", TestPki.chain(leaf, intermediate));
    }

    @Test
    void validCredentialWithIntermediateChain() {
        SdJwtVcVerifier.VerifiedSdJwtVc result =
                verifier(root).verify(present(validJwt(payload()), List.of(ageOver18)), options, Set.of(VCT));

        assertThat(result.vct()).isEqualTo(VCT);
        assertThat(result.sdJwt().issuer()).isEqualTo(ISSUER);
        assertThat(result.sdJwt().payload()).containsEntry("age_over_18", true);
    }

    @Test
    void issuerFromCertificateSubjectWhenNoIss() {
        Map<String, Object> payload = payload();
        payload.remove("iss");

        SdJwtVcVerifier.VerifiedSdJwtVc result =
                verifier(root).verify(present(validJwt(payload), List.of(ageOver18)), options, Set.of(VCT));

        assertThat(result.sdJwt().issuer()).isEqualTo("CN=Test Issuer");
    }

    @Test
    void issBoundBySanUri() {
        Issued uriLeaf = TestPki.endEntity(
                "CN=Uri Issuer",
                intermediate,
                from,
                until,
                KeyUsage.digitalSignature,
                List.of(uri("urn:example:issuer")));
        Map<String, Object> payload = payload();
        payload.put("iss", "urn:example:issuer");
        String jwt = sign(payload, uriLeaf.keyPair().getPrivate(), "dc+sd-jwt", TestPki.chain(uriLeaf, intermediate));

        assertThat(verifier(root)
                        .verify(present(jwt, List.of(ageOver18)), options, Set.of(VCT))
                        .sdJwt()
                        .issuer())
                .isEqualTo("urn:example:issuer");
    }

    @Test
    void issNotBoundToCertificateIsRejected() {
        Map<String, Object> payload = payload();
        payload.put("iss", "https://other-issuer.example");

        assertFailure(
                () -> verifier(root).verify(present(validJwt(payload), List.of(ageOver18)), options, Set.of(VCT)),
                "issuer_untrusted");
    }

    @Test
    void chainToUnknownRootIsRejected() {
        Issued otherRoot = TestPki.rootCa("CN=Other Root", from, until);

        assertFailure(
                () -> verifier(otherRoot)
                        .verify(present(validJwt(payload()), List.of(ageOver18)), options, Set.of(VCT)),
                "certificate_untrusted");
    }

    @Test
    void expiredLeafIsRejected() {
        Issued expired = TestPki.endEntity(
                "CN=Expired",
                intermediate,
                from,
                NOW.minusSeconds(60),
                KeyUsage.digitalSignature,
                List.of(dns("issuer.test.example")));
        String jwt = sign(payload(), expired.keyPair().getPrivate(), "dc+sd-jwt", TestPki.chain(expired, intermediate));

        assertFailure(
                () -> verifier(root).verify(present(jwt, List.of(ageOver18)), options, Set.of(VCT)),
                "certificate_untrusted");
    }

    @Test
    void selfSignedLeafIsRejectedEvenIfConfiguredAsAnchor() {
        Issued selfSigned = TestPki.selfSignedEndEntity("CN=issuer.test.example", from, until);
        String jwt = sign(payload(), selfSigned.keyPair().getPrivate(), "dc+sd-jwt", TestPki.chain(selfSigned));

        assertFailure(
                () -> verifier(selfSigned).verify(present(jwt, List.of(ageOver18)), options, Set.of(VCT)),
                "certificate_chain_invalid");
    }

    @Test
    void chainContainingTheTrustAnchorIsRejected() {
        String jwt = sign(payload(), leaf.keyPair().getPrivate(), "dc+sd-jwt", TestPki.chain(leaf, intermediate, root));

        assertFailure(
                () -> verifier(root).verify(present(jwt, List.of(ageOver18)), options, Set.of(VCT)),
                "certificate_chain_invalid");
    }

    @Test
    void leafWithoutDigitalSignatureUsageIsRejected() {
        Issued wrongUsage = TestPki.endEntity(
                "CN=Wrong usage",
                intermediate,
                from,
                until,
                KeyUsage.keyEncipherment,
                List.of(dns("issuer.test.example")));
        String jwt = sign(
                payload(), wrongUsage.keyPair().getPrivate(), "dc+sd-jwt", TestPki.chain(wrongUsage, intermediate));

        assertFailure(
                () -> verifier(root).verify(present(jwt, List.of(ageOver18)), options, Set.of(VCT)),
                "certificate_chain_invalid");
    }

    @Test
    void credentialSignedByKeyOtherThanCertificateIsRejected() {
        String jwt = sign(payload(), TestPki.ecKeyPair().getPrivate(), "dc+sd-jwt", TestPki.chain(leaf, intermediate));

        assertFailure(
                () -> verifier(root).verify(present(jwt, List.of(ageOver18)), options, Set.of(VCT)),
                "invalid_signature");
    }

    @Test
    void missingX5cIsRejected() {
        String jwt = sign(payload(), leaf.keyPair().getPrivate(), "dc+sd-jwt", null);

        assertFailure(
                () -> verifier(root).verify(present(jwt, List.of(ageOver18)), options, Set.of(VCT)),
                "issuer_untrusted");
    }

    @Test
    void wrongTypIsRejectedAndLegacyTypOnlyWhenEnabled() {
        String plainJwt = sign(payload(), leaf.keyPair().getPrivate(), "JWT", TestPki.chain(leaf, intermediate));
        assertFailure(
                () -> verifier(root).verify(present(plainJwt, List.of(ageOver18)), options, Set.of(VCT)),
                "wrong_credential_format");

        String legacy = sign(payload(), leaf.keyPair().getPrivate(), "vc+sd-jwt", TestPki.chain(leaf, intermediate));
        assertFailure(
                () -> verifier(root).verify(present(legacy, List.of(ageOver18)), options, Set.of(VCT)),
                "wrong_credential_format");
        SdJwtVcVerifier lenient = new SdJwtVcVerifier(
                new X5cIssuerKeyResolver(() -> Set.of(new TrustAnchor(root.certificate(), null)), clock), true);
        assertThat(lenient.verify(present(legacy, List.of(ageOver18)), options, Set.of(VCT))
                        .vct())
                .isEqualTo(VCT);
    }

    @Test
    void credentialTypeMustBePresentAndAllowed() {
        assertFailure(
                () -> verifier(root).verify(present(validJwt(payload()), List.of(ageOver18)), options, Set.of("other")),
                "credential_type_not_allowed");

        Map<String, Object> noVct = payload();
        noVct.remove("vct");
        assertFailure(
                () -> verifier(root).verify(present(validJwt(noVct), List.of(ageOver18)), options, Set.of(VCT)),
                "malformed_credential");
    }

    @Test
    void validityClaimsMustNotBeSelectivelyDisclosed() {
        String exp = disclosure("salt-exp", "exp", NOW.plusSeconds(3600).getEpochSecond());
        Map<String, Object> payload = payload();
        payload.remove("exp");
        payload.put("_sd", List.of(digest(ageOver18), digest(exp)));

        assertFailure(
                () -> verifier(root).verify(present(validJwt(payload), List.of(ageOver18, exp)), options, Set.of(VCT)),
                "invalid_disclosure");
    }

    @Test
    void holderBoundCredentialWithoutKeyBindingIsRejected() {
        SdJwtVerificationOptions noKb = new SdJwtVerificationOptions(
                options.algorithms(),
                options.hashAlgorithms(),
                false,
                null,
                null,
                options.keyBindingMaxAge(),
                options.clockSkew(),
                clock,
                options.maxLength(),
                options.maxDisclosures());
        String sdJwt = TestSdJwtIssuer.sdJwt(validJwt(payload()), List.of(ageOver18));

        assertFailure(() -> verifier(root).verify(sdJwt, noKb, Set.of(VCT)), "key_binding_required");
    }

    @Test
    void rfc9901AppendixA3IsAValidSdJwtVc() {
        SdJwtVcVerifier rfc = new SdJwtVcVerifier(
                new StaticIssuerKeyResolver(
                        Map.of("https://pid-issuer.bund.de.example", Rfc9901ExamplesTest.rfcIssuerKey())),
                false);
        SdJwtVerificationOptions rfcOptions = SdJwtVerificationOptions.keyBound(
                        "https://verifier.example.org", "1234567890")
                .withClock(Clock.fixed(Instant.ofEpochSecond(1748537244), ZoneOffset.UTC));

        assertThat(rfc.verify(Rfc9901ExamplesTest.load("appendix-a.3"), rfcOptions, Set.of("urn:eudi:pid:de:1"))
                        .vct())
                .isEqualTo("urn:eudi:pid:de:1");
    }
}
