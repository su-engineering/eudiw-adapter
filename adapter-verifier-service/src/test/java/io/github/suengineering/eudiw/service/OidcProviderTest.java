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
package io.github.suengineering.eudiw.service;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

/**
 * The wallet login provider (ADR-018) end to end inside the service: an OIDC client starts a login, a wallet
 * presents a PID, the browser that started the login gets the code, and the client exchanges it for an ID token.
 * Then every way the flow must refuse.
 */
@QuarkusTest
@QuarkusTestResource(TestEnvironment.class)
class OidcProviderTest {

    static final String BASE = "/oidc/tenant-a";
    static final String ISSUER = "https://adapter.test.example/oidc/tenant-a";

    /** A browser's view of one login: the page's cookie, status URL and launch URI, plus the client's PKCE pair. */
    record Login(
            String cookieName,
            String cookieValue,
            String statusUrl,
            String launchUri,
            String verifier,
            String state,
            String nonce) {}

    static String challenge(String verifier) throws Exception {
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(
                        MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
    }

    static Map<String, String> authorizeParams(String verifier, String state, String nonce) throws Exception {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("response_type", "code");
        params.put("client_id", TestEnvironment.OIDC_CLIENT);
        params.put("redirect_uri", TestEnvironment.OIDC_REDIRECT);
        params.put("scope", "openid");
        params.put("state", state);
        params.put("nonce", nonce);
        params.put("code_challenge", challenge(verifier));
        params.put("code_challenge_method", "S256");
        return params;
    }

    static Login start() throws Exception {
        String verifier = "v-" + UUID.randomUUID() + "-" + UUID.randomUUID();
        String state = "st-" + UUID.randomUUID();
        String nonce = "n-" + UUID.randomUUID();
        Response page = given().redirects()
                .follow(false)
                .queryParams(authorizeParams(verifier, state, nonce))
                .get(BASE + "/authorize");
        assertThat(page.statusCode()).isEqualTo(200);
        assertThat(page.header("Content-Security-Policy"))
                .contains("frame-ancestors 'none'")
                .contains("script-src 'self'");
        Map.Entry<String, String> cookie = page.cookies().entrySet().stream()
                .filter(e -> e.getKey().startsWith("__Host-eudiw-login-"))
                .findFirst()
                .orElseThrow();
        assertThat(page.detailedCookie(cookie.getKey()).isHttpOnly()).isTrue();
        assertThat(page.detailedCookie(cookie.getKey()).isSecured()).isTrue();
        String html = page.asString();
        return new Login(
                cookie.getKey(),
                cookie.getValue(),
                attribute(html, "status-url"),
                attribute(html, "launch-uri"),
                verifier,
                state,
                nonce);
    }

    static String attribute(String html, String name) {
        Matcher m = Pattern.compile(name + "=\"([^\"]*)\"").matcher(html);
        assertThat(m.find()).as(name).isTrue();
        return m.group(1).replace("&amp;", "&").replace("&quot;", "\"").replace("&#39;", "'");
    }

    static Map<String, String> query(String uri) {
        Map<String, String> params = new LinkedHashMap<>();
        String q = URI.create(uri).getRawQuery();
        for (String pair : q.split("&")) {
            int eq = pair.indexOf('=');
            params.put(
                    URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
                    URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
        }
        return params;
    }

    /** The wallet presents a PID with these claims to the login's verification session. */
    static void present(Login login, Map<String, Object> claims) {
        assertThat(presentResponse(login, claims).statusCode()).isEqualTo(200);
    }

    static Response presentResponse(Login login, Map<String, Object> claims) {
        String requestUri = query(login.launchUri()).get("request_uri");
        Map<String, Object> request = TestWallet.fetchRequest(requestUri);
        String presentation = new TestWallet()
                .presentation(request, TestEnvironment.ISSUER_A, "issuer-a-key.pem", "issuer-a.pem", claims, null);
        return TestWallet.respond(request, Map.of("vp_token", Map.of("pid", List.of(presentation))));
    }

    static Map<String, Object> pid(String pan) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("issuing_country", "BE");
        claims.put("personal_administrative_number", pan);
        claims.put("given_name", "Erika");
        claims.put("family_name", "Mustermann");
        return claims;
    }

    static io.restassured.path.json.JsonPath status(Login login) {
        Response r = given().cookie(login.cookieName(), login.cookieValue()).get(login.statusUrl());
        assertThat(r.statusCode()).isEqualTo(200);
        assertThat(r.header("Cache-Control")).isEqualTo("no-store");
        return r.jsonPath();
    }

    static Response token(String code, String verifier, String redirectUri, String secret) {
        var spec = given().auth()
                .preemptive()
                .basic(TestEnvironment.OIDC_CLIENT, secret)
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "authorization_code")
                .formParam("code", code)
                .formParam("redirect_uri", redirectUri);
        if (verifier != null) {
            spec = spec.formParam("code_verifier", verifier);
        }
        return spec.post(BASE + "/token");
    }

    /** Runs a whole login and returns the code redirect's parameters. */
    static Map<String, String> loginWith(Login login, Map<String, Object> claims) {
        present(login, claims);
        var s = status(login);
        assertThat(s.getString("status")).isEqualTo("verified");
        return query(s.getString("redirect"));
    }

    @Test
    void discoveryAndJwksDescribeTheProvider() throws Exception {
        var d = given().get(BASE + "/.well-known/openid-configuration")
                .then()
                .statusCode(200)
                .extract()
                .jsonPath();
        assertThat(d.getString("issuer")).isEqualTo(ISSUER);
        assertThat(d.getString("authorization_endpoint")).isEqualTo(ISSUER + "/authorize");
        assertThat(d.getString("token_endpoint")).isEqualTo(ISSUER + "/token");
        assertThat(d.getString("jwks_uri")).isEqualTo(ISSUER + "/jwks");
        assertThat(d.getList("response_types_supported")).containsExactly("code");
        assertThat(d.getList("id_token_signing_alg_values_supported")).containsExactly("RS256");
        assertThat(d.getList("code_challenge_methods_supported")).containsExactly("S256");
        assertThat(d.getList("subject_types_supported")).containsExactly("pairwise");
        assertThat(d.getList("claims_supported"))
                .contains("sub", "given_name", "family_name")
                .doesNotContain("email");
        JWKSet jwks = JWKSet.parse(
                given().get(BASE + "/jwks").then().statusCode(200).extract().asString());
        assertThat(jwks.getKeys()).hasSize(1);
        assertThat(jwks.getKeys().get(0).isPrivate()).isFalse();

        given().get("/oidc/tenant-b/.well-known/openid-configuration").then().statusCode(404);
        given().get("/oidc/no-such-tenant/jwks").then().statusCode(404);
    }

    @Test
    void walletLoginEndsInAnIdTokenForTheBrowserThatStartedIt() throws Exception {
        Login login = start();
        assertThat(status(login).getString("status")).isEqualTo("pending");

        Map<String, String> redirect = loginWith(login, pid("BE-0001"));
        assertThat(redirect).containsEntry("state", login.state()).containsEntry("iss", ISSUER);
        String code = redirect.get("code");

        Response tokens =
                token(code, login.verifier(), TestEnvironment.OIDC_REDIRECT, TestEnvironment.OIDC_CLIENT_SECRET);
        assertThat(tokens.statusCode()).isEqualTo(200);
        assertThat(tokens.header("Cache-Control")).isEqualTo("no-store");
        assertThat(tokens.jsonPath().getString("token_type")).isEqualTo("Bearer");
        assertThat(tokens.jsonPath().getMap("$")).doesNotContainKey("refresh_token");

        SignedJWT idToken = SignedJWT.parse(tokens.jsonPath().getString("id_token"));
        RSAKey key = (RSAKey)
                JWKSet.parse(given().get(BASE + "/jwks").asString()).getKeys().get(0);
        assertThat(idToken.verify(new RSASSAVerifier(key))).isTrue();
        assertThat(idToken.getHeader().getKeyID()).isEqualTo(key.getKeyID());
        var claims = idToken.getJWTClaimsSet();
        assertThat(claims.getIssuer()).isEqualTo(ISSUER);
        assertThat(claims.getAudience()).containsExactly(TestEnvironment.OIDC_CLIENT);
        assertThat(claims.getStringClaim("nonce")).isEqualTo(login.nonce());
        assertThat(claims.getSubject()).matches("[A-Za-z0-9_-]{43}");
        assertThat(claims.getStringClaim("given_name")).isEqualTo("Erika");
        assertThat(claims.getStringClaim("family_name")).isEqualTo("Mustermann");
        assertThat(claims.getClaims())
                .containsKey("auth_time")
                .doesNotContainKeys(
                        "email", "preferred_username", "pan", "personal_administrative_number", "issuing_country");

        var userinfo = given().auth()
                .oauth2(tokens.jsonPath().getString("access_token"))
                .get(BASE + "/userinfo")
                .then()
                .statusCode(200)
                .extract()
                .jsonPath();
        assertThat(userinfo.getString("sub")).isEqualTo(claims.getSubject());
        assertThat(userinfo.getString("given_name")).isEqualTo("Erika");

        // The status keeps answering the same browser after the code was used, without the code.
        assertThat(status(login).getString("status")).isEqualTo("expired");
        assertThat(status(login).getString("redirect")).isNull();
    }

    @Test
    void theSameIdentityGetsTheSameSubjectAndAnotherIdentityAnotherOne() throws Exception {
        String first = subjectOf(pid("BE-0002"));
        String again = subjectOf(pid("BE-0002"));
        Map<String, Object> renamed = pid("BE-0002");
        renamed.put("family_name", "Gabler");
        String afterNameChange = subjectOf(renamed);
        String other = subjectOf(pid("BE-0003"));
        assertThat(again).isEqualTo(first);
        assertThat(afterNameChange).isEqualTo(first);
        assertThat(other).isNotEqualTo(first);
    }

    private String subjectOf(Map<String, Object> claims) throws Exception {
        Login login = start();
        String code = loginWith(login, claims).get("code");
        Response tokens =
                token(code, login.verifier(), TestEnvironment.OIDC_REDIRECT, TestEnvironment.OIDC_CLIENT_SECRET);
        assertThat(tokens.statusCode()).isEqualTo(200);
        return SignedJWT.parse(tokens.jsonPath().getString("id_token"))
                .getJWTClaimsSet()
                .getSubject();
    }

    @Test
    void aPresentationWithoutTheSubjectClaimsSendsAccessDenied() throws Exception {
        Login login = start();
        Map<String, Object> noPan = pid("BE-0004");
        noPan.remove("personal_administrative_number");
        // The login policy's query requires the claim, so the verifier already rejects the presentation.
        assertThat(presentResponse(login, noPan).statusCode()).isEqualTo(400);
        var s = status(login);
        assertThat(s.getString("status")).isEqualTo("rejected");
        assertThat(query(s.getString("redirect")))
                .containsEntry("error", "access_denied")
                .containsEntry("state", login.state())
                .doesNotContainKey("code");
    }

    @Test
    void onlyTheBrowserWithTheLoginCookieSeesTheStatus() throws Exception {
        Login login = start();
        given().get(login.statusUrl()).then().statusCode(404);
        given().cookie(login.cookieName(), "someone-else")
                .get(login.statusUrl())
                .then()
                .statusCode(404);
        Login other = start();
        given().cookie(other.cookieName(), other.cookieValue())
                .get(login.statusUrl())
                .then()
                .statusCode(404);
        present(login, pid("BE-0005"));
        given().cookie(other.cookieName(), other.cookieValue())
                .get(login.statusUrl())
                .then()
                .statusCode(404);
        assertThat(status(login).getString("status")).isEqualTo("verified");
    }

    @Test
    void concurrentStatusPollsIssueOneCode() throws Exception {
        Login login = start();
        present(login, pid("BE-0006"));
        ExecutorService pool = Executors.newFixedThreadPool(6);
        try {
            List<Callable<String>> polls = java.util.Collections.nCopies(6, () -> {
                Response r =
                        given().cookie(login.cookieName(), login.cookieValue()).get(login.statusUrl());
                return r.jsonPath().getString("redirect");
            });
            List<String> codes = new java.util.ArrayList<>();
            for (Future<String> f : pool.invokeAll(polls)) {
                String redirect = f.get();
                if (redirect != null) {
                    codes.add(query(redirect).get("code"));
                }
            }
            assertThat(codes).isNotEmpty();
            assertThat(codes.stream().distinct()).hasSize(1);
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void aCodeWorksOnceAndItsReplayRevokesTheAccessToken() throws Exception {
        Login login = start();
        String code = loginWith(login, pid("BE-0007")).get("code");
        Response first =
                token(code, login.verifier(), TestEnvironment.OIDC_REDIRECT, TestEnvironment.OIDC_CLIENT_SECRET);
        assertThat(first.statusCode()).isEqualTo(200);
        String accessToken = first.jsonPath().getString("access_token");
        given().auth().oauth2(accessToken).get(BASE + "/userinfo").then().statusCode(200);

        Response replay =
                token(code, login.verifier(), TestEnvironment.OIDC_REDIRECT, TestEnvironment.OIDC_CLIENT_SECRET);
        assertThat(replay.statusCode()).isEqualTo(400);
        assertThat(replay.jsonPath().getString("error")).isEqualTo("invalid_grant");
        Response revoked = given().auth().oauth2(accessToken).get(BASE + "/userinfo");
        assertThat(revoked.statusCode()).isEqualTo(401);
        assertThat(revoked.header("WWW-Authenticate")).contains("invalid_token");
    }

    @Test
    void theTokenEndpointChecksClientRedirectUriAndPkce() throws Exception {
        Login login = start();
        String code = loginWith(login, pid("BE-0008")).get("code");

        Response wrongSecret =
                token(code, login.verifier(), TestEnvironment.OIDC_REDIRECT, "wrong-secret-0123456789abcdef0123");
        assertThat(wrongSecret.statusCode()).isEqualTo(401);
        assertThat(wrongSecret.jsonPath().getString("error")).isEqualTo("invalid_client");

        Response wrongVerifier =
                token(code, "x".repeat(43), TestEnvironment.OIDC_REDIRECT, TestEnvironment.OIDC_CLIENT_SECRET);
        assertThat(wrongVerifier.jsonPath().getString("error")).isEqualTo("invalid_grant");
        Response noVerifier = token(code, null, TestEnvironment.OIDC_REDIRECT, TestEnvironment.OIDC_CLIENT_SECRET);
        assertThat(noVerifier.jsonPath().getString("error")).isEqualTo("invalid_grant");
        Response wrongRedirect =
                token(code, login.verifier(), "https://idp.test.example/other", TestEnvironment.OIDC_CLIENT_SECRET);
        assertThat(wrongRedirect.jsonPath().getString("error")).isEqualTo("invalid_grant");

        // None of the failed attempts used the code up.
        Response good =
                token(code, login.verifier(), TestEnvironment.OIDC_REDIRECT, TestEnvironment.OIDC_CLIENT_SECRET);
        assertThat(good.statusCode()).isEqualTo(200);

        Response unsupported = given().auth()
                .preemptive()
                .basic(TestEnvironment.OIDC_CLIENT, TestEnvironment.OIDC_CLIENT_SECRET)
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "client_credentials")
                .post(BASE + "/token");
        assertThat(unsupported.jsonPath().getString("error")).isEqualTo("unsupported_grant_type");

        // A management API client is not an OIDC client.
        Response notOidc = given().auth()
                .preemptive()
                .basic("portal-a", TestEnvironment.OIDC_CLIENT_SECRET)
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "authorization_code")
                .formParam("code", code)
                .post(BASE + "/token");
        assertThat(notOidc.statusCode()).isEqualTo(401);
    }

    @Test
    void clientSecretPostAuthenticatesToo() throws Exception {
        Login login = start();
        String code = loginWith(login, pid("BE-0009")).get("code");
        given().contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "authorization_code")
                .formParam("code", code)
                .formParam("redirect_uri", TestEnvironment.OIDC_REDIRECT)
                .formParam("code_verifier", login.verifier())
                .formParam("client_id", TestEnvironment.OIDC_CLIENT)
                .formParam("client_secret", TestEnvironment.OIDC_CLIENT_SECRET)
                .post(BASE + "/token")
                .then()
                .statusCode(200);
    }

    @Test
    void anUnregisteredClientOrRedirectUriIsAPageNotARedirect() throws Exception {
        Map<String, String> params = authorizeParams("v".repeat(43), "s", "n");
        params.put("redirect_uri", "https://attacker.example/cb");
        Response r = given().redirects().follow(false).queryParams(params).get(BASE + "/authorize");
        assertThat(r.statusCode()).isEqualTo(400);
        assertThat(r.header("Location")).isNull();
        assertThat(r.contentType()).startsWith("text/html");

        params = authorizeParams("v".repeat(43), "s", "n");
        params.put("client_id", "portal-a");
        r = given().redirects().follow(false).queryParams(params).get(BASE + "/authorize");
        assertThat(r.statusCode()).isEqualTo(400);
        assertThat(r.header("Location")).isNull();

        // A client of tenant-a at another tenant's issuer.
        params = authorizeParams("v".repeat(43), "s", "n");
        r = given().redirects().follow(false).queryParams(params).get("/oidc/tenant-b/authorize");
        assertThat(r.statusCode()).isEqualTo(404);
    }

    @Test
    void invalidRequestsGoBackToTheClientWithTheirError() throws Exception {
        assertError(Map.of("code_challenge", ""), "invalid_request");
        assertError(Map.of("code_challenge_method", "plain"), "invalid_request");
        assertError(Map.of("response_type", "id_token"), "unsupported_response_type");
        assertError(Map.of("scope", "profile"), "invalid_scope");
        assertError(Map.of("prompt", "none"), "login_required");
        assertError(Map.of("request", "eyJ..."), "request_not_supported");
        assertError(Map.of("request_uri", "https://x.example/r"), "request_uri_not_supported");
        assertError(Map.of("response_mode", "fragment"), "invalid_request");
    }

    private void assertError(Map<String, String> override, String error) throws Exception {
        Map<String, String> params = authorizeParams("v".repeat(43), "st-err", "n");
        params.putAll(override);
        Response r = given().redirects().follow(false).queryParams(params).get(BASE + "/authorize");
        assertThat(r.statusCode()).as(override.toString()).isEqualTo(302);
        String location = r.header("Location");
        assertThat(location).startsWith(TestEnvironment.OIDC_REDIRECT + "?");
        assertThat(query(location)).containsEntry("error", error).containsEntry("state", "st-err");
    }

    @Test
    void aRepeatedParameterIsRefused() throws Exception {
        Map<String, String> params = authorizeParams("v".repeat(43), "s", "n");
        Response r = given().redirects()
                .follow(false)
                .queryParams(params)
                .queryParam("scope", "openid")
                .get(BASE + "/authorize");
        assertThat(r.statusCode()).isEqualTo(302);
        assertThat(query(r.header("Location"))).containsEntry("error", "invalid_request");
        r = given().redirects()
                .follow(false)
                .queryParams(params)
                .queryParam("client_id", "x")
                .get(BASE + "/authorize");
        assertThat(r.statusCode()).isEqualTo(400);
        assertThat(r.header("Location")).isNull();
    }

    @Test
    void theLoginPageCanSendTheUserBackToTheClient() throws Exception {
        Response page = given().redirects()
                .follow(false)
                .queryParams(authorizeParams("v".repeat(43), "st-back", "n"))
                .get(BASE + "/authorize");
        String cancel = Pattern.compile("<p class=\"other\"><a href=\"([^\"]*)\"")
                .matcher(page.asString())
                .results()
                .findFirst()
                .orElseThrow()
                .group(1)
                .replace("&amp;", "&");
        assertThat(query(cancel)).containsEntry("error", "access_denied").containsEntry("state", "st-back");
    }
}
