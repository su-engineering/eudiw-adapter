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
package io.github.suengineering.eudiw.service.oidc;

import io.github.suengineering.eudiw.service.engine.AdapterRuntime;
import io.github.suengineering.eudiw.service.oidc.OidcProvider.LoginPage;
import io.github.suengineering.eudiw.service.oidc.OidcProvider.OAuthError;
import io.github.suengineering.eudiw.service.oidc.OidcProvider.PageError;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** The HTTP surface of the wallet login provider (ADR-018). Public: every caller is a browser or an OIDC client. */
@Path("/oidc/{tenant}")
public class OidcResource {

    /**
     * The login page runs only the adapter's own scripts and styles, talks only to the adapter, and cannot be framed.
     */
    static final String PAGE_CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:;"
            + " font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

    @Inject
    OidcProvider provider;

    @Inject
    AdapterRuntime runtime;

    @GET
    @Path(".well-known/openid-configuration")
    @jakarta.ws.rs.Produces(MediaType.APPLICATION_JSON)
    public Response discovery(@PathParam("tenant") String tenant) {
        try {
            return Response.ok(provider.discovery(tenant))
                    .header("Cache-Control", "public, max-age=300")
                    .build();
        } catch (PageError e) {
            return Response.status(404).build();
        }
    }

    @GET
    @Path("jwks")
    @jakarta.ws.rs.Produces("application/jwk-set+json")
    public Response jwks(@PathParam("tenant") String tenant) {
        try {
            return Response.ok(provider.jwks(tenant))
                    .header("Cache-Control", "public, max-age=300")
                    .build();
        } catch (PageError e) {
            return Response.status(404).build();
        }
    }

    @GET
    @Path("authorize")
    public Response authorizeGet(@PathParam("tenant") String tenant, @Context UriInfo uri) {
        return authorize(tenant, uri.getQueryParameters());
    }

    @POST
    @Path("authorize")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response authorizePost(@PathParam("tenant") String tenant, MultivaluedMap<String, String> form) {
        return authorize(tenant, form);
    }

    private Response authorize(String tenant, MultivaluedMap<String, String> params) {
        OidcProvider.AuthorizeOutcome outcome;
        try {
            outcome = provider.authorize(tenant, copy(params));
        } catch (PageError e) {
            return page(e.status, errorPage(e.getMessage()), null);
        }
        if (outcome.redirect() != null) {
            return Response.status(302)
                    .location(outcome.redirect())
                    .header("Cache-Control", "no-store")
                    .build();
        }
        LoginPage login = outcome.page();
        Duration life = Duration.between(runtime.clock().instant(), login.expiresAt());
        NewCookie cookie = new NewCookie.Builder(cookieName(login.attemptId()))
                .value(login.binding())
                .path("/")
                .maxAge((int) Math.max(1, life.toSeconds()))
                .secure(secureCookies())
                .httpOnly(true)
                .sameSite(NewCookie.SameSite.LAX)
                .build();
        return page(200, loginPage(login), cookie);
    }

    /** The page's status poll; answers only the browser holding the login's cookie. */
    @GET
    @Path("login/{attempt}/status")
    @jakarta.ws.rs.Produces(MediaType.APPLICATION_JSON)
    public Response status(
            @PathParam("tenant") String tenant, @PathParam("attempt") String attempt, @Context HttpHeaders headers) {
        if (attempt.length() > 64) {
            return Response.status(404).build();
        }
        Cookie cookie = headers.getCookies().get(cookieName(attempt));
        try {
            return Response.ok(provider.status(tenant, attempt, cookie == null ? null : cookie.getValue()))
                    .header("Cache-Control", "no-store")
                    .build();
        } catch (PageError e) {
            return Response.status(404).header("Cache-Control", "no-store").build();
        }
    }

    @POST
    @Path("token")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @jakarta.ws.rs.Produces(MediaType.APPLICATION_JSON)
    public Response token(
            @PathParam("tenant") String tenant,
            @HeaderParam("Authorization") String authorization,
            MultivaluedMap<String, String> form) {
        try {
            return noStore(Response.ok(provider.token(tenant, authorization, copy(form))));
        } catch (OAuthError e) {
            Response.ResponseBuilder b = Response.status(e.status).entity(oauthError(e));
            if (e.status == 401 && authorization != null) {
                b.header("WWW-Authenticate", "Basic realm=\"eudiw-adapter\"");
            }
            return noStore(b);
        }
    }

    @GET
    @Path("userinfo")
    @jakarta.ws.rs.Produces(MediaType.APPLICATION_JSON)
    public Response userinfoGet(
            @PathParam("tenant") String tenant, @HeaderParam("Authorization") String authorization) {
        return userinfo(tenant, authorization);
    }

    @POST
    @Path("userinfo")
    @jakarta.ws.rs.Produces(MediaType.APPLICATION_JSON)
    public Response userinfoPost(
            @PathParam("tenant") String tenant, @HeaderParam("Authorization") String authorization) {
        return userinfo(tenant, authorization);
    }

    private Response userinfo(String tenant, String authorization) {
        String bearer = authorization != null && authorization.regionMatches(true, 0, "Bearer ", 0, 7)
                ? authorization.substring(7).strip()
                : null;
        try {
            return noStore(Response.ok(provider.userinfo(tenant, bearer)));
        } catch (OAuthError e) {
            Response.ResponseBuilder b = Response.status(e.status).entity(oauthError(e));
            if (e.status == 401) {
                b.header("WWW-Authenticate", "Bearer error=\"" + e.error + "\"");
            }
            return noStore(b);
        }
    }

    private boolean secureCookies() {
        return "https".equals(runtime.publicBaseUrl().getScheme());
    }

    /**
     * One cookie per login, so two logins in two tabs do not overwrite each other. The {@code __Host-} prefix pins
     * it to this host and path {@code /} over https; a plain-http development setup cannot use the prefix.
     */
    private String cookieName(String attempt) {
        return (secureCookies() ? "__Host-" : "") + "eudiw-login-" + attempt;
    }

    private static Map<String, List<String>> copy(MultivaluedMap<String, String> params) {
        Map<String, List<String>> copy = new LinkedHashMap<>();
        params.forEach((k, v) -> copy.put(k, List.copyOf(v)));
        return copy;
    }

    private static Map<String, Object> oauthError(OAuthError e) {
        return Map.of("error", e.error, "error_description", e.getMessage());
    }

    private static Response noStore(Response.ResponseBuilder b) {
        return b.header("Cache-Control", "no-store")
                .header("Pragma", "no-cache")
                .build();
    }

    private static Response page(int status, String html, NewCookie cookie) {
        Response.ResponseBuilder b = Response.status(status)
                .type("text/html; charset=utf-8")
                .entity(html)
                .header("Content-Security-Policy", PAGE_CSP)
                .header("X-Content-Type-Options", "nosniff")
                .header("Referrer-Policy", "no-referrer")
                .header("Cache-Control", "no-store");
        if (cookie != null) {
            b.cookie(cookie);
        }
        return b.build();
    }

    private String assets() {
        return runtime.publicBaseUrl().getRawPath() + "eudiw-assets/";
    }

    private String loginPage(LoginPage login) {
        String base = runtime.publicBaseUrl().getRawPath();
        String statusUrl = base + "oidc/" + login.tenantId() + "/login/" + login.attemptId() + "/status";
        String cancel =
                provider.cancelRedirect(login.tenantId(), login.attemptId()).toString();
        return "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
                + "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
                + "<meta name=\"robots\" content=\"noindex\">\n"
                + "<title>Sign in with your EU Digital Identity Wallet</title>\n"
                + "<link rel=\"stylesheet\" href=\"" + esc(assets()) + "login.css\">\n"
                + "<script type=\"module\" src=\"" + esc(assets()) + "eudiw-request.js\"></script>\n"
                + "<script type=\"module\" src=\"" + esc(assets()) + "login.js\"></script>\n"
                + "</head>\n<body>\n<main>\n"
                + "<h1>sign in with your wallet<i>.</i></h1>\n"
                + "<p class=\"lead\">Scan the code with your EU Digital Identity Wallet, or open the wallet on this"
                + " device. Keep this page open: it continues by itself once your wallet has answered.</p>\n"
                + "<eudiw-request launch-uri=\"" + esc(login.launchUri()) + "\" status-url=\"" + esc(statusUrl)
                + "\" theme=\"auto\" request-label=\"" + esc(login.requestLabel()) + "\" expires-at=\""
                + esc(login.expiresAt().toString()) + "\"></eudiw-request>\n"
                + "<p class=\"other\"><a href=\"" + esc(cancel) + "\">use another way to sign in</a></p>\n"
                + "</main>\n</body>\n</html>\n";
    }

    private String errorPage(String message) {
        return "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
                + "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
                + "<meta name=\"robots\" content=\"noindex\">\n"
                + "<title>Sign-in not possible</title>\n"
                + "<link rel=\"stylesheet\" href=\"" + esc(assets()) + "login.css\">\n"
                + "</head>\n<body>\n<main>\n<h1>sign-in not possible<i>.</i></h1>\n<p class=\"lead\">" + esc(message)
                + " Go back to the application and try again.</p>\n</main>\n</body>\n</html>\n";
    }

    static String esc(String value) {
        StringBuilder b = new StringBuilder(value.length());
        for (char c : value.toCharArray()) {
            switch (c) {
                case '&' -> b.append("&amp;");
                case '<' -> b.append("&lt;");
                case '>' -> b.append("&gt;");
                case '"' -> b.append("&quot;");
                case '\'' -> b.append("&#39;");
                default -> b.append(c);
            }
        }
        return b.toString();
    }
}
