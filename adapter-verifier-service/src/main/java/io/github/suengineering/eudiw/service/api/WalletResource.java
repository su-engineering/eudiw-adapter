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
package io.github.suengineering.eudiw.service.api;

import io.github.suengineering.eudiw.core.oid4vp.AuthorizationRequests;
import io.github.suengineering.eudiw.service.engine.VerificationEngine;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.util.HashMap;
import java.util.Map;

/**
 * Wallet-facing OpenID4VP endpoints. Unauthenticated by design: possession of the request handle, state and the
 * per-request encryption key is what binds a wallet to a session. Responses are never cached.
 */
@Path("/oid4vp")
public class WalletResource {

    @Inject
    VerificationEngine engine;

    @Context
    io.vertx.core.http.HttpServerRequest http;

    /** Request URI, GET method (RFC 9101). */
    @GET
    @Path("requests/{handle}")
    public Response requestObjectGet(@PathParam("handle") String handle) {
        return requestObject(handle, null);
    }

    /**
     * 429 with {@code Retry-After} when this source address is over the wallet request limit, before any lookup.
     * The address is the one Quarkus resolved, so a forwarded address counts only when proxy forwarding is on.
     */
    private Response refused() {
        // hostAddress() is null when a forwarded value is not an IP literal; the engine puts those in one bucket.
        String address = http == null || http.remoteAddress() == null
                ? null
                : http.remoteAddress().hostAddress();
        return engine.walletRequestRefused(address)
                .map(seconds -> Response.status(429)
                        .type(MediaType.APPLICATION_JSON)
                        .header("Cache-Control", "no-store")
                        .header("Retry-After", seconds)
                        .entity(Map.of("error", "rate_limited"))
                        .build())
                .orElse(null);
    }

    /** Request URI, POST method (OpenID4VP 1.0 section 5.10). */
    @POST
    @Path("requests/{handle}")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response requestObjectPost(
            @PathParam("handle") String handle, @FormParam("wallet_nonce") String walletNonce) {
        return requestObject(handle, walletNonce);
    }

    private Response requestObject(String handle, String walletNonce) {
        Response refused = refused();
        if (refused != null) {
            return refused;
        }
        return engine.requestObject(handle, walletNonce)
                .map(jwt -> Response.ok(jwt, AuthorizationRequests.REQUEST_OBJECT_MEDIA_TYPE))
                .orElseGet(() -> Response.status(404))
                .header("Cache-Control", "no-store")
                .build();
    }

    /** Response URI for {@code direct_post.jwt} (OpenID4VP 1.0 sections 8.2 and 8.3.1). */
    @POST
    @Path("responses")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response response(MultivaluedMap<String, String> form) {
        Response refused = refused();
        if (refused != null) {
            return refused;
        }
        Map<String, String> single = new HashMap<>();
        for (var entry : form.entrySet()) {
            if (entry.getValue().size() != 1) {
                return reply(new VerificationEngine.WalletReply(400, Map.of("error", "invalid_request")));
            }
            single.put(entry.getKey(), entry.getValue().get(0));
        }
        return reply(engine.handleResponse(single));
    }

    private static Response reply(VerificationEngine.WalletReply reply) {
        return Response.status(reply.status())
                .type(MediaType.APPLICATION_JSON)
                .header("Cache-Control", "no-store")
                .entity(reply.body())
                .build();
    }
}
