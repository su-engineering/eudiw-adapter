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

import com.fasterxml.jackson.annotation.JsonProperty;
import io.github.suengineering.eudiw.service.engine.AdapterRuntime;
import io.github.suengineering.eudiw.service.engine.VerificationEngine;
import io.github.suengineering.eudiw.service.store.SessionStore.SessionRow;
import io.quarkus.security.Authenticated;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/** The application-facing API. Every operation is authenticated, scoped and filtered by tenant and client. */
@Path("/v1/verification-sessions")
@Authenticated
@Produces(MediaType.APPLICATION_JSON)
public class VerificationSessionResource {

    @Inject
    Callers callers;

    @Inject
    VerificationEngine engine;

    @Inject
    AdapterRuntime runtime;

    public record CreateBody(
            @JsonProperty("policy_id") String policyId,
            @JsonProperty("mode") String mode,
            @JsonProperty("client_reference") String clientReference) {}

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public Response create(CreateBody body, @HeaderParam("Idempotency-Key") String idempotencyKey) {
        var caller = callers.require("verification:create");
        VerificationEngine.Created created = engine.create(
                caller,
                body == null
                        ? null
                        : new VerificationEngine.CreateRequest(body.policyId(), body.mode(), body.clientReference()),
                idempotencyKey);
        Map<String, Object> out = view(created.session());
        out.put(
                "wallet_launch",
                Map.of(
                        "request_uri", created.requestUri(),
                        "launch_uri", created.launchUri(),
                        "qr_payload", created.launchUri()));
        out.put("poll_url", "/v1/verification-sessions/" + created.session().id());
        return Response.status(201)
                .header("Cache-Control", "no-store")
                .entity(out)
                .build();
    }

    @GET
    @Path("{id}")
    public Response get(@PathParam("id") String id) {
        var caller = callers.require("verification:read");
        return Response.ok(view(engine.status(caller, id)))
                .header("Cache-Control", "no-store")
                .build();
    }

    @GET
    @Path("{id}/result")
    public Response result(@PathParam("id") String id, @QueryParam("response_code") String responseCode) {
        var caller = callers.require("verification:result");
        return Response.ok(engine.result(caller, id, responseCode))
                .header("Cache-Control", "no-store")
                .build();
    }

    @POST
    @Path("{id}/cancel")
    public Response cancel(@PathParam("id") String id) {
        var caller = callers.require("verification:cancel");
        engine.cancel(caller, id);
        return Response.ok(view(engine.status(caller, id)))
                .header("Cache-Control", "no-store")
                .build();
    }

    private Map<String, Object> view(SessionRow session) {
        Instant now = runtime.clock().instant();
        String status = session.status();
        if (status.equals("pending") && !now.isBefore(session.expiresAt())) {
            status = "expired";
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("id", session.id());
        out.put("status", status);
        out.put("policy_id", session.policyId());
        out.put("mode", session.mode());
        if (session.clientReference() != null) {
            out.put("client_reference", session.clientReference());
        }
        out.put("created_at", session.createdAt().toString());
        out.put("expires_at", session.expiresAt().toString());
        if (session.completedAt() != null) {
            out.put("completed_at", session.completedAt().toString());
        }
        if (status.equals("rejected") && session.failureCode() != null) {
            out.put("reason", session.failureCode());
        }
        out.put("result_available", status.equals("verified") && session.hasResult());
        return out;
    }
}
