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

import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.jboss.logging.Logger;

/**
 * Renders every error as {@code application/problem+json} with a machine-readable code and a correlation id.
 * Unexpected exceptions are logged with the correlation id only; their messages never reach the caller.
 */
@Provider
public class ProblemMapper implements ExceptionMapper<Exception> {

    private static final Logger LOG = Logger.getLogger(ProblemMapper.class);

    @Override
    public Response toResponse(Exception exception) {
        String correlationId = UUID.randomUUID().toString();
        int status;
        String code;
        String detail;
        if (exception instanceof ApiException api) {
            status = api.status();
            code = api.code();
            detail = api.getMessage();
        } else if (exception instanceof WebApplicationException web) {
            status = web.getResponse().getStatus();
            code = status == 401
                    ? "unauthorized"
                    : status == 403 ? "forbidden" : status == 404 ? "not_found" : "invalid_request";
            detail = "request rejected";
        } else {
            status = 500;
            code = "internal_error";
            detail = "internal error";
            LOG.errorf(
                    "unhandled error, correlation %s: %s",
                    correlationId, exception.getClass().getName());
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("type", "about:blank");
        body.put("title", code);
        body.put("status", status);
        body.put("code", code);
        body.put("detail", detail);
        body.put("correlation_id", correlationId);
        return Response.status(status)
                .type("application/problem+json")
                .header("Cache-Control", "no-store")
                .entity(body)
                .build();
    }
}
