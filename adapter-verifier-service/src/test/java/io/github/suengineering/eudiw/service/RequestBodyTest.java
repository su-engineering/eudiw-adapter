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
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;

import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/** Request bodies are held to the published schema: unknown properties and malformed JSON get a 400 problem. */
@QuarkusTest
@QuarkusTestResource(TestEnvironment.class)
class RequestBodyTest {

    @Test
    void aPropertyTheSchemaDoesNotDefineIsRefused() {
        given().auth()
                .oauth2(TestWallet.fullToken("portal-a"))
                .header("Idempotency-Key", UUID.randomUUID().toString())
                .contentType(ContentType.JSON)
                .body(Map.of("policy_id", "age-over-18", "dcql", Map.of("credentials", "anything")))
                .post("/v1/verification-sessions")
                .then()
                .statusCode(400)
                .contentType("application/problem+json")
                .body("code", equalTo("invalid_request"))
                .body("detail", not(containsString("dcql")));
    }

    @Test
    void malformedJsonIsAProblemNotAServerError() {
        given().auth()
                .oauth2(TestWallet.fullToken("portal-a"))
                .header("Idempotency-Key", UUID.randomUUID().toString())
                .contentType(ContentType.JSON)
                .body("{\"policy_id\": \"age-over-18\"")
                .post("/v1/verification-sessions")
                .then()
                .statusCode(400)
                .contentType("application/problem+json")
                .body("code", equalTo("invalid_request"));
        given().auth()
                .oauth2(TestWallet.fullToken("portal-a"))
                .header("Idempotency-Key", UUID.randomUUID().toString())
                .contentType(ContentType.JSON)
                .body(Map.of("policy_id", Map.of("nested", true)))
                .post("/v1/verification-sessions")
                .then()
                .statusCode(400)
                .body("code", equalTo("invalid_request"));
    }

    @Test
    void theDocumentedPropertiesStillWork() {
        given().auth()
                .oauth2(TestWallet.fullToken("portal-a"))
                .header("Idempotency-Key", UUID.randomUUID().toString())
                .contentType(ContentType.JSON)
                .body(Map.of("policy_id", "age-over-18", "mode", "cross_device", "client_reference", "ref-1"))
                .post("/v1/verification-sessions")
                .then()
                .statusCode(201);
    }
}
