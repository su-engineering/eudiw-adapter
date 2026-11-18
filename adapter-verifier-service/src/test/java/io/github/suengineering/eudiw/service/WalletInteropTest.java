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

import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.http.ContentType;
import io.restassured.path.json.JsonPath;
import java.time.Duration;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.testcontainers.Testcontainers;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.startupcheck.OneShotStartupCheckStrategy;
import org.testcontainers.utility.MountableFile;

/**
 * Interoperability with an independently developed wallet, the eudi-dev test wallet, driven only through its
 * documented command line ({@code eudi issue sdjwt --wallet}, {@code eudi wallet accept --haip --arf --mode strict}). The wallet
 * issues itself a credential under a test issuer key, fetches our signed request, and posts an encrypted response.
 */
@QuarkusTest
@TestProfile(WalletInteropTest.InteropProfile.class)
@QuarkusTestResource(TestEnvironment.class)
class WalletInteropTest {

    static final int PORT = 18081;
    static final String WALLET_IMAGE = "ghcr.io/eudi-dev/eudi-dev:v3.8.0";

    public static class InteropProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of(
                    "quarkus.http.test-port",
                    Integer.toString(PORT),
                    "eudiw.public-base-url",
                    "http://host.testcontainers.internal:" + PORT);
        }
    }

    @jakarta.inject.Inject
    io.github.suengineering.eudiw.service.engine.AdapterRuntime runtime;

    @Test
    void eudiDevWalletCompletesAHaipPresentation() {
        Started started = startSession();

        boolean walletSucceeded = runWallet(started.launch(), "rp-root.pem");

        assertThat(walletSucceeded).isTrue();
        given().auth()
                .oauth2(started.token())
                .get("/v1/verification-sessions/" + started.id())
                .then()
                .statusCode(200)
                .body("status", org.hamcrest.Matchers.equalTo("verified"));
        String result = given().auth()
                .oauth2(started.token())
                .get("/v1/verification-sessions/" + started.id() + "/result")
                .then()
                .statusCode(200)
                .extract()
                .asString();
        assertThat(new JsonPath(result).getBoolean("claims.age_over_18")).isTrue();
        assertThat(result).doesNotContain("Erika-Canary");
    }

    /** The wallet checks our access certificate chain (ARF RPA_04); an untrusted chain must be refused. */
    @Test
    void eudiDevWalletRefusesAnUntrustedRelyingParty() {
        Started started = startSession();

        boolean walletSucceeded = runWallet(started.launch(), "issuer-b-root.pem");

        assertThat(walletSucceeded).isFalse();
        given().auth()
                .oauth2(started.token())
                .get("/v1/verification-sessions/" + started.id())
                .then()
                .statusCode(200)
                .body("status", org.hamcrest.Matchers.equalTo("pending"));
    }

    private record Started(String id, String launch, String token) {}

    private Started startSession() {
        runtime.reconfigureForTests(
                java.time.Clock.systemUTC(),
                (uri, accept, max) -> TestWallet.statusListToken(
                                TestEnvironment.ISSUER_A, "issuer-a-key.pem", "issuer-a.pem")
                        .getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        Testcontainers.exposeHostPorts(PORT, TestEnvironment.receiverPort);
        String token = TestWallet.fullToken("portal-a");
        JsonPath session = given().auth()
                .oauth2(token)
                .header("Idempotency-Key", UUID.randomUUID().toString())
                .contentType(ContentType.JSON)
                .body(Map.of("policy_id", "age-over-18", "mode", "cross_device"))
                .post("/v1/verification-sessions")
                .then()
                .statusCode(201)
                .extract()
                .jsonPath();
        return new Started(session.getString("id"), session.getString("wallet_launch.launch_uri"), token);
    }

    /**
     * Runs the wallet: issue a credential under issuer A, then accept the request in HAIP and ARF strict mode,
     * trusting {@code relyingPartyCa} for relying-party access certificates.
     *
     * @return whether the wallet completed the presentation
     */
    private static boolean runWallet(String launch, String relyingPartyCa) {
        String script = String.join(
                " && ",
                "mkdir -p /tmp/w",
                "eudi issue sdjwt --wallet --storage file --wallet-dir /tmp/w --key /env/issuer-a-key.pem"
                        + " --cert /env/issuer-a.pem --iss " + TestEnvironment.ISSUER_A
                        + " --vct " + TestEnvironment.VCT
                        + " --status-list-uri " + TestWallet.statusUri(TestEnvironment.ISSUER_A)
                        + " --status-list-idx 1"
                        + " --claims '{\"age_over_18\":true,\"given_name\":\"Erika-Canary\"}'",
                "eudi wallet accept --storage file --wallet-dir /tmp/w --haip --arf --mode strict"
                        + " --relying-party-ca /env/rp-ca.pem --auto-accept --no-open '" + launch + "'");
        try (GenericContainer<?> wallet = new GenericContainer<>(WALLET_IMAGE)
                .withCreateContainerCmdModifier(cmd -> cmd.withEntrypoint("sh"))
                .withCommand("-c", script)
                .withCopyFileToContainer(
                        MountableFile.forHostPath(TestEnvironment.DIR.resolve("issuer-a-key.pem")),
                        "/env/issuer-a-key.pem")
                .withCopyFileToContainer(
                        MountableFile.forHostPath(TestEnvironment.DIR.resolve("issuer-a.pem")), "/env/issuer-a.pem")
                .withCopyFileToContainer(
                        MountableFile.forHostPath(TestEnvironment.DIR.resolve(relyingPartyCa)), "/env/rp-ca.pem")
                .withLogConsumer(frame -> System.out.print("[eudi-dev] " + frame.getUtf8String()))
                .withStartupCheckStrategy(new OneShotStartupCheckStrategy().withTimeout(Duration.ofMinutes(2)))) {
            wallet.start();
            return true;
        } catch (org.testcontainers.containers.ContainerLaunchException e) {
            return false;
        }
    }
}
