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
package io.github.suengineering.eudiw.kms.aws;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.impl.ECDSA;
import io.github.suengineering.eudiw.core.keys.RequestSigner;
import java.net.URI;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.KmsClientBuilder;
import software.amazon.awssdk.services.kms.model.KmsException;
import software.amazon.awssdk.services.kms.model.MessageType;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

/**
 * Signs with an {@code ECC_NIST_P256} {@code SIGN_VERIFY} key in AWS KMS. The SHA-256 digest is computed here and
 * sent with {@code MessageType=DIGEST}, so request objects of any size can be signed (KMS takes at most 4096 bytes of
 * raw message). KMS returns a DER signature, converted to the JOSE {@code R || S} form. The key never leaves KMS.
 *
 * <p>Credentials come from the SDK's default chain: environment, web identity (EKS IRSA), container and instance
 * credentials. They are never part of the adapter's configuration.
 */
public final class AwsKmsSigner implements RequestSigner, AutoCloseable {

    private static final Pattern KEY_ID = Pattern.compile("[A-Za-z0-9:/_.+=@-]{1,2048}");
    static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(5);
    static final Duration CALL_TIMEOUT = Duration.ofSeconds(10);

    /**
     * @param keyId key id, key ARN, alias name ({@code alias/...}) or alias ARN
     * @param region the key's region; empty uses the SDK's default region chain ({@code AWS_REGION})
     * @param endpoint a KMS endpoint other than the region's public one, such as a VPC endpoint
     */
    public record Settings(String keyId, Optional<String> region, Optional<URI> endpoint) {
        public Settings {
            if (keyId == null || !KEY_ID.matcher(keyId).matches()) {
                throw new IllegalArgumentException("aws_kms.key_id must be a key id, key ARN, alias or alias ARN");
            }
            Objects.requireNonNull(region, "region");
            Objects.requireNonNull(endpoint, "endpoint");
        }
    }

    private final Settings settings;
    private final KmsClient client;

    public AwsKmsSigner(Settings settings) {
        this(settings, DefaultCredentialsProvider.builder().build());
    }

    /** With explicit credentials, for tests against a KMS emulator. */
    public AwsKmsSigner(Settings settings, AwsCredentialsProvider credentials) {
        this.settings = Objects.requireNonNull(settings, "settings");
        KmsClientBuilder builder = KmsClient.builder()
                .credentialsProvider(credentials)
                .httpClientBuilder(UrlConnectionHttpClient.builder()
                        .connectionTimeout(CONNECT_TIMEOUT)
                        .socketTimeout(CALL_TIMEOUT))
                .overrideConfiguration(c -> c.apiCallTimeout(CALL_TIMEOUT));
        settings.region().map(Region::of).ifPresent(builder::region);
        settings.endpoint().ifPresent(builder::endpointOverride);
        try {
            this.client = builder.build();
        } catch (SdkClientException e) {
            throw new IllegalArgumentException(
                    "AWS KMS client cannot be created (is the region set?): " + e.getMessage());
        }
    }

    @Override
    public byte[] signEs256(byte[] data) throws JOSEException {
        byte[] der;
        try {
            der = client.sign(r -> r.keyId(settings.keyId())
                            .message(SdkBytes.fromByteArray(sha256(data)))
                            .messageType(MessageType.DIGEST)
                            .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256))
                    .signature()
                    .asByteArray();
        } catch (KmsException e) {
            String code = e.awsErrorDetails() == null ? "" : e.awsErrorDetails().errorCode();
            throw new JOSEException("AWS KMS refused to sign with key " + settings.keyId() + ": " + code + " (HTTP "
                    + e.statusCode() + ")");
        } catch (SdkException e) {
            throw new JOSEException(
                    "AWS KMS cannot be reached or used: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        try {
            return ECDSA.transcodeSignatureToConcat(der, 64);
        } catch (JOSEException e) {
            throw new JOSEException("AWS KMS returned a signature that is not ES256; is the key ECC_NIST_P256?");
        }
    }

    @Override
    public void close() {
        client.close();
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
