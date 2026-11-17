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
package io.github.suengineering.eudiw.core.net;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Flow;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * {@link HttpFetcher} on the JDK HTTP client. Redirects are never followed (a redirect could lead past the egress
 * check), responses are read up to a size limit, and one deadline covers the whole fetch: the egress check with its
 * DNS lookup, the connection, the headers and the body. {@code HttpRequest.timeout} alone does not bound the body,
 * so a server that sends headers and then drips bytes would otherwise hold the caller.
 */
public final class JdkHttpFetcher implements HttpFetcher {

    /** DNS lookups cannot be interrupted; a small bounded pool keeps slow ones from piling up threads. */
    private static final ThreadPoolExecutor RESOLVER =
            new ThreadPoolExecutor(0, 16, 30, TimeUnit.SECONDS, new SynchronousQueue<>(), r -> {
                Thread thread = new Thread(r, "eudiw-egress-resolver");
                thread.setDaemon(true);
                return thread;
            });

    private final HttpClient client;
    private final EgressPolicy policy;
    private final Duration timeout;

    public JdkHttpFetcher(EgressPolicy policy, Duration timeout) {
        this.policy = Objects.requireNonNull(policy, "policy");
        this.timeout = Objects.requireNonNull(timeout, "timeout");
        this.client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(timeout)
                .build();
    }

    @Override
    public byte[] get(URI uri, String accept, int maxBytes) throws FetchException {
        long deadline = System.nanoTime() + timeout.toNanos();
        check(uri, deadline);
        HttpRequest request = HttpRequest.newBuilder(uri)
                .timeout(timeout)
                .header("Accept", accept)
                .GET()
                .build();
        CompletableFuture<HttpResponse<byte[]>> exchange = client.sendAsync(request, info -> {
            int status = info.statusCode();
            return new BoundedBody(maxBytes, status < 200 || status > 299 ? "unexpected HTTP status " + status : null);
        });
        return await(exchange, deadline).body();
    }

    private void check(URI uri, long deadline) throws FetchException {
        Future<?> lookup;
        try {
            lookup = RESOLVER.submit(() -> {
                policy.check(uri);
                return null;
            });
        } catch (RejectedExecutionException e) {
            throw new FetchException("too many pending DNS lookups", e);
        }
        await(lookup, deadline);
    }

    private static <T> T await(Future<T> future, long deadline) throws FetchException {
        try {
            return future.get(Math.max(0, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
        } catch (TimeoutException e) {
            future.cancel(true);
            throw new FetchException("request timed out", e);
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof FetchException f) {
                throw new FetchException(f.getMessage(), f);
            }
            if (cause instanceof IOException) {
                throw new FetchException("request failed", cause);
            }
            throw new FetchException("request failed", cause == null ? e : cause);
        } catch (InterruptedException e) {
            future.cancel(true);
            Thread.currentThread().interrupt();
            throw new FetchException("request interrupted", e);
        }
    }

    /** Collects at most {@code maxBytes}, and cancels the response as soon as it is refused or too large. */
    private static final class BoundedBody implements HttpResponse.BodySubscriber<byte[]> {

        private final int maxBytes;
        private final String refusal;
        private final CompletableFuture<byte[]> result = new CompletableFuture<>();
        private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        private Flow.Subscription subscription;

        BoundedBody(int maxBytes, String refusal) {
            this.maxBytes = maxBytes;
            this.refusal = refusal;
        }

        @Override
        public void onSubscribe(Flow.Subscription subscription) {
            this.subscription = subscription;
            if (refusal != null) {
                fail(refusal);
            } else {
                subscription.request(Long.MAX_VALUE);
            }
        }

        @Override
        public void onNext(List<ByteBuffer> items) {
            for (ByteBuffer item : items) {
                if (result.isDone()) {
                    return;
                }
                if (item.remaining() > maxBytes - buffer.size()) {
                    fail("response exceeds " + maxBytes + " bytes");
                    return;
                }
                byte[] bytes = new byte[item.remaining()];
                item.get(bytes);
                buffer.writeBytes(bytes);
            }
        }

        @Override
        public void onError(Throwable throwable) {
            result.completeExceptionally(throwable);
        }

        @Override
        public void onComplete() {
            result.complete(buffer.toByteArray());
        }

        @Override
        public CompletionStage<byte[]> getBody() {
            return result;
        }

        private void fail(String message) {
            subscription.cancel();
            result.completeExceptionally(new FetchException(message));
        }
    }
}
