# Runtime image for the verifier service. Build the application first:
#   ./mvnw -pl adapter-verifier-service -am package -DskipTests
# glibc base, so vendor PKCS#11 libraries for HSMs and KMSs can be loaded.
FROM eclipse-temurin:21.0.9_10-jre-noble@sha256:d3eb69add1874bc785382d6282db53a67841f602a1139dee6c4a1221d8c56568

# Optional OS packages, for example "softhsm2 opensc openssl" for the local demo. Empty for production images.
ARG EXTRA_PACKAGES=""
RUN if [ -n "$EXTRA_PACKAGES" ]; then \
      apt-get update && apt-get install -y --no-install-recommends $EXTRA_PACKAGES && rm -rf /var/lib/apt/lists/*; \
    fi \
 && groupadd --system --gid 10001 eudiw \
 && useradd --system --uid 10001 --gid eudiw --no-create-home --shell /usr/sbin/nologin eudiw
WORKDIR /app
COPY --chown=10001:10001 adapter-verifier-service/target/quarkus-app/lib/ /app/lib/
COPY --chown=10001:10001 adapter-verifier-service/target/quarkus-app/*.jar /app/
COPY --chown=10001:10001 adapter-verifier-service/target/quarkus-app/app/ /app/app/
COPY --chown=10001:10001 adapter-verifier-service/target/quarkus-app/quarkus/ /app/quarkus/

USER 10001
EXPOSE 8080 9000
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-jar", "/app/quarkus-run.jar"]
