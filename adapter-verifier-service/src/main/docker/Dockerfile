# Runtime image for the verifier service. Build the application first:
#   ./mvnw -pl adapter-verifier-service -am package -DskipTests
FROM eclipse-temurin:21.0.9_10-jre-alpine

RUN addgroup -S -g 10001 eudiw && adduser -S -u 10001 -G eudiw eudiw
WORKDIR /app
COPY --chown=10001:10001 adapter-verifier-service/target/quarkus-app/lib/ /app/lib/
COPY --chown=10001:10001 adapter-verifier-service/target/quarkus-app/*.jar /app/
COPY --chown=10001:10001 adapter-verifier-service/target/quarkus-app/app/ /app/app/
COPY --chown=10001:10001 adapter-verifier-service/target/quarkus-app/quarkus/ /app/quarkus/

USER 10001
EXPOSE 8080 9000
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-jar", "/app/quarkus-run.jar"]
