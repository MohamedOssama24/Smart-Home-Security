# Build context: repository root (needs /database/migrations)
#   docker build -f backend/spring-boot-api/Dockerfile .
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /build
COPY backend/spring-boot-api/pom.xml backend/spring-boot-api/pom.xml
RUN mvn -q -f backend/spring-boot-api/pom.xml dependency:go-offline -B
COPY database/migrations database/migrations
COPY backend/spring-boot-api/src backend/spring-boot-api/src
# Tests run separately (they need Docker for Testcontainers): see infrastructure/scripts/test-backend.sh
RUN mvn -q -f backend/spring-boot-api/pom.xml -B -DskipTests package \
 && cp backend/spring-boot-api/target/spring-boot-api-*.jar /build/app.jar

FROM eclipse-temurin:21-jre-alpine
RUN addgroup -S shsc && adduser -S -G shsc -H shsc && apk add --no-cache wget
WORKDIR /app
COPY --from=build --chown=shsc:shsc /build/app.jar /app/app.jar
USER shsc
EXPOSE 8080
ENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=75 -XX:+ExitOnOutOfMemoryError"
HEALTHCHECK --interval=15s --timeout=3s --start-period=60s --retries=5 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/actuator/health/readiness || exit 1
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
