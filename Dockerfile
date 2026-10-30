FROM maven:3.9.9-eclipse-temurin-21-alpine AS build
WORKDIR /src
COPY pom.xml .
RUN mvn -q -B dependency:go-offline
COPY src ./src
RUN mvn -q -B -DskipTests package \
    && java -Djarmode=tools -jar target/sentinel-stream-*.jar extract --layers --launcher --destination /extracted

FROM eclipse-temurin:21-jre-alpine
# RocksDB (Kafka Streams state stores) ships a native library linked against libstdc++.
RUN apk add --no-cache libstdc++
RUN addgroup -S sentinel && adduser -S -G sentinel -u 10001 sentinel \
    && mkdir -p /var/lib/sentinel/streams && chown -R 10001:sentinel /var/lib/sentinel
WORKDIR /app
COPY --from=build /extracted/dependencies/ ./
COPY --from=build /extracted/spring-boot-loader/ ./
COPY --from=build /extracted/snapshot-dependencies/ ./
COPY --from=build /extracted/application/ ./
USER 10001
ENV SENTINEL_PORT=8080 \
    SENTINEL_STATE_DIR=/var/lib/sentinel/streams \
    JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=75 -XX:+ExitOnOutOfMemoryError"
HEALTHCHECK --interval=5s --timeout=3s --start-period=60s --retries=12 \
    CMD wget -qO- "http://localhost:${SENTINEL_PORT}/actuator/health/readiness" | grep -q UP || exit 1
ENTRYPOINT ["java", "org.springframework.boot.loader.launch.JarLauncher"]
