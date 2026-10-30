package com.sentinelstream.support;

import org.junit.jupiter.api.BeforeEach;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.nio.file.Files;
import java.util.UUID;

/**
 * The whole app on a random port against real Postgres, Kafka, Redis and versitygw. Every IT class shares
 * this configuration, so Spring caches one context for the run. Tests isolate themselves by using their own
 * entity names rather than by wiping tables, which is closer to a shared deployment anyway.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(ItBase.Security.class)
public abstract class ItBase {

    @TestConfiguration(proxyBeanMethods = false)
    static class Security {
        @Bean
        @Primary
        JwtDecoder testJwtDecoder() {
            return TestJwt.decoder();
        }
    }

    @LocalServerPort
    protected int port;

    protected Api acme;
    protected Api acme2;
    protected Api acmeAdmin;
    protected Api acmeAdmin2;
    protected Api globex;
    protected Api anon;

    @DynamicPropertySource
    static void wire(DynamicPropertyRegistry r) throws Exception {
        var pg = Containers.postgres();
        r.add("spring.datasource.url", pg::getJdbcUrl);
        r.add("spring.datasource.username", pg::getUsername);
        r.add("spring.datasource.password", () -> Containers.DB_PASSWORD);
        r.add("spring.kafka.bootstrap-servers", () -> Containers.kafka().getBootstrapServers());
        r.add("spring.data.redis.host", () -> Containers.redis().getHost());
        r.add("spring.data.redis.port", () -> Containers.redis().getMappedPort(6379));
        r.add("sentinel.audit.s3-endpoint", Containers::s3Endpoint);
        r.add("sentinel.audit.s3-access-key", () -> Containers.S3_ACCESS);
        r.add("sentinel.audit.s3-secret-key", () -> Containers.S3_SECRET);
        r.add("sentinel.audit.bucket", () -> "audit-it");
        r.add("sentinel.audit.seal-every", () -> "1h");
        r.add("sentinel.webhooks.secret", () -> UUID.randomUUID().toString());
        String stateDir = Files.createTempDirectory("sentinel-it").toString();
        r.add("sentinel.streams.state-dir", () -> stateDir);
        r.add("sentinel.streams.application-id", () -> "sentinel-it-" + UUID.randomUUID());
        r.add("sentinel.streams.rules-poll", () -> "500ms");
    }

    @BeforeEach
    void clients() {
        Api base = Api.at(port);
        anon = base;
        acme = base.as(TestJwt.analyst("analyst@acme"));
        acme2 = base.as(TestJwt.analyst("analyst2@acme"));
        acmeAdmin = base.as(TestJwt.admin("admin@acme"));
        acmeAdmin2 = base.as(TestJwt.admin("admin2@acme"));
        globex = base.as(TestJwt.admin("analyst@globex"));
    }

    protected static String unique(String prefix) {
        return prefix + "-" + UUID.randomUUID().toString().substring(0, 8);
    }
}
