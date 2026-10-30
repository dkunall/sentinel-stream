package com.sentinelstream.support;

import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.kafka.KafkaContainer;

import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Map;

/** One of each dependency per JVM, started on first use. Credentials are random per run and never printed. */
public final class Containers {

    public static final String DB_PASSWORD = random();
    public static final String S3_ACCESS = "sentinel" + random().substring(0, 8);
    public static final String S3_SECRET = random();

    private static PostgreSQLContainer<?> postgres;
    private static KafkaContainer kafka;
    private static GenericContainer<?> redis;
    private static GenericContainer<?> s3;

    private Containers() {
    }

    public static synchronized PostgreSQLContainer<?> postgres() {
        if (postgres == null) {
            var pg = new PostgreSQLContainer<>("postgres:16-alpine").withDatabaseName("sentinel").withUsername("sentinel")
                    .withPassword(DB_PASSWORD);
            pg.start();
            postgres = pg;
        }
        return postgres;
    }

    public static synchronized KafkaContainer kafka() {
        if (kafka == null) {
            var k = new KafkaContainer("apache/kafka:3.8.0").withEnv("KAFKA_HEAP_OPTS", "-Xms256m -Xmx256m");
            k.start();
            kafka = k;
        }
        return kafka;
    }

    public static synchronized GenericContainer<?> redis() {
        if (redis == null) {
            GenericContainer<?> r = new GenericContainer<>("redis:7-alpine").withExposedPorts(6379);
            r.start();
            redis = r;
        }
        return redis;
    }

    /** versitygw on a tmpfs posix backend with versioning, which object lock needs. */
    public static synchronized GenericContainer<?> s3() {
        if (s3 == null) {
            GenericContainer<?> g = new GenericContainer<>("versity/versitygw:v1.10.0")
                    .withEnv("ROOT_ACCESS_KEY", S3_ACCESS).withEnv("ROOT_SECRET_KEY", S3_SECRET)
                    .withTmpFs(Map.of("/gw", "rw", "/vers", "rw"))
                    .withCommand("posix", "--versioning-dir", "/vers", "/gw")
                    .withExposedPorts(7070)
                    .waitingFor(Wait.forListeningPort());
            g.start();
            s3 = g;
        }
        return s3;
    }

    public static String s3Endpoint() {
        return "http://" + s3().getHost() + ":" + s3().getMappedPort(7070);
    }

    private static String random() {
        byte[] bytes = new byte[18];
        new SecureRandom().nextBytes(bytes);
        return HexFormat.of().formatHex(bytes);
    }
}
