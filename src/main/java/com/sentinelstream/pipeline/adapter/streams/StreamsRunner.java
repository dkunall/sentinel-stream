package com.sentinelstream.pipeline.adapter.streams;

import com.sentinelstream.detection.application.RuleSets;
import com.sentinelstream.ingest.domain.Normalizer;
import com.sentinelstream.ingest.domain.enrich.EnricherChain;
import com.sentinelstream.shared.config.SentinelProperties;
import org.apache.kafka.common.serialization.Serdes;
import org.apache.kafka.streams.KafkaStreams;
import org.apache.kafka.streams.StreamsConfig;
import org.apache.kafka.streams.errors.StreamsUncaughtExceptionHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.context.SmartLifecycle;
import org.springframework.kafka.core.KafkaAdmin;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.util.Properties;

/** Owns the Kafka Streams instance: starts after topics exist, reports in health, closes on shutdown. */
@Component
class StreamsRunner implements SmartLifecycle, HealthIndicator {

    private static final Logger log = LoggerFactory.getLogger(StreamsRunner.class);

    private final Properties config = new Properties();
    private final Normalizer normalizer;
    private final EnricherChain enricher;
    private final RuleSets rules;
    private final Duration idleTtl;
    private final KafkaAdmin admin;
    private volatile KafkaStreams streams;
    private final ReplacementBudget budget = new ReplacementBudget();

    StreamsRunner(SentinelProperties props, Clock clock, EnricherChain enricher, RuleSets rules, KafkaAdmin admin,
                  @Value("${spring.kafka.bootstrap-servers}") String bootstrap) {
        var s = props.streams();
        config.put(StreamsConfig.APPLICATION_ID_CONFIG, s.applicationId());
        config.put(StreamsConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrap);
        config.put(StreamsConfig.STATE_DIR_CONFIG, s.stateDir());
        config.put(StreamsConfig.PROCESSING_GUARANTEE_CONFIG, StreamsConfig.EXACTLY_ONCE_V2);
        config.put(StreamsConfig.COMMIT_INTERVAL_MS_CONFIG, 100);
        config.put(StreamsConfig.NUM_STREAM_THREADS_CONFIG, 1);
        config.put(StreamsConfig.REPLICATION_FACTOR_CONFIG, 1);
        config.put(StreamsConfig.STATESTORE_CACHE_MAX_BYTES_CONFIG, 8L * 1024 * 1024);
        config.put(StreamsConfig.DEFAULT_KEY_SERDE_CLASS_CONFIG, Serdes.StringSerde.class);
        config.put(StreamsConfig.DEFAULT_VALUE_SERDE_CLASS_CONFIG, Serdes.StringSerde.class);
        this.normalizer = new Normalizer(clock, props.ingest().maxEventAge(), props.ingest().maxClockSkew());
        this.enricher = enricher;
        this.rules = rules;
        this.idleTtl = s.entityIdleTtl();
        this.admin = admin;
    }

    @Override
    public void start() {
        admin.initialize();
        KafkaStreams ks = new KafkaStreams(DetectionTopology.build(normalizer, enricher, rules, idleTtl), config);
        ks.setUncaughtExceptionHandler(e -> {
            if (budget.tryReplace(System.nanoTime())) {
                log.error("stream thread failed, replacing it", e);
                return StreamsUncaughtExceptionHandler.StreamThreadExceptionResponse.REPLACE_THREAD;
            }
            // A failure that keeps coming back (a missing native library, a corrupt store) will not heal by
            // retrying; stop the client so health and readiness go DOWN instead of reporting a busy loop as UP.
            log.error("stream threads failed {} times within {}; shutting the detector down", ReplacementBudget.MAX,
                    ReplacementBudget.WINDOW, e);
            return StreamsUncaughtExceptionHandler.StreamThreadExceptionResponse.SHUTDOWN_CLIENT;
        });
        ks.start();
        streams = ks;
    }

    @Override
    public void stop() {
        KafkaStreams ks = streams;
        streams = null;
        if (ks != null) {
            ks.close(Duration.ofSeconds(10));
        }
    }

    @Override
    public boolean isRunning() {
        return streams != null;
    }

    @Override
    public Health health() {
        KafkaStreams ks = streams;
        if (ks == null) {
            return Health.down().withDetail("state", "stopped").build();
        }
        var state = ks.state();
        return (state.isRunningOrRebalancing() ? Health.up() : Health.down()).withDetail("state", state.name()).build();
    }
}
