package com.sentinelstream.pipeline.adapter.streams;

import com.fasterxml.jackson.databind.JsonNode;
import com.sentinelstream.detection.domain.engine.ActiveRule;
import com.sentinelstream.detection.domain.engine.RuleSet;
import com.sentinelstream.detection.domain.engine.Signal;
import com.sentinelstream.detection.domain.rule.RuleCompiler;
import com.sentinelstream.detection.domain.rule.Severity;
import com.sentinelstream.ingest.domain.Normalizer;
import com.sentinelstream.ingest.domain.RawEnvelope;
import com.sentinelstream.ingest.domain.enrich.EnricherChain;
import com.sentinelstream.ingest.domain.enrich.IpRangeTable;
import com.sentinelstream.shared.Json;
import com.sentinelstream.shared.Topics;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.apache.kafka.streams.StreamsConfig;
import org.apache.kafka.streams.TestInputTopic;
import org.apache.kafka.streams.TestOutputTopic;
import org.apache.kafka.streams.TopologyTestDriver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

class DetectionTopologyTest {

    static final Instant NOW = Instant.parse("2026-10-30T12:00:00Z");
    static final String FRANKFURT_HOSTING = "203.0.113.9";

    final List<TopologyTestDriver> drivers = new ArrayList<>();
    TopologyTestDriver driver;
    TestInputTopic<String, String> raw;
    TestOutputTopic<String, String> alerts;
    TestOutputTopic<String, String> normalized;
    TestOutputTopic<String, String> dlq;

    @BeforeEach
    void setUp() throws Exception {
        driver = newDriver();
        raw = driver.createInputTopic(Topics.RAW, new StringSerializer(), new StringSerializer());
        alerts = driver.createOutputTopic(Topics.ALERTS, new StringDeserializer(), new StringDeserializer());
        normalized = driver.createOutputTopic(Topics.NORMALIZED, new StringDeserializer(), new StringDeserializer());
        dlq = driver.createOutputTopic(Topics.DLQ, new StringDeserializer(), new StringDeserializer());
    }

    @AfterEach
    void tearDown() {
        drivers.forEach(TopologyTestDriver::close);
    }

    TopologyTestDriver newDriver() throws Exception {
        var rule = new ActiveRule("bf", 1, "Brute force then success", Severity.HIGH, new RuleCompiler().compile(
                "sequence login.failure{5,} then login.success where asn is new by user within 10m"));
        return newDriver(new RuleSet(1, List.of(rule), Map.of()));
    }

    TopologyTestDriver newDriver(RuleSet set) throws Exception {
        EnricherChain chain;
        try (var in = getClass().getResourceAsStream("/geo/synthetic-ip-table.csv")) {
            chain = EnricherChain.standard(IpRangeTable.fromCsv(new InputStreamReader(in, StandardCharsets.UTF_8)));
        }
        var normalizer = new Normalizer(Clock.fixed(NOW, ZoneOffset.UTC), Duration.ofDays(30), Duration.ofMinutes(5));
        var topology = DetectionTopology.build(normalizer, chain, tenant -> "acme".equals(tenant) ? set : RuleSet.EMPTY,
                Duration.ofDays(7));
        Properties p = new Properties();
        p.put(StreamsConfig.APPLICATION_ID_CONFIG, "topology-test");
        p.put(StreamsConfig.BOOTSTRAP_SERVERS_CONFIG, "unused:9092");
        p.put(StreamsConfig.STATE_DIR_CONFIG, Files.createTempDirectory("streams").toString());
        var d = new TopologyTestDriver(topology, p, NOW);
        drivers.add(d);
        return d;
    }

    static String envelope(String tenant, String id, int secondsBefore, String user, String ip, String outcome) {
        Map<String, Object> m = new HashMap<>();
        m.put("id", id);
        m.put("ts", NOW.minusSeconds(secondsBefore).toString());
        m.put("user", user);
        m.put("ip", ip);
        m.put("action", "login");
        m.put("outcome", outcome);
        return DetectionTopology.write(RawEnvelope.http(tenant, NOW, m));
    }

    void bruteForce(TestInputTopic<String, String> in, String tenant) {
        for (int i = 0; i < 5; i++) {
            in.pipeInput(tenant + ":f" + i, envelope(tenant, "f" + i, 300 - i * 10, "asha@example.test", FRANKFURT_HOSTING, "failure"));
        }
        in.pipeInput(tenant + ":s", envelope(tenant, "s", 200, "asha@example.test", FRANKFURT_HOSTING, "success"));
    }

    @Test
    void fiveFailuresThenSuccessFromANewNetworkRaisesOneSignal() throws Exception {
        bruteForce(raw, "acme");

        assertThat(normalized.readValuesToList()).hasSize(6);
        var out = alerts.readKeyValuesToList();
        assertThat(out).hasSize(1);
        assertThat(out.getFirst().key).isEqualTo("acme|asha@example.test");
        Signal s = Json.MAPPER.readValue(out.getFirst().value, Signal.class);
        assertThat(s.ruleId()).isEqualTo("bf");
        assertThat(s.triggerEventId()).isEqualTo("s");
        assertThat(s.eventIds()).contains("f0", "f4", "s");
        assertThat(s.ingestedAt()).isEqualTo(NOW);
    }

    @Test
    void anotherTenantsEventsNeverMeetThisTenantsRules() {
        bruteForce(raw, "globex");
        assertThat(normalized.readValuesToList()).hasSize(6);
        assertThat(alerts.isEmpty()).isTrue();
    }

    @Test
    void entityStateIsKeyedPerTenant() {
        for (int i = 0; i < 3; i++) {
            raw.pipeInput("acme:f" + i, envelope("acme", "f" + i, 300 - i, "asha@example.test", FRANKFURT_HOSTING, "failure"));
        }
        for (int i = 3; i < 5; i++) {
            raw.pipeInput("globex:f" + i, envelope("globex", "f" + i, 300 - i, "asha@example.test", FRANKFURT_HOSTING, "failure"));
        }
        raw.pipeInput("acme:s", envelope("acme", "s", 200, "asha@example.test", FRANKFURT_HOSTING, "success"));
        assertThat(alerts.isEmpty()).as("3 acme failures + 2 globex failures are not 5 for one entity").isTrue();
    }

    @Test
    void unparseableAndInvalidRecordsGoToTheDeadLetterTopicWithAReason() throws Exception {
        raw.pipeInput("x", "{not json");
        raw.pipeInput("acme:bad", envelope("acme", "bad", 10, "asha@example.test", FRANKFURT_HOSTING, "maybe"));

        assertThat(normalized.isEmpty()).isTrue();
        var dead = dlq.readValuesToList();
        assertThat(dead).hasSize(2);
        JsonNode first = Json.MAPPER.readTree(dead.get(0));
        JsonNode second = Json.MAPPER.readTree(dead.get(1));
        assertThat(first.get("reason").asText()).isEqualTo("not a raw envelope");
        assertThat(second.get("tenant").asText()).isEqualTo("acme");
        assertThat(second.get("reason").asText()).isNotBlank();
    }

    @Test
    void replayingTheSameEventsGivesTheSameSignalIds() throws Exception {
        bruteForce(raw, "acme");
        String first = Json.MAPPER.readValue(alerts.readValue(), Signal.class).id();

        var other = newDriver();
        var in = other.createInputTopic(Topics.RAW, new StringSerializer(), new StringSerializer());
        var out = other.createOutputTopic(Topics.ALERTS, new StringDeserializer(), new StringDeserializer());
        bruteForce(in, "acme");
        assertThat(Json.MAPPER.readValue(out.readValue(), Signal.class).id()).isEqualTo(first);
    }

    @Test
    void stateSurvivesBetweenRecordsAndIdleEntitiesAreEvicted() {
        for (int i = 0; i < 5; i++) {
            raw.pipeInput("acme:f" + i, envelope("acme", "f" + i, 300 - i, "asha@example.test", FRANKFURT_HOSTING, "failure"));
        }
        var store = driver.<String, byte[]>getKeyValueStore(DetectionTopology.USER_STORE);
        assertThat(store.get("acme|asha@example.test")).isNotNull();

        driver.advanceWallClockTime(Duration.ofDays(6));
        assertThat(store.get("acme|asha@example.test")).as("not idle long enough").isNotNull();

        driver.advanceWallClockTime(Duration.ofDays(1).plusHours(2));
        assertThat(store.get("acme|asha@example.test")).isNull();
        assertThat(driver.<String, byte[]>getKeyValueStore(DetectionTopology.IP_STORE).get("acme|" + FRANKFURT_HOSTING)).isNull();
    }

    @Test
    void entityStateRoundTripsThroughJson() throws Exception {
        for (int i = 0; i < 5; i++) {
            raw.pipeInput("acme:f" + i, envelope("acme", "f" + i, 300 - i, "asha@example.test", FRANKFURT_HOSTING, "failure"));
        }
        byte[] stored = driver.<String, byte[]>getKeyValueStore(DetectionTopology.USER_STORE).get("acme|asha@example.test");
        JsonNode state = Json.MAPPER.readTree(stored);
        assertThat(state.at("/rules/bf@1/runs")).isNotEmpty();
    }

    @Test
    void userAndIpRulesSideBySideBothFire() throws Exception {
        var c = new RuleCompiler();
        var set = new RuleSet(1, List.of(
                new ActiveRule("spray", 1, "Spray", Severity.HIGH, c.compile("threshold login.failure >= 3 by ip within 5m")),
                new ActiveRule("takeover", 1, "Takeover", Severity.HIGH, c.compile(
                        "sequence login.failure{5,} then login.success where asn is new by user within 10m")),
                new ActiveRule("travel", 1, "Travel", Severity.HIGH, c.compile("travel login.success by user faster than 900 kmh"))),
                Map.of());
        var d = newDriver(set);
        var in = d.createInputTopic(Topics.RAW, new StringSerializer(), new StringSerializer());
        var out = d.createOutputTopic(Topics.ALERTS, new StringDeserializer(), new StringDeserializer());
        for (int i = 0; i < 6; i++) {
            in.pipeInput("acme:z" + i, envelope("acme", "z" + i, 300 - i, "zed@example.test", "203.0.113.201", "failure"));
        }
        in.pipeInput("acme:zs", envelope("acme", "zs", 280, "zed@example.test", "203.0.113.201", "success"));
        in.pipeInput("acme:r1", envelope("acme", "r1", 900, "ravi@example.test", "198.51.100.20", "success"));
        in.pipeInput("acme:r2", envelope("acme", "r2", 300, "ravi@example.test", "203.0.113.50", "success"));
        var rules = out.readValuesToList().stream().map(v -> {
            try {
                return Json.MAPPER.readValue(v, Signal.class).ruleId();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }).toList();
        assertThat(rules).contains("spray", "takeover", "travel");
    }
}
