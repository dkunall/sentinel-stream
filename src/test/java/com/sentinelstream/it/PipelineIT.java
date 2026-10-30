package com.sentinelstream.it;

import com.fasterxml.jackson.databind.JsonNode;
import com.sentinelstream.detection.application.PolledRuleSets;
import com.sentinelstream.support.Api;
import com.sentinelstream.support.ItBase;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.StreamSupport;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

/** HTTP ingest through Kafka Streams detection to correlated alerts and incidents, end to end. */
class PipelineIT extends ItBase {

    @Autowired
    PolledRuleSets ruleSets;
    @Autowired
    JdbcTemplate jdbc;

    static String randomIp() {
        var r = ThreadLocalRandom.current();
        return "203.0.113." + r.nextInt(1, 255);
    }

    static Map<String, Object> event(String user, String ip, String action, String outcome, Instant ts) {
        return Map.of("id", UUID.randomUUID().toString(), "ts", ts.toString(), "user", user, "ip", ip, "action", action,
                "outcome", outcome, "user_agent", "SyntheticAgent/1.0");
    }

    Api collector(Api admin) {
        var issued = admin.post("/v1/collectors", Map.of("name", unique("it"))).expect(201);
        return Api.at(port).with("X-Api-Key", issued.text("apiKey"));
    }

    void rule(Api admin, String id, String dsl, String severity) {
        admin.post("/v1/rules", Map.of("id", id, "name", id, "dsl", dsl, "severity", severity));
        ruleSets.refresh();
    }

    /** Other tests' rules stay enabled in the shared tenant, so match on the rule as well as the entity. */
    List<JsonNode> alertsFor(Api api, String entity, String ruleId) {
        var body = api.get("/v1/alerts?limit=200").expect(200).body();
        return StreamSupport.stream(body.spliterator(), false).filter(a -> a.path("entity_key").asText().equals(entity))
                .filter(a -> a.path("rule_id").asText().equals(ruleId)).toList();
    }

    @Test
    void failedLoginBurstBecomesOneAlertAndOneIncidentAndResendingChangesNothing() {
        String user = unique("u") + "@example.test";
        rule(acmeAdmin, "it-burst-by-user", "threshold login.failure >= 5 by user within 5m", "HIGH");
        Api collector = collector(acmeAdmin);
        Instant t = Instant.now().minusSeconds(60);
        List<Map<String, Object>> batch = new ArrayList<>();
        for (int i = 0; i < 6; i++) {
            batch.add(event(user, randomIp(), "login", "failure", t.plusSeconds(i)));
        }
        var first = collector.post("/v1/events:batch", Map.of("events", batch)).expect(202);
        assertThat(first.body().path("accepted").asInt()).isEqualTo(6);

        await().atMost(Duration.ofSeconds(90)).untilAsserted(() -> assertThat(alertsFor(acme, user, "it-burst-by-user")).hasSize(1));
        JsonNode alert = alertsFor(acme, user, "it-burst-by-user").getFirst();
        assertThat(alert.path("rule_id").asText()).isEqualTo("it-burst-by-user");
        assertThat(alert.path("incident_id").isNull()).isFalse();

        var again = collector.post("/v1/events:batch", Map.of("events", batch)).expect(202);
        assertThat(again.body().path("accepted").asInt()).isZero();
        assertThat(again.body().path("duplicates").asInt()).isEqualTo(6);

        await().atMost(Duration.ofSeconds(60)).untilAsserted(() ->
                assertThat(jdbc.queryForObject("select count(*) from event where tenant_id = 'acme' and user_name = ?", Integer.class, user))
                        .isEqualTo(6));
        assertThat(alertsFor(acme, user, "it-burst-by-user")).hasSize(1);
        assertThat(alertsFor(acme, user, "it-burst-by-user").getFirst().path("count").asInt()).isEqualTo(alert.path("count").asInt());
        // every HIGH alert for one user lands in one incident, whichever rules fired
        assertThat(jdbc.queryForObject("select count(*) from incident where tenant_id = 'acme' and entity_key = ?", Integer.class, user))
                .isEqualTo(1);
    }

    /**
     * Regression: with the raw topic keyed by event id, one user's batch was spread over every raw
     * partition and reached the user detector out of order, so the success often came before the
     * failures and the sequence never matched. The raw key is now the user.
     */
    @Test
    void oneUsersBatchReachesTheSequenceDetectorInOrder() {
        rule(acmeAdmin, "it-seq-in-order", "sequence login.failure{8,} then login.success by user within 10m", "HIGH");
        Api collector = collector(acmeAdmin);
        List<String> users = new ArrayList<>();
        List<Map<String, Object>> batch = new ArrayList<>();
        Instant t = Instant.now().minusSeconds(120);
        for (int u = 0; u < 3; u++) {
            String user = unique("seq") + "@example.test";
            users.add(user);
            for (int i = 0; i < 8; i++) {
                batch.add(event(user, "203.0.113.20" + u, "login", "failure", t.plusSeconds(i)));
            }
            batch.add(event(user, "203.0.113.20" + u, "login", "success", t.plusSeconds(9)));
        }
        collector.post("/v1/events:batch", Map.of("events", batch)).expect(202);

        await().atMost(Duration.ofSeconds(90)).untilAsserted(() -> {
            for (String user : users) {
                assertThat(alertsFor(acme, user, "it-seq-in-order")).as(user).hasSize(1);
            }
        });
    }

    @Test
    void searchMasksPiiAndOnlyThePiiScopeMayAskForCleartext() {
        String user = unique("m") + "@example.test";
        Api collector = collector(acmeAdmin);
        collector.post("/v1/events:batch", Map.of("events", List.of(event(user, "198.51.100.23", "login", "success",
                Instant.now().minusSeconds(5))))).expect(202);
        await().atMost(Duration.ofSeconds(60)).untilAsserted(() ->
                assertThat(acme.get("/v1/events/search?user=" + user).expect(200).body().path("events")).hasSize(1));

        acme.get("/v1/events/search?user=" + user + "&unmasked=true").expect(403);
        var masked = acme.get("/v1/events/search?user=" + user).expect(200).body();
        assertThat(masked.path("masked").asBoolean()).isTrue();
        assertThat(masked.path("events").get(0).path("user").asText()).isNotEqualTo(user);
        assertThat(masked.path("events").get(0).path("ip").asText()).isNotEqualTo("198.51.100.23");

        Api pii = Api.at(port).as(com.sentinelstream.support.TestJwt.token("lead@acme", "sentinel.analyst", "sentinel.pii"));
        var clear = pii.get("/v1/events/search?user=" + user + "&unmasked=true").expect(200).body();
        assertThat(clear.path("masked").asBoolean()).isFalse();
        assertThat(clear.path("events").get(0).path("user").asText()).isEqualTo(user);
    }

    @Test
    void tenantsSeeOnlyTheirOwnData() {
        String user = unique("iso") + "@example.test";
        rule(acmeAdmin, "it-iso-by-user", "threshold login.failure >= 3 by user within 5m", "HIGH");
        Api collector = collector(acmeAdmin);
        Instant t = Instant.now().minusSeconds(30);
        collector.post("/v1/events:batch", Map.of("events", List.of(event(user, randomIp(), "login", "failure", t),
                event(user, randomIp(), "login", "failure", t.plusSeconds(1)),
                event(user, randomIp(), "login", "failure", t.plusSeconds(2))))).expect(202);
        await().atMost(Duration.ofSeconds(90)).untilAsserted(() -> assertThat(alertsFor(acme, user, "it-iso-by-user")).hasSize(1));
        String incident = alertsFor(acme, user, "it-iso-by-user").getFirst().path("incident_id").asText();

        assertThat(alertsFor(globex, user, "it-iso-by-user")).isEmpty();
        assertThat(globex.get("/v1/events/search?user=" + user).expect(200).body().path("events")).isEmpty();
        globex.get("/v1/incidents/" + incident).expect(404);
        globex.post("/v1/incidents/" + incident + "/transition", Map.of("to", "TRIAGED")).expect(404);
        assertThat(StreamSupport.stream(globex.get("/v1/rules").expect(200).body().spliterator(), false)
                .map(r -> r.path("id").asText())).doesNotContain("it-iso-by-user");
    }

    @Test
    void authIsEnforcedOnEveryDoor() {
        anon.get("/v1/alerts").expect(401);
        Api.at(port).with("X-Api-Key", "sk_not_a_real_key").post("/v1/events:batch", Map.of("events", List.of())).expect(401);
        acme.post("/v1/rules", Map.of("id", "nope", "name", "n", "dsl", "threshold login.failure >= 1 by ip within 1m",
                "severity", "LOW")).expect(403);
        acme.post("/v1/collectors", Map.of("name", "nope")).expect(403);
        Api.at(port).as(com.sentinelstream.support.TestJwt.token("nobody", "sentinel.analyst")).get("/v1/alerts").expect(403);
        assertThat(anon.get("/actuator/health/readiness").status()).isEqualTo(200);
    }
}
