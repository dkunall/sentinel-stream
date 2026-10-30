package com.sentinelstream.it;

import com.sentinelstream.detection.domain.rule.EntityKind;
import com.sentinelstream.response.application.Correlator;
import com.sentinelstream.support.Api;
import com.sentinelstream.support.ItBase;
import com.sentinelstream.support.Race;
import com.sentinelstream.support.Signals;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

class PlaybookIT extends ItBase {

    @Autowired
    Correlator correlator;
    @Autowired
    JdbcTemplate jdbc;

    UUID investigatingIncident(String user) {
        correlator.onSignal(Signals.high("acme", "it-playbook", EntityKind.USER, user, Instant.now()));
        UUID id = jdbc.queryForObject("select id from incident where tenant_id = 'acme' and entity_key = ?", UUID.class, user);
        acme.post("/v1/incidents/" + id + "/transition", Map.of("to", "TRIAGED")).expect(200);
        acme.post("/v1/incidents/" + id + "/transition", Map.of("to", "INVESTIGATING")).expect(200);
        return id;
    }

    String playbook(String id) {
        acmeAdmin.put("/v1/playbooks/" + id, Map.of("name", "Lock and notify", "needsApproval", true, "steps", List.of(
                Map.of("kind", "LOCK_ACCOUNT", "params", Map.of()),
                Map.of("kind", "NOTIFY_WEBHOOK", "params", Map.of("url", "http://localhost:" + port + "/demo/webhook-sink"))))).expect(200);
        return id;
    }

    @Test
    void fourEyesApprovalThenTheRunLocksTheAccountNotifiesOnceAndContainsTheIncident() {
        String user = unique("pb") + "@example.test";
        UUID incident = investigatingIncident(user);
        String pb = playbook(unique("lock-notify"));
        String runPath = "/v1/incidents/" + incident + "/playbooks/" + pb + ":run";

        String own = acmeAdmin.post(runPath, null).expect(201).text("id");
        acmeAdmin.post("/v1/playbook-runs/" + own + ":approve", null).expect(403);
        acme.post(runPath, null).expect(409);
        acme2.post("/v1/playbook-runs/" + own + ":approve", null).expect(403);
        acmeAdmin2.post("/v1/playbook-runs/" + own + ":reject", null).expect(200);

        String run = acme.post(runPath, null).expect(201).text("id");
        List<Integer> statuses = Race.run(2, i -> (i == 0 ? acmeAdmin : acmeAdmin2)
                .post("/v1/playbook-runs/" + run + ":approve", null).status());
        assertThat(statuses).containsExactlyInAnyOrder(200, 409);

        await().atMost(Duration.ofSeconds(30)).untilAsserted(() ->
                assertThat(acme.get("/v1/playbook-runs/" + run).expect(200).body().path("run").path("status").asText())
                        .isEqualTo("SUCCEEDED"));
        assertThat(acme.get("/v1/incidents/" + incident).expect(200).body().path("incident").path("state").asText())
                .isEqualTo("CONTAINED");
        assertThat(jdbc.queryForObject("select locked from demo_account where tenant_id = 'acme' and user_name = ?", Boolean.class, user))
                .isTrue();
        await().atMost(Duration.ofSeconds(30)).untilAsserted(() -> assertThat(deliveries(run + ":1")).isEqualTo(1));
        assertThat(globex.get("/v1/playbook-runs/" + run).status()).isEqualTo(404);
    }

    @Test
    void aRunResumedAfterACrashSkipsStepsThatAlreadyFinished() {
        String user = unique("resume") + "@example.test";
        UUID incident = investigatingIncident(user);
        String pb = playbook(unique("resume"));
        UUID run = UUID.randomUUID();
        // as if a worker had finished step 0 and died two hours ago
        jdbc.update("""
                insert into playbook_run (id, tenant_id, playbook_id, incident_id, status, requested_by, approved_by, created_at, started_at)
                values (?, 'acme', ?, ?, 'RUNNING', 'analyst@acme', 'admin@acme', now() - interval '2 hours', now() - interval '2 hours')
                """, run, pb, incident);
        jdbc.update("insert into playbook_step_result (run_id, idx, kind, status, detail) values (?, 0, 'LOCK_ACCOUNT', 'SKIPPED', 'pre-recorded')", run);

        await().atMost(Duration.ofSeconds(30)).untilAsserted(() ->
                assertThat(jdbc.queryForObject("select status from playbook_run where id = ?", String.class, run)).isEqualTo("SUCCEEDED"));
        assertThat(jdbc.queryForObject("select count(*) from demo_account where tenant_id = 'acme' and user_name = ?", Integer.class, user))
                .isZero();
        await().atMost(Duration.ofSeconds(30)).untilAsserted(() -> assertThat(deliveries(run + ":1")).isEqualTo(1));
    }

    @Test
    void playbooksRefuseWebhooksToHostsOutsideTheAllowList() {
        acmeAdmin.put("/v1/playbooks/" + unique("bad"), Map.of("name", "exfil", "needsApproval", false, "steps", List.of(
                Map.of("kind", "NOTIFY_WEBHOOK", "params", Map.of("url", "https://example.com/hook"))))).expect(400);
        acme.put("/v1/playbooks/" + unique("nope"), Map.of("name", "x", "needsApproval", false, "steps", List.of(
                Map.of("kind", "LOCK_ACCOUNT", "params", Map.of())))).expect(403);
    }

    @Test
    void theDemoSinkRejectsUnsignedDeliveries() {
        Api.Response r = anon.post("/demo/webhook-sink", Map.of("deliveryKey", "forged", "tenant", "acme"),
                Map.of("X-Sentinel-Signature", "sha256=" + "0".repeat(64)));
        assertThat(r.status()).isEqualTo(401);
        assertThat(deliveries("forged")).isZero();
    }

    int deliveries(String key) {
        return jdbc.queryForObject("select count(*) from webhook_delivery where body->>'deliveryKey' = ?", Integer.class, key);
    }
}
