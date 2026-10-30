package com.sentinelstream.it;

import com.sentinelstream.support.ItBase;
import com.sentinelstream.support.Race;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class RulesIT extends ItBase {

    @Autowired
    JdbcTemplate jdbc;

    Map<String, Object> rule(String id, int n) {
        return Map.of("id", id, "name", id, "dsl", "threshold login.failure >= " + n + " by ip within 5m", "severity", "MEDIUM");
    }

    @Test
    void savingTheSameRuleTwiceIsANoOpAndConcurrentEditsNeverShareAVersion() {
        String id = unique("rule");
        assertThat(acmeAdmin.post("/v1/rules", rule(id, 10)).expect(201).body().path("version").asInt()).isEqualTo(1);
        acmeAdmin.post("/v1/rules", rule(id, 10)).expect(200);

        List<Integer> statuses = Race.run(6, i -> acmeAdmin.post("/v1/rules", rule(id, 20 + i)).status());
        int created = Collections.frequency(statuses, 201);
        assertThat(created).isGreaterThanOrEqualTo(1);
        assertThat(created + Collections.frequency(statuses, 409)).isEqualTo(6);
        List<Integer> versions = jdbc.queryForList("select version from rule where tenant_id = 'acme' and id = ? order by version",
                Integer.class, id);
        assertThat(versions).hasSize(1 + created).doesNotHaveDuplicates();
    }

    @Test
    void syntaxErrorsSayWhereAndBacktestRoutesThroughTheColonPath() {
        var bad = acmeAdmin.post("/v1/rules", Map.of("id", unique("bad"), "name", "b", "dsl", "threshold login.failure >= by ip",
                "severity", "LOW")).expect(400);
        assertThat(bad.text("code")).isEqualTo("rule-syntax");

        String id = unique("bt");
        acmeAdmin.post("/v1/rules", rule(id, 3)).expect(201);
        var bt = acme.post("/v1/rules/" + id + ":backtest", Map.of()).expect(200).body();
        assertThat(bt.path("ruleId").asText()).isEqualTo(id);
        assertThat(bt.has("eventsScanned")).isTrue();
        acme.post("/v1/rules/does-not-exist:backtest", Map.of()).expect(404);
    }

    @Test
    void iocListsAreAdminWritableAndValidated() {
        String list = unique("blk");
        acmeAdmin.post("/v1/iocs/" + list, Map.of("kind", "ip", "values", List.of("198.51.100.66"))).expect(200);
        acmeAdmin.post("/v1/iocs/" + list, Map.of("kind", "dns", "values", List.of("x"))).expect(400);
        acme.post("/v1/iocs/" + list, Map.of("kind", "ip", "values", List.of("198.51.100.67"))).expect(403);
    }
}
