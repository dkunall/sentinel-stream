package com.sentinelstream.it;

import com.sentinelstream.detection.domain.engine.Signal;
import com.sentinelstream.detection.domain.rule.EntityKind;
import com.sentinelstream.response.application.Correlator;
import com.sentinelstream.support.ItBase;
import com.sentinelstream.support.Race;
import com.sentinelstream.support.Signals;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.Instant;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** Correlation is where at-least-once delivery and parallel consumers meet; these races must not double count. */
class CorrelationIT extends ItBase {

    @Autowired
    Correlator correlator;
    @Autowired
    JdbcTemplate jdbc;

    @Test
    void aRedeliveredSignalCountsOnceEvenWhenTheCopiesArriveTogether() {
        String user = unique("redeliver") + "@example.test";
        Signal s = Signals.high("acme", "it-redeliver", EntityKind.USER, user, Instant.now());

        List<Correlator.Outcome> outcomes = Race.run(8, i -> correlator.onSignal(s));

        assertThat(Collections.frequency(outcomes, Correlator.Outcome.ALERT_CREATED)).isEqualTo(1);
        assertThat(Collections.frequency(outcomes, Correlator.Outcome.DUPLICATE)).isEqualTo(7);
        assertThat(jdbc.queryForObject("select count from alert where tenant_id = 'acme' and entity_key = ?", Integer.class, user))
                .isEqualTo(1);
        assertThat(correlator.onSignal(s)).isEqualTo(Correlator.Outcome.DUPLICATE);
    }

    @Test
    void concurrentAlertsForOneEntityOpenExactlyOneIncident() {
        String user = unique("burst") + "@example.test";
        Instant ts = Instant.now();

        Race.run(8, i -> correlator.onSignal(Signals.high("acme", "it-rule-" + i, EntityKind.USER, user, ts)));

        assertThat(jdbc.queryForObject("select count(*) from alert where tenant_id = 'acme' and entity_key = ?", Integer.class, user))
                .isEqualTo(8);
        assertThat(jdbc.queryForObject("select count(*) from incident where tenant_id = 'acme' and entity_key = ?", Integer.class, user))
                .isEqualTo(1);
        assertThat(jdbc.queryForObject("""
                select count(*) from incident_alert ia join incident i on i.id = ia.incident_id
                where i.tenant_id = 'acme' and i.entity_key = ?
                """, Integer.class, user)).isEqualTo(8);
    }

    @Test
    void theSameRuleWithinOneHourUpdatesTheAlertInsteadOfOpeningANewOne() {
        String ip = "192.0.2." + (1 + (int) (Math.random() * 250));
        String key = unique("ipkey");
        Instant ts = Instant.parse("2026-10-30T10:05:00Z");
        correlator.onSignal(Signals.high("acme", "it-hourly-" + key, EntityKind.IP, ip, ts));
        correlator.onSignal(Signals.high("acme", "it-hourly-" + key, EntityKind.IP, ip, ts.plusSeconds(600)));
        correlator.onSignal(Signals.high("acme", "it-hourly-" + key, EntityKind.IP, ip, ts.plusSeconds(3600)));

        assertThat(jdbc.queryForList("select count from alert where tenant_id = 'acme' and rule_id = ? order by first_seen",
                Integer.class, "it-hourly-" + key)).containsExactly(2, 1);
    }
}
