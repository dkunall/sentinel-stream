package com.sentinelstream.detection.application;

import com.sentinelstream.detection.domain.rule.EntityKind;
import com.sentinelstream.detection.domain.rule.Severity;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class RuleSetBuilderTest {

    private static RuleStore.StoredRule rule(String tenant, String id, int v, String dsl, boolean enabled) {
        return new RuleStore.StoredRule(tenant, id, v, id, dsl, dsl, "h", Severity.HIGH, enabled, "t", Instant.EPOCH);
    }

    @Test
    void onlyEnabledLatestRulesAreLiveAndTenantsStaySeparate() {
        var sets = RuleSetBuilder.build(7, List.of(
                rule("acme", "brute", 2, "threshold login.failure >= 20 by ip within 5m", true),
                rule("acme", "off", 1, "threshold login.failure >= 5 by user within 5m", false),
                rule("globex", "seq", 1, "sequence login.failure{5,} then login.success by user within 10m", true)),
                List.of(new RuleStore.IocEntry("acme", "bad", "ip", "203.0.113.66"),
                        new RuleStore.IocEntry("acme", "bad", "user_agent", "evilbot")));
        assertThat(sets.get("acme").version()).isEqualTo(7);
        assertThat(sets.get("acme").rules()).extracting(r -> r.id() + "@" + r.version()).containsExactly("brute@2");
        assertThat(sets.get("acme").rulesFor(EntityKind.IP)).hasSize(1);
        assertThat(sets.get("acme").iocs().get("bad").match("ip", "203.0.113.66")).isPresent();
        assertThat(sets.get("acme").iocs().get("bad").match("user_agent", "Mozilla evilbot/1.0")).isPresent();
        assertThat(sets.get("globex").rules()).extracting(r -> r.id()).containsExactly("seq");
        assertThat(sets.get("globex").iocs()).isEmpty();
    }

    @Test
    void aRuleThatNoLongerCompilesIsSkippedNotFatal() {
        var sets = RuleSetBuilder.build(1, List.of(rule("acme", "broken", 1, "threshold nonsense", true),
                rule("acme", "ok", 1, "threshold login.failure >= 20 by ip within 5m", true)), List.of());
        assertThat(sets.get("acme").rules()).extracting(r -> r.id()).containsExactly("ok");
    }
}
