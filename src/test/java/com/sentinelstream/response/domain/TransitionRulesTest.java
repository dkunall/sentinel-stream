package com.sentinelstream.response.domain;

import com.sentinelstream.detection.domain.engine.Confidence;
import com.sentinelstream.detection.domain.engine.Signal;
import com.sentinelstream.detection.domain.rule.EntityKind;
import com.sentinelstream.detection.domain.rule.Severity;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.time.Instant;
import java.util.List;

import static com.sentinelstream.response.domain.IncidentState.*;
import static org.assertj.core.api.Assertions.assertThat;

class TransitionRulesTest {

    @Test
    void theHappyPathIsAllowed() {
        assertThat(TransitionRules.refuse(NEW, TRIAGED, null, false)).isEmpty();
        assertThat(TransitionRules.refuse(TRIAGED, INVESTIGATING, null, false)).isEmpty();
        assertThat(TransitionRules.refuse(INVESTIGATING, CONTAINED, null, true)).isEmpty();
        assertThat(TransitionRules.refuse(CONTAINED, RESOLVED, "fixed", false)).isEmpty();
        assertThat(TransitionRules.refuse(RESOLVED, INVESTIGATING, "it came back", false)).isEmpty();
    }

    @Test
    void containmentNeedsASucceededPlaybook() {
        assertThat(TransitionRules.refuse(INVESTIGATING, CONTAINED, null, false)).get().asString().contains("playbook");
    }

    @Test
    void closingAndReopeningNeedANote() {
        assertThat(TransitionRules.refuse(TRIAGED, FALSE_POSITIVE, " ", false)).isPresent();
        assertThat(TransitionRules.refuse(CONTAINED, RESOLVED, null, false)).isPresent();
        assertThat(TransitionRules.refuse(RESOLVED, INVESTIGATING, null, false)).isPresent();
    }

    @ParameterizedTest
    @EnumSource(IncidentState.class)
    void nothingLeavesFalsePositiveAndNothingSkipsTriage(IncidentState to) {
        assertThat(FALSE_POSITIVE.canMoveTo(to)).isFalse();
        assertThat(NEW.canMoveTo(to)).isEqualTo(to == TRIAGED);
        assertThat(IncidentState.valueOf(to.name()).canMoveTo(to)).isFalse();
    }

    @Test
    void fingerprintBucketsByRuleEntityAndUtcHour() {
        Signal a = signal("r1", "alice@example.test", "2026-10-30T10:05:00Z");
        Signal sameHour = signal("r1", "alice@example.test", "2026-10-30T10:59:59Z");
        Signal nextHour = signal("r1", "alice@example.test", "2026-10-30T11:00:00Z");
        Signal otherRule = signal("r2", "alice@example.test", "2026-10-30T10:05:00Z");
        assertThat(AlertFingerprint.of(a)).isEqualTo(AlertFingerprint.of(sameHour));
        assertThat(AlertFingerprint.of(a)).isNotEqualTo(AlertFingerprint.of(nextHour)).isNotEqualTo(AlertFingerprint.of(otherRule));
        assertThat(AlertFingerprint.alertId(AlertFingerprint.of(a))).isEqualTo(AlertFingerprint.alertId(AlertFingerprint.of(sameHour)));
    }

    private static Signal signal(String rule, String user, String ts) {
        return new Signal("s-" + ts, "acme", rule, 1, "Brute force", Severity.HIGH, Confidence.HIGH, EntityKind.USER,
                user, Instant.parse(ts), "e1", List.of("e1"), Instant.parse(ts), "x");
    }
}
