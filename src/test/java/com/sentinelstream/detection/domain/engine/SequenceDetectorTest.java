package com.sentinelstream.detection.domain.engine;

import com.sentinelstream.detection.domain.rule.EntityKind;
import com.sentinelstream.event.EnrichedEvent;
import com.sentinelstream.event.Outcome;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static com.sentinelstream.detection.domain.engine.Fixtures.*;
import static org.assertj.core.api.Assertions.assertThat;

class SequenceDetectorTest {

    static final ActiveRule BRUTE_THEN_NEW_ASN =
            rule("bf", "sequence login.failure{5,} then login.success where asn is new by user within 10m");

    final DetectionEngine engine = new DetectionEngine();

    List<Signal> feed(RuleSet set, EntityState st, EnrichedEvent... events) {
        List<Signal> out = new ArrayList<>();
        for (EnrichedEvent e : events) {
            out.addAll(engine.process(set, EntityKind.USER, st, e));
        }
        return out;
    }

    EnrichedEvent[] failures(String user, String ip, long from, int n) {
        EnrichedEvent[] es = new EnrichedEvent[n];
        for (int i = 0; i < n; i++) {
            es[i] = ev(from + i * 10L, user, ip, Outcome.FAILURE);
        }
        return es;
    }

    @Test
    void fivefailuresThenSuccessFromAnUnfamiliarAsnFires() {
        var st = new EntityState();
        var set = set(BRUTE_THEN_NEW_ASN);
        feed(set, st, ev(-3600, "asha", BENGALURU, Outcome.SUCCESS)); // asha's usual ASN
        assertThat(feed(set, st, failures("asha", FRANKFURT_HOSTING, 0, 6))).isEmpty();

        var signals = feed(set, st, ev(70, "asha", FRANKFURT_HOSTING, Outcome.SUCCESS));

        assertThat(signals).singleElement().satisfies(s -> {
            assertThat(s.ruleId()).isEqualTo("bf");
            assertThat(s.entityKey()).isEqualTo("asha");
            // evidence is the youngest run that satisfies the rule: the last 5 failures plus the success
            assertThat(s.eventIds()).hasSize(6);
            assertThat(s.confidence()).isEqualTo(Confidence.HIGH);
        });
        assertThat(st.rules.get("bf@1").runs).isEmpty();
    }

    @Test
    void successFromTheUsualAsnIsNotSuspicious() {
        var st = new EntityState();
        var set = set(BRUTE_THEN_NEW_ASN);
        feed(set, st, ev(-3600, "asha", BENGALURU, Outcome.SUCCESS));
        feed(set, st, failures("asha", FRANKFURT_HOSTING, 0, 8));
        assertThat(feed(set, st, ev(90, "asha", "198.51.100.9", Outcome.SUCCESS))).isEmpty();
    }

    @Test
    void fourFailuresAreNotEnough() {
        var st = new EntityState();
        var set = set(BRUTE_THEN_NEW_ASN);
        feed(set, st, failures("ravi", FRANKFURT_HOSTING, 0, 4));
        assertThat(feed(set, st, ev(50, "ravi", FRANKFURT_HOSTING, Outcome.SUCCESS))).isEmpty();
    }

    @Test
    void failuresOutsideTheWindowExpire() {
        var st = new EntityState();
        var set = set(BRUTE_THEN_NEW_ASN);
        feed(set, st, failures("ravi", FRANKFURT_HOSTING, 0, 5));
        assertThat(feed(set, st, ev(601, "ravi", FRANKFURT_HOSTING, Outcome.SUCCESS))).isEmpty();
        // the window is measured from the first failure of the run, so 5 failures at 0..40s and success at 599s fire
        var st2 = new EntityState();
        feed(set, st2, failures("ravi", FRANKFURT_HOSTING, 0, 5));
        assertThat(feed(set, st2, ev(599, "ravi", FRANKFURT_HOSTING, Outcome.SUCCESS))).hasSize(1);
    }

    @Test
    void runsStayBoundedUnderAFloodOfFailures() {
        var st = new EntityState();
        var set = set(BRUTE_THEN_NEW_ASN);
        feed(set, st, failures("bot", FRANKFURT_HOSTING, 0, 5000));
        // states are (step 0, count 1..5); one run per state survives
        assertThat(st.rules.get("bf@1").runs).hasSizeLessThanOrEqualTo(5);
    }

    @Test
    void sameAndChangedCompareWithTheRun() {
        var rule = rule("hop", "sequence login.success then login.success where ip changed and country same by user within 1h");
        var st = new EntityState();
        var set = set(rule);
        assertThat(feed(set, st, ev(0, "kim", BENGALURU, Outcome.SUCCESS), ev(10, "kim", BENGALURU, Outcome.SUCCESS))).isEmpty();
        assertThat(feed(set, st, ev(20, "kim", MUMBAI_MOBILE, Outcome.SUCCESS))).hasSize(1);
        assertThat(feed(set, st, ev(30, "kim", FRANKFURT_HOSTING, Outcome.SUCCESS))).isEmpty();
    }

    @Test
    void editingARuleDropsItsOldPartialMatches() {
        var st = new EntityState();
        feed(set(BRUTE_THEN_NEW_ASN), st, failures("asha", FRANKFURT_HOSTING, 0, 5));
        var v2 = new ActiveRule("bf", 2, "bf", BRUTE_THEN_NEW_ASN.severity(), BRUTE_THEN_NEW_ASN.compiled());
        assertThat(feed(set(v2), st, ev(60, "asha", FRANKFURT_HOSTING, Outcome.SUCCESS))).isEmpty();
        assertThat(st.rules).containsOnlyKeys("bf@2");
    }
}
