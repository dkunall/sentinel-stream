package com.sentinelstream.detection.domain.engine;

import com.sentinelstream.detection.domain.rule.EntityKind;
import com.sentinelstream.event.EnrichedEvent;
import com.sentinelstream.event.Outcome;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static com.sentinelstream.detection.domain.engine.Fixtures.*;
import static org.assertj.core.api.Assertions.assertThat;

class OtherDetectorsTest {

    final DetectionEngine engine = new DetectionEngine();

    List<Signal> feed(RuleSet set, EntityKind kind, EntityState st, List<EnrichedEvent> events) {
        List<Signal> out = new ArrayList<>();
        for (EnrichedEvent e : events) {
            out.addAll(engine.process(set, kind, st, e));
        }
        return out;
    }

    @Test
    void thresholdCountsInASlidingWindowAndRestartsAfterFiring() {
        var set = set(rule("spray", "threshold login.failure >= 20 by ip within 5m"));
        var st = new EntityState();
        List<EnrichedEvent> es = new ArrayList<>();
        for (int i = 0; i < 45; i++) {
            es.add(ev(i * 5L, "user" + i, FRANKFURT_HOSTING, Outcome.FAILURE));
        }
        var signals = feed(set, EntityKind.IP, st, es);
        assertThat(signals).hasSize(2);
        assertThat(signals.getFirst().entityKey()).isEqualTo(FRANKFURT_HOSTING);
        assertThat(signals.getFirst().triggerEventId()).isEqualTo(es.get(19).id());

        var slow = new EntityState();
        List<EnrichedEvent> trickle = new ArrayList<>();
        for (int i = 0; i < 60; i++) {
            trickle.add(ev(i * 20L, "u", DELHI_CORP, Outcome.FAILURE)); // 15 per 5 minutes
        }
        assertThat(feed(set, EntityKind.IP, slow, trickle)).isEmpty();
    }

    @Test
    void anomalyWaitsForABaselineThenFiresOncePerBucket() {
        var set = set(rule("spike", "anomaly login.failure by user per 1h zscore > 3 after 24"));
        var st = new EntityState();
        List<EnrichedEvent> history = new ArrayList<>();
        for (int h = 0; h < 30; h++) {
            history.add(ev(h * 3600L, "meera", BENGALURU, Outcome.FAILURE)); // one typo an hour
        }
        assertThat(feed(set, EntityKind.USER, st, history)).isEmpty();
        assertThat(st.rules.get("spike@1").baseline.n).isEqualTo(29);

        List<EnrichedEvent> burst = new ArrayList<>();
        for (int i = 0; i < 40; i++) {
            burst.add(ev(30 * 3600L + i * 30L, "meera", BENGALURU, Outcome.FAILURE));
        }
        var signals = feed(set, EntityKind.USER, st, burst);
        assertThat(signals).singleElement().satisfies(s -> assertThat(s.summary()).contains("against a typical 1.0"));
    }

    @Test
    void anomalyDoesNotFireBeforeMinObservations() {
        var set = set(rule("spike", "anomaly login.failure by user per 1h zscore > 3 after 24"));
        var st = new EntityState();
        List<EnrichedEvent> es = new ArrayList<>();
        for (int h = 0; h < 5; h++) {
            es.add(ev(h * 3600L, "new", BENGALURU, Outcome.FAILURE));
        }
        for (int i = 0; i < 50; i++) {
            es.add(ev(5 * 3600L + i, "new", BENGALURU, Outcome.FAILURE));
        }
        assertThat(feed(set, EntityKind.USER, st, es)).isEmpty();
    }

    @Test
    void quietHoursCountAsZerosInTheBaseline() {
        var set = set(rule("spike", "anomaly login.failure by user per 1h zscore > 3 after 24"));
        var st = new EntityState();
        feed(set, EntityKind.USER, st, List.of(ev(0, "q", BENGALURU, Outcome.FAILURE), ev(48 * 3600L, "q", BENGALURU, Outcome.FAILURE)));
        var w = st.rules.get("spike@1").baseline;
        assertThat(w.n).isEqualTo(48);
        assertThat(w.mean).isCloseTo(Math.log(2) / 48, org.assertj.core.data.Offset.offset(1e-9));
    }

    @Test
    void impossibleTravelIsHighConfidenceUnlessAVpnOrMobileNetworkIsInvolved() {
        var set = set(rule("travel", "travel login.success by user faster than 900 kmh"));
        var st = new EntityState();
        var signals = feed(set, EntityKind.USER, st, List.of(
                ev(0, "asha", BENGALURU, Outcome.SUCCESS),
                ev(600, "asha", FRANKFURT_HOSTING, Outcome.SUCCESS)));
        assertThat(signals).singleElement().satisfies(s -> {
            assertThat(s.confidence()).isEqualTo(Confidence.HIGH);
            assertThat(s.summary()).startsWith("Bengaluru -> Frankfurt");
        });

        var vpn = feed(set, EntityKind.USER, new EntityState(), List.of(
                ev(0, "ravi", BENGALURU, Outcome.SUCCESS),
                ev(600, "ravi", NEWYORK_VPN, Outcome.SUCCESS)));
        assertThat(vpn).singleElement().extracting(Signal::confidence).isEqualTo(Confidence.LOW);

        // Bengaluru -> Delhi is ~1,750 km; ten hours is a plausible flight
        var plausible = feed(set, EntityKind.USER, new EntityState(), List.of(
                ev(0, "kim", BENGALURU, Outcome.SUCCESS),
                ev(36_000, "kim", DELHI_CORP, Outcome.SUCCESS)));
        assertThat(plausible).isEmpty();
    }

    @Test
    void newDeviceNeedsHistoryAndLearnsOnlyFromSuccess() {
        var set = set(rule("nd", "newdevice login.success by user after 3"));
        var st = new EntityState();
        List<EnrichedEvent> es = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            es.add(ev(i * 60L, "lena", BENGALURU, "login", Outcome.SUCCESS, "laptop"));
        }
        assertThat(feed(set, EntityKind.USER, st, es)).isEmpty();
        // a failure from the attacker's device must not make it familiar
        feed(set, EntityKind.USER, st, List.of(ev(200, "lena", FRANKFURT_HOSTING, "login", Outcome.FAILURE, "kali-box")));
        assertThat(feed(set, EntityKind.USER, st, List.of(ev(260, "lena", FRANKFURT_HOSTING, "login", Outcome.SUCCESS, "kali-box"))))
                .hasSize(1);
        assertThat(feed(set, EntityKind.USER, st, List.of(ev(320, "lena", BENGALURU, "login", Outcome.SUCCESS, "laptop")))).isEmpty();
    }

    @Test
    void iocMatchesExactIpsAndUserAgentSubstrings() {
        var lists = Map.of("bad", new IocList("bad", List.of("203.0.113.66"), List.of("sqlmap", "Hydra")));
        var byIp = new RuleSet(1, List.of(rule("ioc-ip", "ioc ip in \"bad\"")), lists);
        var byUa = new RuleSet(1, List.of(rule("ioc-ua", "ioc user_agent in \"bad\" by user")), lists);
        var hitIp = ev(0, "x", "203.0.113.66", Outcome.FAILURE);
        assertThat(engine.process(byIp, EntityKind.IP, new EntityState(), hitIp)).hasSize(1);
        assertThat(engine.process(byIp, EntityKind.IP, new EntityState(), ev(0, "x", "203.0.113.67", Outcome.FAILURE))).isEmpty();

        var uaEvent = Fixtures.CHAIN.enrich(new com.sentinelstream.event.SecurityEvent("u1", "acme", T0, "x", BENGALURU, "login",
                Outcome.FAILURE, "Mozilla/5.0 (compatible; HYDRA-like test agent)", null, "http", T0));
        assertThat(engine.process(byUa, EntityKind.USER, new EntityState(), uaEvent))
                .singleElement().satisfies(s -> assertThat(s.summary()).contains("'hydra'"));
        // a rule whose list does not exist simply never matches
        var missing = new RuleSet(1, List.of(rule("ioc-x", "ioc ip in \"nope\"")), lists);
        assertThat(engine.process(missing, EntityKind.IP, new EntityState(), hitIp)).isEmpty();
    }

    @Test
    void signalIdsAreStableSoReplaysDeduplicate() {
        var set = set(rule("spray", "threshold login.failure >= 2 by ip within 5m"));
        var a = ev(0, "a", FRANKFURT_HOSTING, Outcome.FAILURE);
        var b = ev(1, "b", FRANKFURT_HOSTING, Outcome.FAILURE);
        var first = feed(set, EntityKind.IP, new EntityState(), List.of(a, b));
        var replay = feed(set, EntityKind.IP, new EntityState(), List.of(a, b));
        assertThat(first).hasSize(1);
        assertThat(replay.getFirst().id()).isEqualTo(first.getFirst().id());
    }

    @Test
    void rulesOnlySeeTheirEntityKind() {
        var set = set(rule("spray", "threshold login.failure >= 2 by ip within 5m"));
        var st = new EntityState();
        var out = feed(set, EntityKind.USER, st, List.of(ev(0, "a", FRANKFURT_HOSTING, Outcome.FAILURE),
                ev(1, "a", FRANKFURT_HOSTING, Outcome.FAILURE)));
        assertThat(out).isEmpty();
        assertThat(st.rules).isEmpty();
    }
}
