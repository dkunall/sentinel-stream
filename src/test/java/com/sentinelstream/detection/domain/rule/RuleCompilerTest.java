package com.sentinelstream.detection.domain.rule;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RuleCompilerTest {

    static CompiledRule compile(String dsl) {
        return new RuleCompiler().compile(dsl);
    }

    @Test
    void parsesTheBruteForceThenSuccessRule() {
        var r = compile("sequence login.failure{5,} then login.success where asn is new by user within 10m");
        var s = (RuleSpec.Sequence) r.spec();
        assertThat(s.steps()).hasSize(2);
        assertThat(s.steps().get(0).min()).isEqualTo(5);
        assertThat(s.steps().get(0).max()).isEqualTo(Step.UNBOUNDED);
        assertThat(s.steps().get(1).where()).containsExactly(new Condition.IsNew("asn"));
        assertThat(s.entity()).isEqualTo(EntityKind.USER);
        assertThat(s.within()).isEqualTo(Duration.ofMinutes(10));
        assertThat(r.kind()).isEqualTo(RuleKind.SEQUENCE);
        assertThat(r.hash()).hasSize(64);
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
            "threshold login.failure >= 20 by ip within 5m | THRESHOLD",
            "anomaly login.failure by user per 1h zscore > 3 after 24 | ANOMALY",
            "ioc user_agent in \"bad-agents\" | IOC",
            "travel login.success by user faster than 900 kmh | TRAVEL",
            "newdevice login.success by user after 3 | NEW_DEVICE",
            "sequence *.success where network in (vpn, hosting) then password_change.* where ip changed by user within 1h | SEQUENCE",
    })
    void everyRuleKindCompilesAndRoundTripsThroughItsCanonicalForm(String dsl, RuleKind kind) {
        var r = compile(dsl);
        assertThat(r.kind()).isEqualTo(kind);
        var again = compile(r.canonical());
        assertThat(again.canonical()).isEqualTo(r.canonical());
        assertThat(again.hash()).isEqualTo(r.hash());
    }

    @Test
    void whitespaceCaseAndCommentsDoNotChangeTheHash() {
        var a = compile("threshold login.failure >= 20 by ip within 5m");
        var b = compile("# noisy IPs\n  THRESHOLD   login.failure>=20\n BY ip WITHIN 300s ");
        assertThat(b.hash()).isEqualTo(a.hash());
        assertThat(compile("threshold login.failure >= 21 by ip within 5m").hash()).isNotEqualTo(a.hash());
    }

    @Test
    void exactAndRangedQuantifiers() {
        var s = (RuleSpec.Sequence) compile("sequence login.failure{3} then login.failure{2,4} then login.success by ip within 1m").spec();
        assertThat(s.steps().get(0)).extracting(Step::min, Step::max).containsExactly(3, 3);
        assertThat(s.steps().get(1)).extracting(Step::min, Step::max).containsExactly(2, 4);
        assertThat(s.steps().get(2)).extracting(Step::min, Step::max).containsExactly(1, 1);
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
            "detect login.failure | a rule starts with",
            "threshold login.failure >= 20 by ip within 2d | window longer than 1d",
            "threshold login.failure >= 20 by host within 5m | ",
            "sequence login.failure where ip same then login.success by user within 1m | nothing earlier to compare",
            "sequence login.success where user_agent is new by user within 1m | 'is new' is tracked for",
            "sequence login.success where colour = red by user within 1m | unknown field",
            "travel login.success by ip faster than 900 kmh | travel is tracked per user",
            "ioc ip in \"Bad List\" | ioc list name",
            "sequence login.maybe by user within 1m | outcome is success, failure or *",
            "threshold login.failure >= 1 by ip within 5m | expected 2..100000",
            "sequence login.failure{3,2} by user within 1m | expected 3..1000",
            "threshold login.failure >= 20 by ip within 5m extra | unexpected",
            "sequence login.failure \"open | unterminated",
    })
    void reportsWhatIsWrongAndWhere(String dsl, String message) {
        assertThatThrownBy(() -> compile(dsl))
                .isInstanceOf(RuleSyntaxException.class)
                .hasMessageContaining(message == null ? "" : message)
                .hasMessageContaining("at position");
    }

    @Test
    void positionPointsAtTheOffendingToken() {
        var ex = (RuleSyntaxException) org.assertj.core.api.Assertions.catchThrowable(
                () -> compile("threshold login.failure >= 20 by ip within soon"));
        assertThat(ex.position()).isEqualTo("threshold login.failure >= 20 by ip within ".length());
    }

    @ParameterizedTest
    @ValueSource(ints = {8, 9})
    void capsTheNumberOfSteps(int steps) {
        String dsl = "sequence " + String.join(" then ", java.util.Collections.nCopies(steps, "login.failure")) + " by user within 1h";
        if (steps <= 8) {
            assertThat(compile(dsl).spec()).isInstanceOf(RuleSpec.Sequence.class);
        } else {
            assertThatThrownBy(() -> compile(dsl)).hasMessageContaining("at most 8 steps");
        }
    }

    @Test
    void oneSharedCompilerParsesConcurrentRulesCorrectly() throws Exception {
        RuleCompiler shared = new RuleCompiler();
        int threads = 8;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            CountDownLatch start = new CountDownLatch(1);
            List<Future<List<String>>> results = new ArrayList<>();
            for (int t = 0; t < threads; t++) {
                int n = 10 + t;
                results.add(pool.submit(() -> {
                    start.await();
                    List<String> out = new ArrayList<>();
                    for (int k = 0; k < 2000; k++) {
                        out.add(shared.compile("threshold login.failure >= " + n + " by ip within 5m").canonical());
                    }
                    return out;
                }));
            }
            start.countDown();
            for (int t = 0; t < threads; t++) {
                assertThat(results.get(t).get()).containsOnly("threshold login.failure >= " + (10 + t) + " by ip within 5m");
            }
        } finally {
            pool.shutdownNow();
        }
    }
}
