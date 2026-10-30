package com.sentinelstream.detection.domain.engine;

import com.sentinelstream.detection.domain.rule.EntityKind;
import com.sentinelstream.event.EnrichedEvent;
import com.sentinelstream.event.Outcome;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Combinators;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.constraints.IntRange;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The NFA against a brute-force oracle for "F{n,} then S within W": a success at time t fires iff at
 * least n failures happened in [t - W, t] since the last time the rule fired. Each fire resets the
 * oracle exactly as the detector clears its runs.
 */
class SequenceOraclePropertyTest {

    record Ev(long t, boolean success) {
    }

    @Provide
    Arbitrary<List<Ev>> streams() {
        Arbitrary<Ev> one = Combinators.combine(Arbitraries.longs().between(0, 40), Arbitraries.integers().between(0, 99))
                .as((gap, p) -> new Ev(gap, p < 25));
        return one.list().ofMinSize(1).ofMaxSize(120).map(gaps -> {
            List<Ev> out = new ArrayList<>();
            long t = 0;
            for (Ev g : gaps) {
                t += g.t();
                out.add(new Ev(t, g.success()));
            }
            return out;
        });
    }

    @Property(tries = 400)
    void nfaAgreesWithBruteForce(@ForAll("streams") List<Ev> stream,
                                 @ForAll @IntRange(min = 1, max = 6) int n,
                                 @ForAll @IntRange(min = 10, max = 200) int windowSeconds) {
        ActiveRule rule = Fixtures.rule("p", "sequence login.failure{" + n + ",} then login.success by user within " + windowSeconds + "s");
        RuleSet set = Fixtures.set(rule);
        DetectionEngine engine = new DetectionEngine();
        EntityState state = new EntityState();

        List<Long> nfa = new ArrayList<>();
        List<Long> oracle = new ArrayList<>();
        List<Long> failures = new ArrayList<>();
        for (Ev e : stream) {
            EnrichedEvent ev = Fixtures.ev(e.t(), "u", Fixtures.BENGALURU, e.success() ? Outcome.SUCCESS : Outcome.FAILURE);
            if (!engine.process(set, EntityKind.USER, state, ev).isEmpty()) {
                nfa.add(e.t());
            }
            if (!e.success()) {
                failures.add(e.t());
                continue;
            }
            long inWindow = failures.stream().filter(f -> e.t() - f <= windowSeconds).count();
            if (inWindow >= n) {
                oracle.add(e.t());
                failures.clear();
            }
        }
        assertThat(nfa).isEqualTo(oracle);
    }
}
