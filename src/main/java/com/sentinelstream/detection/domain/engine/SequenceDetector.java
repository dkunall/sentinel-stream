package com.sentinelstream.detection.domain.engine;

import com.sentinelstream.detection.domain.rule.RuleSpec;
import com.sentinelstream.detection.domain.rule.Step;
import com.sentinelstream.event.EnrichedEvent;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Runs a compiled sequence rule as an NFA over one entity's events. Each partial match ({@link Run})
 * is a state (step, count); non-matching events are skipped, a run advances as soon as the next step
 * matches, and a run older than the window is dropped when the next event arrives (event time).
 * Two runs in the same state are the same NFA state, so only the youngest (latest expiry) is kept:
 * that bounds the run list by the sum of the step counts rather than by the number of events.
 */
public final class SequenceDetector implements Detector {

    static final int MAX_EVIDENCE = 20;

    @Override
    public Optional<Detection> evaluate(ActiveRule rule, EnrichedEvent e, RuleState st, Profile profile, RuleSet set) {
        RuleSpec.Sequence spec = (RuleSpec.Sequence) rule.compiled().spec();
        List<Step> steps = spec.steps();
        long now = e.ts().toEpochMilli();
        long window = spec.within().toMillis();
        st.runs.removeIf(r -> now - r.startMs > window);

        Run done = null;
        for (Run r : st.runs) {
            Step cur = steps.get(r.step);
            boolean last = r.step == steps.size() - 1;
            if (!last && r.count >= cur.min() && Conditions.matches(steps.get(r.step + 1), e, r, profile)) {
                r.step++;
                r.count = 1;
                record(r, e);
            } else if (Conditions.matches(cur, e, r, profile) && (cur.max() == Step.UNBOUNDED || r.count < cur.max())) {
                r.count = Math.min(r.count + 1, cur.countCap());
                record(r, e);
            } else {
                continue;
            }
            if (r.step == steps.size() - 1 && r.count >= steps.getLast().min() && (done == null || r.startMs < done.startMs)) {
                done = r;
            }
        }
        if (Conditions.matches(steps.getFirst(), e, null, profile)) {
            Run r = new Run();
            r.startMs = now;
            r.count = 1;
            Conditions.capture(r.first, e);
            record(r, e);
            st.runs.add(r);
            if (steps.size() == 1 && steps.getFirst().min() <= 1 && done == null) {
                done = r;
            }
        }
        if (done != null) {
            Detection d = new Detection(List.copyOf(done.eventIds), Confidence.HIGH,
                    "sequence matched over " + done.eventIds.size() + " events in " + (now - done.startMs) / 1000 + "s");
            st.runs.clear();
            return Optional.of(d);
        }
        collapse(st);
        return Optional.empty();
    }

    private static void record(Run r, EnrichedEvent e) {
        Conditions.capture(r.last, e);
        r.eventIds.add(e.id());
        if (r.eventIds.size() > MAX_EVIDENCE) {
            r.eventIds.removeFirst();
        }
    }

    /** Keep one run per (step, count): the one that started last, so it expires last. */
    private static void collapse(RuleState st) {
        Map<Long, Run> best = new HashMap<>();
        for (Run r : st.runs) {
            long key = ((long) r.step << 32) | r.count;
            best.merge(key, r, (a, b) -> a.startMs >= b.startMs ? a : b);
        }
        if (best.size() != st.runs.size()) {
            List<Run> kept = new ArrayList<>(best.values());
            kept.sort((a, b) -> Long.compare(a.startMs, b.startMs));
            st.runs = kept;
        }
    }
}
