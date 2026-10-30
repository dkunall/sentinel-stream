package com.sentinelstream.detection.domain.engine;

import com.sentinelstream.detection.domain.rule.RuleSpec;
import com.sentinelstream.event.EnrichedEvent;

import java.util.List;
import java.util.Optional;

/** Sliding-window count. Fires when the window holds {@code count} matches, then starts counting again. */
public final class ThresholdDetector implements Detector {

    @Override
    public Optional<Detection> evaluate(ActiveRule rule, EnrichedEvent e, RuleState st, Profile profile, RuleSet set) {
        RuleSpec.Threshold spec = (RuleSpec.Threshold) rule.compiled().spec();
        if (!Conditions.matches(spec.step(), e, null, profile)) {
            return Optional.empty();
        }
        long now = e.ts().toEpochMilli();
        long cutoff = now - spec.within().toMillis();
        while (!st.times.isEmpty() && st.times.getFirst() < cutoff) {
            st.times.removeFirst();
            st.ids.removeFirst();
        }
        st.times.add(now);
        st.ids.add(e.id());
        if (st.times.size() < spec.count()) {
            return Optional.empty();
        }
        List<String> evidence = List.copyOf(st.ids.subList(Math.max(0, st.ids.size() - SequenceDetector.MAX_EVIDENCE), st.ids.size()));
        int n = st.times.size();
        st.times.clear();
        st.ids.clear();
        return Optional.of(new Detection(evidence, Confidence.HIGH,
                n + " " + spec.step().pattern().canonical() + " within " + spec.within().toMinutes() + " min"));
    }
}
