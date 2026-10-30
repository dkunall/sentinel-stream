package com.sentinelstream.detection.domain.engine;

import com.sentinelstream.detection.domain.rule.Condition;
import com.sentinelstream.detection.domain.rule.Step;
import com.sentinelstream.event.EnrichedEvent;

final class Conditions {

    static final java.util.List<String> CAPTURED = java.util.List.of("asn", "ip", "country", "city", "device", "user", "network", "user_agent");

    private Conditions() {
    }

    /** Does the event satisfy the step's pattern and every where-term? {@code run} is null for a first step. */
    static boolean matches(Step step, EnrichedEvent e, Run run, Profile profile) {
        if (!step.pattern().matches(e)) {
            return false;
        }
        for (Condition c : step.where()) {
            if (!holds(c, e, run, profile)) {
                return false;
            }
        }
        return true;
    }

    static boolean holds(Condition c, EnrichedEvent e, Run run, Profile profile) {
        String v = e.field(c.field());
        return switch (c) {
            case Condition.Equals eq -> (v != null && v.equalsIgnoreCase(eq.value())) != eq.negated();
            case Condition.In in -> (v != null && in.values().stream().anyMatch(v::equalsIgnoreCase)) != in.negated();
            case Condition.IsNew n -> v != null && !profile.knows(c.field(), v);
            case Condition.Same s -> v != null && run != null && v.equals(run.first.get(c.field()));
            case Condition.Changed ch -> v != null && run != null && !v.equals(run.last.get(c.field()));
        };
    }

    static void capture(java.util.Map<String, String> into, EnrichedEvent e) {
        into.clear();
        for (String f : CAPTURED) {
            String v = e.field(f);
            if (v != null) {
                into.put(f, v);
            }
        }
    }
}
