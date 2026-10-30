package com.sentinelstream.detection.domain.rule;

import com.sentinelstream.event.EnrichedEvent;
import com.sentinelstream.event.Outcome;

/** {@code action.outcome}, either part may be {@code *}. */
public record EventPattern(String action, Outcome outcome) {

    public boolean matches(EnrichedEvent e) {
        return (action == null || action.equals(e.event().action()))
                && (outcome == null || outcome == e.event().outcome());
    }

    public String canonical() {
        return (action == null ? "*" : action) + "." + (outcome == null ? "*" : outcome.dsl());
    }
}
