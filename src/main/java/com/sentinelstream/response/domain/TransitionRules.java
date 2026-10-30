package com.sentinelstream.response.domain;

import java.util.Optional;

/** The guards beyond the state graph itself. Returns why a transition is refused, if it is. */
public final class TransitionRules {

    private TransitionRules() {
    }

    public static Optional<String> refuse(IncidentState from, IncidentState to, String note, boolean hasSucceededPlaybook) {
        if (!from.canMoveTo(to)) {
            return Optional.of("cannot move from " + from + " to " + to + "; allowed: " + from.next());
        }
        if (to == IncidentState.CONTAINED && !hasSucceededPlaybook) {
            return Optional.of("containment needs a succeeded playbook run");
        }
        boolean needsNote = to == IncidentState.FALSE_POSITIVE || to == IncidentState.RESOLVED
                || (from == IncidentState.RESOLVED && to == IncidentState.INVESTIGATING);
        if (needsNote && (note == null || note.isBlank())) {
            return Optional.of("a note is required to move to " + to);
        }
        return Optional.empty();
    }
}
