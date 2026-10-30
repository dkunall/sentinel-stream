package com.sentinelstream.response.domain;

import java.util.EnumSet;
import java.util.Map;
import java.util.Set;

/**
 * NEW → TRIAGED → (FALSE_POSITIVE | INVESTIGATING) → CONTAINED → RESOLVED, and RESOLVED can be
 * reopened into INVESTIGATING. Everything else is refused.
 */
public enum IncidentState {
    NEW, TRIAGED, FALSE_POSITIVE, INVESTIGATING, CONTAINED, RESOLVED;

    private static final Map<IncidentState, Set<IncidentState>> NEXT = Map.of(
            NEW, EnumSet.of(TRIAGED),
            TRIAGED, EnumSet.of(FALSE_POSITIVE, INVESTIGATING),
            FALSE_POSITIVE, EnumSet.noneOf(IncidentState.class),
            INVESTIGATING, EnumSet.of(CONTAINED),
            CONTAINED, EnumSet.of(RESOLVED),
            RESOLVED, EnumSet.of(INVESTIGATING));

    public boolean canMoveTo(IncidentState target) {
        return NEXT.get(this).contains(target);
    }

    /** Open incidents still collect new alerts for their entity. */
    public boolean isOpen() {
        return this != FALSE_POSITIVE && this != RESOLVED;
    }

    public Set<IncidentState> next() {
        return NEXT.get(this);
    }
}
