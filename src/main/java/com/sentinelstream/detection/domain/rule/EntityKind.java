package com.sentinelstream.detection.domain.rule;

import com.sentinelstream.event.EnrichedEvent;

/** What a rule groups events by. Each kind has its own re-keyed topic, so one entity's events stay ordered. */
public enum EntityKind {
    USER("user"), IP("ip");

    private final String field;

    EntityKind(String field) {
        this.field = field;
    }

    public String field() {
        return field;
    }

    public String keyOf(EnrichedEvent e) {
        return e.field(field);
    }

    public static EntityKind byField(String f) {
        for (EntityKind k : values()) {
            if (k.field.equals(f)) {
                return k;
            }
        }
        throw new IllegalArgumentException("rules can group by user or ip, not " + f);
    }
}
