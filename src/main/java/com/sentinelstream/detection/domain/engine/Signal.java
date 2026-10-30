package com.sentinelstream.detection.domain.engine;

import com.sentinelstream.detection.domain.rule.EntityKind;
import com.sentinelstream.detection.domain.rule.Severity;

import java.time.Instant;
import java.util.List;

/**
 * One detection. The id is derived from rule version, entity and the triggering event, so replaying
 * the same events (redelivery, detector restart) produces the same id and the correlator can drop it.
 */
public record Signal(
        String id,
        String tenant,
        String ruleId,
        int ruleVersion,
        String ruleName,
        Severity severity,
        Confidence confidence,
        EntityKind entityKind,
        String entityKey,
        Instant ts,
        String triggerEventId,
        List<String> eventIds,
        Instant ingestedAt,
        String summary) {

    public Signal {
        eventIds = List.copyOf(eventIds);
    }
}
