package com.sentinelstream.support;

import com.sentinelstream.detection.domain.engine.Confidence;
import com.sentinelstream.detection.domain.engine.Signal;
import com.sentinelstream.detection.domain.rule.EntityKind;
import com.sentinelstream.detection.domain.rule.Severity;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/** Builds detector output directly, for tests that start at correlation instead of at ingest. */
public final class Signals {

    private Signals() {
    }

    public static Signal high(String tenant, String ruleId, EntityKind kind, String entity, Instant ts) {
        String evt = UUID.randomUUID().toString();
        return new Signal(UUID.randomUUID().toString(), tenant, ruleId, 1, ruleId, Severity.HIGH, Confidence.HIGH, kind, entity,
                ts, evt, List.of(evt), Instant.now(), "synthetic signal for " + entity);
    }
}
