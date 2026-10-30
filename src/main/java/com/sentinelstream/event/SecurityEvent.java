package com.sentinelstream.event;

import java.time.Instant;
import java.util.Objects;

/**
 * The common schema every collector's input is normalized into. Only fields the detectors use are kept,
 * which is also the PII minimization step: anything else in the raw payload is dropped here.
 */
public record SecurityEvent(
        String id,
        String tenant,
        Instant ts,
        String user,
        String ip,
        String action,
        Outcome outcome,
        String userAgent,
        String deviceId,
        String source,
        Instant ingestedAt) {

    public SecurityEvent {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(tenant, "tenant");
        Objects.requireNonNull(ts, "ts");
        Objects.requireNonNull(action, "action");
        Objects.requireNonNull(outcome, "outcome");
        Objects.requireNonNull(source, "source");
        Objects.requireNonNull(ingestedAt, "ingestedAt");
    }
}
