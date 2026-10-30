package com.sentinelstream.ingest.domain;

import java.time.Instant;
import java.util.Map;

/**
 * What goes on the raw topic: the collector's payload untouched, plus who sent it and when it arrived.
 * Exactly one of {@code payload} (HTTP SDK) or {@code line} (syslog) is set.
 */
public record RawEnvelope(String tenant, String source, Instant receivedAt, Map<String, Object> payload, String line) {

    public static RawEnvelope http(String tenant, Instant receivedAt, Map<String, Object> payload) {
        return new RawEnvelope(tenant, "http", receivedAt, payload, null);
    }

    public static RawEnvelope syslog(String tenant, Instant receivedAt, String line) {
        return new RawEnvelope(tenant, "syslog", receivedAt, null, line);
    }
}
