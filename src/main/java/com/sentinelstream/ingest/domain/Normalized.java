package com.sentinelstream.ingest.domain;

import com.sentinelstream.event.SecurityEvent;

/** Either a normalized event or the reason the raw input was rejected (and sent to the DLQ). */
public sealed interface Normalized {

    record Ok(SecurityEvent event) implements Normalized {
    }

    record Rejected(String reason) implements Normalized {
    }
}
