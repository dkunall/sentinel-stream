package com.sentinelstream.detection.application;

import com.sentinelstream.event.EnrichedEvent;

import java.time.Instant;
import java.util.List;

/** Port: stored events for backtesting, oldest first. */
public interface EventHistory {

    List<EnrichedEvent> replay(String tenant, Instant from, Instant to, int max);
}
