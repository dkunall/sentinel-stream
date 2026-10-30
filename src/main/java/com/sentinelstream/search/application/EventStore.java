package com.sentinelstream.search.application;

import com.sentinelstream.event.EnrichedEvent;

import java.util.List;

/** Port: the searchable copy of normalized events. */
public interface EventStore {

    /** Idempotent: an event already stored is skipped. Returns rows actually inserted. */
    int store(List<EnrichedEvent> events);

    List<EventRow> search(EventQuery query);
}
