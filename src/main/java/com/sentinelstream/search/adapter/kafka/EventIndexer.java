package com.sentinelstream.search.adapter.kafka;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.sentinelstream.event.EnrichedEvent;
import com.sentinelstream.search.application.EventStore;
import com.sentinelstream.shared.Json;
import com.sentinelstream.shared.Topics;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

import com.sentinelstream.shared.config.SentinelProperties;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/** Copies normalized events into Postgres in batches. Inserts are idempotent, so redelivery is harmless. */
@Component
class EventIndexer {

    private static final Logger log = LoggerFactory.getLogger(EventIndexer.class);

    private final EventStore store;
    private final Clock clock;
    private final Duration retention;
    private final Counter indexed;
    private final Counter expired;

    EventIndexer(EventStore store, Clock clock, SentinelProperties props, MeterRegistry meters) {
        this.store = store;
        this.clock = clock;
        this.retention = Duration.ofDays(props.events().retentionDays());
        this.indexed = meters.counter("sentinel.events.indexed");
        this.expired = meters.counter("sentinel.events.expired");
    }

    @KafkaListener(topics = Topics.NORMALIZED, groupId = "sentinel-indexer", containerFactory = "batchFactory")
    void index(List<ConsumerRecord<String, String>> records) {
        List<EnrichedEvent> events = new ArrayList<>(records.size());
        Instant oldest = clock.instant().minus(retention);
        for (var r : records) {
            try {
                EnrichedEvent e = Json.MAPPER.readValue(r.value(), EnrichedEvent.class);
                // older than retention: its partition is (or is about to be) dropped; detection still saw it
                if (e.ts().isBefore(oldest)) {
                    expired.increment();
                    continue;
                }
                events.add(e);
            } catch (JsonProcessingException e) {
                log.warn("skipping unreadable normalized record at {}-{}@{}", r.topic(), r.partition(), r.offset());
            }
        }
        indexed.increment(store.store(events));
    }
}
