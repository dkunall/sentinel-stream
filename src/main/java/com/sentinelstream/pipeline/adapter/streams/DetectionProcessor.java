package com.sentinelstream.pipeline.adapter.streams;

import com.sentinelstream.detection.application.RuleSets;
import com.sentinelstream.detection.domain.engine.DetectionEngine;
import com.sentinelstream.detection.domain.engine.EntityState;
import com.sentinelstream.detection.domain.engine.Signal;
import com.sentinelstream.detection.domain.rule.EntityKind;
import com.sentinelstream.event.EnrichedEvent;
import com.sentinelstream.shared.Json;
import org.apache.kafka.streams.KeyValue;
import org.apache.kafka.streams.processor.PunctuationType;
import org.apache.kafka.streams.processor.api.Processor;
import org.apache.kafka.streams.processor.api.ProcessorContext;
import org.apache.kafka.streams.processor.api.Record;
import org.apache.kafka.streams.state.KeyValueIterator;
import org.apache.kafka.streams.state.KeyValueStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Loads the entity's state, runs the engine, stores the state, forwards signals. State lives in a
 * changelogged RocksDB store; with exactly-once processing the state write, the signals and the input
 * offset commit together, so a crash neither loses nor double-applies an event.
 */
final class DetectionProcessor implements Processor<String, String, String, String> {

    private static final Logger log = LoggerFactory.getLogger(DetectionProcessor.class);

    private final EntityKind kind;
    private final String storeName;
    private final DetectionEngine engine;
    private final RuleSets rules;
    private final Duration idleTtl;
    private ProcessorContext<String, String> ctx;
    private KeyValueStore<String, byte[]> store;

    DetectionProcessor(EntityKind kind, String storeName, DetectionEngine engine, RuleSets rules, Duration idleTtl) {
        this.kind = kind;
        this.storeName = storeName;
        this.engine = engine;
        this.rules = rules;
        this.idleTtl = idleTtl;
    }

    @Override
    public void init(ProcessorContext<String, String> context) {
        this.ctx = context;
        this.store = context.getStateStore(storeName);
        context.schedule(Duration.ofHours(1), PunctuationType.WALL_CLOCK_TIME, this::evictIdle);
    }

    @Override
    public void process(Record<String, String> record) {
        EnrichedEvent event;
        try {
            event = Json.MAPPER.readValue(record.value(), EnrichedEvent.class);
        } catch (IOException e) {
            log.warn("skipping unreadable {} record {}", kind, record.key());
            return;
        }
        EntityState state = load(record.key());
        List<Signal> signals = engine.process(rules.current(event.tenant()), kind, state, event);
        store.put(record.key(), DetectionTopology.write(state).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        for (Signal s : signals) {
            ctx.forward(record.withKey(s.tenant() + "|" + s.entityKey()).withValue(DetectionTopology.write(s)));
        }
    }

    private EntityState load(String key) {
        byte[] bytes = store.get(key);
        if (bytes == null) {
            return new EntityState();
        }
        try {
            return Json.MAPPER.readValue(bytes, EntityState.class);
        } catch (IOException e) {
            log.warn("discarding unreadable state for {} entity {}", kind, key);
            return new EntityState();
        }
    }

    /** Forget entities with no events for the idle TTL; without this the store only ever grows. */
    void evictIdle(long nowMs) {
        long cutoff = nowMs - idleTtl.toMillis();
        List<String> idle = new ArrayList<>();
        try (KeyValueIterator<String, byte[]> it = store.all()) {
            while (it.hasNext()) {
                KeyValue<String, byte[]> kv = it.next();
                try {
                    if (Json.MAPPER.readValue(kv.value, EntityState.class).lastEventMs < cutoff) {
                        idle.add(kv.key);
                    }
                } catch (IOException e) {
                    idle.add(kv.key);
                }
            }
        }
        idle.forEach(store::delete);
        if (!idle.isEmpty()) {
            log.info("evicted {} idle {} entities", idle.size(), kind);
        }
    }
}
