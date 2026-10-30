package com.sentinelstream.pipeline.adapter.streams;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.sentinelstream.detection.application.RuleSets;
import com.sentinelstream.detection.domain.engine.DetectionEngine;
import com.sentinelstream.detection.domain.rule.EntityKind;
import com.sentinelstream.event.EnrichedEvent;
import com.sentinelstream.ingest.domain.Normalized;
import com.sentinelstream.ingest.domain.Normalizer;
import com.sentinelstream.ingest.domain.RawEnvelope;
import com.sentinelstream.ingest.domain.enrich.EnricherChain;
import com.sentinelstream.shared.Json;
import com.sentinelstream.shared.Topics;
import org.apache.kafka.common.serialization.Serdes;
import org.apache.kafka.streams.StreamsBuilder;
import org.apache.kafka.streams.Topology;
import org.apache.kafka.streams.kstream.Consumed;
import org.apache.kafka.streams.kstream.KStream;
import org.apache.kafka.streams.kstream.Produced;
import org.apache.kafka.streams.state.Stores;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * raw → normalize + enrich → normalized (and dlq for anything that does not parse), then re-keyed by
 * user and by ip through their own topics so each entity's events land on one partition in order,
 * and finally one stateful detection processor per entity kind writing signals to the alerts topic.
 */
public final class DetectionTopology {

    static final String USER_STORE = "entity-state-user";
    static final String IP_STORE = "entity-state-ip";
    private static final int MAX_DLQ_RAW = 8192;

    private DetectionTopology() {
    }

    public static Topology build(Normalizer normalizer, EnricherChain enricher, RuleSets rules, Duration idleTtl) {
        StreamsBuilder b = new StreamsBuilder();
        var strings = Consumed.with(Serdes.String(), Serdes.String());
        var out = Produced.with(Serdes.String(), Serdes.String());

        KStream<String, Outcome> parsed = b.stream(Topics.RAW, strings)
                .mapValues(raw -> parse(raw, normalizer, enricher));
        parsed.filter((k, v) -> v.event() == null).mapValues(Outcome::dlq).to(Topics.DLQ, out);

        KStream<String, EnrichedEvent> events = parsed.filter((k, v) -> v.event() != null).mapValues(Outcome::event);
        events.selectKey((k, e) -> e.tenant() + ":" + e.id()).mapValues(DetectionTopology::write).to(Topics.NORMALIZED, out);
        events.filter((k, e) -> e.event().user() != null)
                .selectKey((k, e) -> e.tenant() + "|" + e.event().user())
                .mapValues(DetectionTopology::write).to(Topics.BY_USER, out);
        events.filter((k, e) -> e.event().ip() != null)
                .selectKey((k, e) -> e.tenant() + "|" + e.event().ip())
                .mapValues(DetectionTopology::write).to(Topics.BY_IP, out);

        detect(b, Topics.BY_USER, USER_STORE, EntityKind.USER, rules, idleTtl);
        detect(b, Topics.BY_IP, IP_STORE, EntityKind.IP, rules, idleTtl);
        return b.build();
    }

    private static void detect(StreamsBuilder b, String topic, String store, EntityKind kind, RuleSets rules, Duration idleTtl) {
        b.addStateStore(Stores.keyValueStoreBuilder(Stores.persistentKeyValueStore(store), Serdes.String(), Serdes.ByteArray()));
        b.stream(topic, Consumed.with(Serdes.String(), Serdes.String()))
                .process(() -> new DetectionProcessor(kind, store, new DetectionEngine(), rules, idleTtl), store)
                .to(Topics.ALERTS, Produced.with(Serdes.String(), Serdes.String()));
    }

    record Outcome(EnrichedEvent event, String reason, RawEnvelope envelope, String raw) {
        String dlq() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("reason", reason);
            if (envelope != null) {
                m.put("tenant", envelope.tenant());
                m.put("source", envelope.source());
                m.put("receivedAt", envelope.receivedAt());
            }
            m.put("raw", raw.length() > MAX_DLQ_RAW ? raw.substring(0, MAX_DLQ_RAW) : raw);
            return write(m);
        }
    }

    static Outcome parse(String raw, Normalizer normalizer, EnricherChain enricher) {
        if (raw == null) {
            return new Outcome(null, "empty record", null, "");
        }
        RawEnvelope env;
        try {
            env = Json.MAPPER.readValue(raw, RawEnvelope.class);
        } catch (JsonProcessingException | RuntimeException e) {
            return new Outcome(null, "not a raw envelope", null, raw);
        }
        try {
            return switch (normalizer.normalize(env)) {
                case Normalized.Ok ok -> new Outcome(enricher.enrich(ok.event()), null, env, raw);
                case Normalized.Rejected r -> new Outcome(null, r.reason(), env, raw);
            };
        } catch (RuntimeException e) {
            return new Outcome(null, "normalizer failed: " + e.getClass().getSimpleName(), env, raw);
        }
    }

    static String write(Object o) {
        try {
            return Json.MAPPER.writeValueAsString(o);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }
}
