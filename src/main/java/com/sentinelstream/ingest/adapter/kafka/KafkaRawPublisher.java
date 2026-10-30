package com.sentinelstream.ingest.adapter.kafka;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sentinelstream.ingest.application.RawEventPublisher;
import com.sentinelstream.ingest.domain.RawEnvelope;
import com.sentinelstream.shared.Topics;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

import java.util.concurrent.CompletableFuture;

@Component
class KafkaRawPublisher implements RawEventPublisher {

    private final KafkaTemplate<String, String> kafka;
    private final ObjectMapper json;

    KafkaRawPublisher(KafkaTemplate<String, String> kafka, ObjectMapper json) {
        this.kafka = kafka;
        this.json = json;
    }

    @Override
    public CompletableFuture<Void> publish(String key, RawEnvelope envelope) {
        try {
            return kafka.send(Topics.RAW, key, json.writeValueAsString(envelope)).thenApply(r -> null);
        } catch (JsonProcessingException e) {
            return CompletableFuture.failedFuture(e);
        } catch (RuntimeException e) {
            return CompletableFuture.failedFuture(e);
        }
    }
}
