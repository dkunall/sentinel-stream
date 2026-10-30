package com.sentinelstream.response.adapter.kafka;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.sentinelstream.detection.domain.engine.Signal;
import com.sentinelstream.response.application.Correlator;
import com.sentinelstream.shared.Json;
import com.sentinelstream.shared.Topics;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

@Component
class SignalListener {

    private static final Logger log = LoggerFactory.getLogger(SignalListener.class);

    private final Correlator correlator;

    SignalListener(Correlator correlator) {
        this.correlator = correlator;
    }

    @KafkaListener(topics = Topics.ALERTS, groupId = "sentinel-correlator")
    void onSignal(ConsumerRecord<String, String> record) {
        Signal s;
        try {
            s = Json.MAPPER.readValue(record.value(), Signal.class);
        } catch (JsonProcessingException e) {
            log.warn("skipping unreadable signal at {}-{}@{}", record.topic(), record.partition(), record.offset());
            return;
        }
        correlator.onSignal(s);
    }
}
