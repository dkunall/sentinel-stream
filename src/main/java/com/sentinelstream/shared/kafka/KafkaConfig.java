package com.sentinelstream.shared.kafka;

import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.kafka.ConcurrentKafkaListenerContainerFactoryConfigurer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.ConcurrentKafkaListenerContainerFactory;
import org.springframework.kafka.core.ConsumerFactory;
import org.springframework.kafka.listener.ContainerProperties;
import org.springframework.kafka.listener.DefaultErrorHandler;
import org.springframework.util.backoff.ExponentialBackOff;

/**
 * Listener error policy: retry with backoff for about two minutes (long enough to ride out a database
 * restart), then log and skip the record, counting it in {@code sentinel.consumer.skipped}. Skipping
 * loses that record's effect; the counter is what an operator should alert on.
 */
@Configuration(proxyBeanMethods = false)
class KafkaConfig {

    private static final Logger log = LoggerFactory.getLogger(KafkaConfig.class);

    @Bean
    DefaultErrorHandler kafkaErrorHandler(MeterRegistry meters) {
        var backoff = new ExponentialBackOff(200, 2.0);
        backoff.setMaxInterval(10_000);
        backoff.setMaxElapsedTime(120_000);
        var skipped = meters.counter("sentinel.consumer.skipped");
        return new DefaultErrorHandler((record, e) -> {
            skipped.increment();
            log.error("giving up on {}-{}@{} after retries", record.topic(), record.partition(), record.offset(), e);
        }, backoff);
    }

    @Bean
    ConcurrentKafkaListenerContainerFactory<Object, Object> kafkaListenerContainerFactory(
            ConcurrentKafkaListenerContainerFactoryConfigurer configurer, ConsumerFactory<Object, Object> consumers,
            DefaultErrorHandler errors) {
        var f = new ConcurrentKafkaListenerContainerFactory<Object, Object>();
        configurer.configure(f, consumers);
        f.setCommonErrorHandler(errors);
        return f;
    }

    @Bean
    ConcurrentKafkaListenerContainerFactory<Object, Object> batchFactory(
            ConcurrentKafkaListenerContainerFactoryConfigurer configurer, ConsumerFactory<Object, Object> consumers,
            DefaultErrorHandler errors) {
        var f = new ConcurrentKafkaListenerContainerFactory<Object, Object>();
        configurer.configure(f, consumers);
        f.setBatchListener(true);
        f.getContainerProperties().setAckMode(ContainerProperties.AckMode.BATCH);
        f.setCommonErrorHandler(errors);
        return f;
    }
}
