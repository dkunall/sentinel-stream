package com.sentinelstream.pipeline.adapter.streams;

import com.sentinelstream.ingest.domain.enrich.EnricherChain;
import com.sentinelstream.ingest.domain.enrich.IpRangeTable;
import com.sentinelstream.shared.Topics;
import org.apache.kafka.clients.admin.NewTopic;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.TopicBuilder;
import org.springframework.kafka.core.KafkaAdmin;

import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

@Configuration(proxyBeanMethods = false)
class PipelineConfig {

    static final int PARTITIONS = 3;

    @Bean
    EnricherChain enricherChain() throws IOException {
        try (var in = PipelineConfig.class.getResourceAsStream("/geo/synthetic-ip-table.csv")) {
            if (in == null) {
                throw new IllegalStateException("synthetic IP table missing from the classpath");
            }
            return EnricherChain.standard(IpRangeTable.fromCsv(new InputStreamReader(in, StandardCharsets.UTF_8)));
        }
    }

    /** The two re-keyed topics must have the same partition count, or co-located state breaks on resize. */
    @Bean
    KafkaAdmin.NewTopics sentinelTopics() {
        return new KafkaAdmin.NewTopics(
                topic(Topics.RAW), topic(Topics.NORMALIZED), topic(Topics.BY_USER), topic(Topics.BY_IP),
                topic(Topics.ALERTS), topic(Topics.DLQ));
    }

    private static NewTopic topic(String name) {
        return TopicBuilder.name(name).partitions(PARTITIONS).replicas(1).build();
    }
}
