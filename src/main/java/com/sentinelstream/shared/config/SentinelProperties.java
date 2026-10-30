package com.sentinelstream.shared.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.List;

@ConfigurationProperties("sentinel")
public record SentinelProperties(
        Ingest ingest,
        Syslog syslog,
        Streams streams,
        Correlation correlation,
        Events events,
        Playbooks playbooks,
        Webhooks webhooks,
        Audit audit) {

    public record Ingest(int maxBatch, long maxBodyBytes, int maxInFlight, Duration dedupTtl, Duration maxEventAge,
                         Duration maxClockSkew) {
    }

    public record Syslog(boolean enabled, String bind, int port, String tenant) {
    }

    public record Streams(String applicationId, String stateDir, Duration rulesPoll, Duration entityIdleTtl) {
    }

    public record Correlation(Duration incidentWindow) {
    }

    public record Events(int retentionDays) {
    }

    public record Playbooks(Duration poll) {
    }

    public record Webhooks(String secret, List<String> allowedHosts, Duration poll) {
    }

    public record Audit(String bucket, String s3Endpoint, String s3AccessKey, String s3SecretKey, String signingKeyPem,
                        int retentionDays, Duration sealEvery, int maxBatch) {
    }
}
