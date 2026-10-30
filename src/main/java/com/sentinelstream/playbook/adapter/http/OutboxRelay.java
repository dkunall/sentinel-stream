package com.sentinelstream.playbook.adapter.http;

import com.sentinelstream.playbook.domain.Step;
import com.sentinelstream.playbook.domain.WebhookSignature;
import com.sentinelstream.shared.config.SentinelProperties;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Delivers queued webhooks at least once: a row is marked sent only after a 2xx, so a crash between
 * the send and the update resends it. Receivers dedupe on the delivery key in the payload. The host
 * allow-list is checked again at send time, redirects are not followed, and after 10 attempts a
 * delivery is parked with its last error.
 */
@Component
class OutboxRelay {

    private static final Logger log = LoggerFactory.getLogger(OutboxRelay.class);
    static final int MAX_ATTEMPTS = 10;

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final WebhookSecret secret;
    private final Set<String> allowedHosts;
    private final MeterRegistry meters;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3))
            .followRedirects(HttpClient.Redirect.NEVER).build();

    OutboxRelay(JdbcTemplate jdbc, TransactionTemplate tx, WebhookSecret secret, SentinelProperties props, MeterRegistry meters) {
        this.jdbc = jdbc;
        this.tx = tx;
        this.secret = secret;
        this.allowedHosts = props.webhooks().allowedHosts().stream().map(String::toLowerCase).collect(Collectors.toUnmodifiableSet());
        this.meters = meters;
    }

    record Pending(long id, String url, String payload, int attempts) {
    }

    @Scheduled(fixedDelayString = "${sentinel.webhooks.poll}")
    void relay() {
        tx.executeWithoutResult(s -> {
            var batch = jdbc.query("""
                    select id, target_url, payload::text, attempts from outbox
                    where sent_at is null and attempts < ? and next_attempt_at <= now()
                    order by id limit 20 for update skip locked
                    """, (rs, i) -> new Pending(rs.getLong(1), rs.getString(2), rs.getString(3), rs.getInt(4)), MAX_ATTEMPTS);
            for (Pending p : batch) {
                String error = send(p);
                if (error == null) {
                    jdbc.update("update outbox set sent_at = now(), attempts = attempts + 1, last_error = null where id = ?", p.id());
                    meters.counter("sentinel.webhooks", "result", "sent").increment();
                } else {
                    long backoff = Math.min(600, 1L << Math.min(p.attempts(), 10));
                    jdbc.update("""
                            update outbox set attempts = attempts + 1, last_error = ?,
                                next_attempt_at = now() + make_interval(secs => ?) where id = ?
                            """, error, (double) backoff, p.id());
                    meters.counter("sentinel.webhooks", "result", "failed").increment();
                }
            }
        });
    }

    private String send(Pending p) {
        try {
            var uri = Step.checkUrl(p.url(), allowedHosts);
            byte[] body = p.payload().getBytes(StandardCharsets.UTF_8);
            var req = HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(5))
                    .header("Content-Type", "application/json")
                    .header("X-Sentinel-Delivery", Long.toString(p.id()))
                    .header("X-Sentinel-Signature", WebhookSignature.sign(secret.value(), body))
                    .POST(HttpRequest.BodyPublishers.ofByteArray(body)).build();
            int status = http.send(req, HttpResponse.BodyHandlers.discarding()).statusCode();
            return status / 100 == 2 ? null : "HTTP " + status;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return "interrupted";
        } catch (Exception e) {
            log.debug("webhook {} failed: {}", p.id(), e.toString());
            String m = e.getClass().getSimpleName() + (e.getMessage() == null ? "" : ": " + e.getMessage());
            return m.length() > 300 ? m.substring(0, 300) : m;
        }
    }
}
