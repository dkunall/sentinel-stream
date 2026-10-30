package com.sentinelstream.ingest.application;

import com.sentinelstream.ingest.domain.Normalized;
import com.sentinelstream.ingest.domain.Normalizer;
import com.sentinelstream.ingest.domain.RawEnvelope;
import com.sentinelstream.shared.config.SentinelProperties;
import com.sentinelstream.shared.error.ApiException;
import com.sentinelstream.shared.error.RateLimitedException;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

/**
 * Validates events synchronously (so a collector learns at once what was wrong), drops ids it has
 * already accepted in the last 24 hours, and publishes the rest to the raw topic. A semaphore bounds
 * how many events can be waiting on the broker at once; past that the caller gets 429 and backs off,
 * instead of the app buffering without limit while Kafka is slow.
 */
@Service
public class IngestService {

    private static final Logger log = LoggerFactory.getLogger(IngestService.class);

    public record Problem(int index, String reason) {
    }

    public record BatchResult(int accepted, int duplicates, List<Problem> rejected, List<Problem> failed) {
    }

    private final Normalizer normalizer;
    private final IngestDedup dedup;
    private final RawEventPublisher publisher;
    private final SentinelProperties.Ingest config;
    private final Semaphore inFlight;
    private final Clock clock;
    private final Counter accepted;
    private final Counter duplicates;
    private final Counter rejected;

    public IngestService(IngestDedup dedup, RawEventPublisher publisher, SentinelProperties props, Clock clock,
                         MeterRegistry meters) {
        this.config = props.ingest();
        this.normalizer = new Normalizer(clock, config.maxEventAge(), config.maxClockSkew());
        this.dedup = dedup;
        this.publisher = publisher;
        this.clock = clock;
        this.inFlight = new Semaphore(config.maxInFlight());
        this.accepted = meters.counter("sentinel.ingest.events", "result", "accepted");
        this.duplicates = meters.counter("sentinel.ingest.events", "result", "duplicate");
        this.rejected = meters.counter("sentinel.ingest.events", "result", "rejected");
    }

    public BatchResult ingest(String tenant, List<Map<String, Object>> events) {
        if (events == null || events.isEmpty()) {
            throw ApiException.invalid("events must be a non-empty array");
        }
        if (events.size() > config.maxBatch()) {
            throw new ApiException(413, "batch-too-large", "at most " + config.maxBatch() + " events per batch");
        }
        int n = events.size();
        if (!inFlight.tryAcquire(n)) {
            throw new RateLimitedException("ingest queue is full", 1);
        }
        try {
            return publishAll(tenant, events);
        } finally {
            inFlight.release(n);
        }
    }

    private BatchResult publishAll(String tenant, List<Map<String, Object>> events) {
        Instant now = clock.instant();
        List<Problem> bad = new ArrayList<>();
        List<Problem> failed = new ArrayList<>();
        List<Pending> pending = new ArrayList<>();
        int dups = 0;
        for (int i = 0; i < events.size(); i++) {
            Map<String, Object> payload = events.get(i);
            RawEnvelope env = RawEnvelope.http(tenant, now, payload == null ? Map.of() : payload);
            switch (normalizer.normalize(env)) {
                case Normalized.Rejected r -> bad.add(new Problem(i, r.reason()));
                case Normalized.Ok ok -> {
                    String id = ok.event().id();
                    if (!dedup.claim(tenant, id, config.dedupTtl())) {
                        dups++;
                    } else {
                        pending.add(new Pending(i, id, publisher.publish(partitionKey(tenant, ok.event()), env)));
                    }
                }
            }
        }
        int ok = 0;
        for (Pending p : pending) {
            try {
                p.future().get(10, TimeUnit.SECONDS);
                ok++;
            } catch (Exception e) {
                dedup.release(tenant, p.id());
                failed.add(new Problem(p.index(), "not queued, retry: " + rootMessage(e)));
            }
        }
        if (!failed.isEmpty()) {
            log.warn("{} of {} events could not be published for tenant {}", failed.size(), pending.size(), tenant);
        }
        accepted.increment(ok);
        duplicates.increment(dups);
        rejected.increment(bad.size());
        return new BatchResult(ok, dups, bad, failed);
    }

    /**
     * The raw topic is keyed by user (else ip, else event id), not by event id. Detection repartitions by
     * user and by ip, and a repartition only keeps the order its source partition had: keyed by id, one
     * user's events were spread over every raw partition and reached the user detector interleaved, so a
     * "five failures then a success" sequence could see the success first. Keyed by user, a user's events
     * stay in arrival order end to end; ip-keyed state can still see users interleaved, which only matters
     * for order-sensitive rules grouped by ip.
     */
    static String partitionKey(String tenant, com.sentinelstream.event.SecurityEvent e) {
        if (e.user() != null) {
            return tenant + "|u|" + e.user();
        }
        if (e.ip() != null) {
            return tenant + "|ip|" + e.ip();
        }
        return tenant + ":" + e.id();
    }

    /** Syslog has no reply channel: unparseable lines still go to the pipeline, which dead-letters them visibly. */
    public void ingestSyslog(String tenant, String line) {
        RawEnvelope env = RawEnvelope.syslog(tenant, clock.instant(), line);
        String key = tenant;
        if (normalizer.normalize(env) instanceof Normalized.Ok ok) {
            if (!dedup.claim(tenant, ok.event().id(), config.dedupTtl())) {
                duplicates.increment();
                return;
            }
            key = partitionKey(tenant, ok.event());
        }
        try {
            publisher.publish(key, env).get(10, TimeUnit.SECONDS);
        } catch (Exception e) {
            if (normalizer.normalize(env) instanceof Normalized.Ok ok) {
                dedup.release(tenant, ok.event().id());
            }
            throw new IllegalStateException("could not publish syslog line: " + rootMessage(e), e);
        }
    }

    private static String rootMessage(Throwable e) {
        Throwable t = e;
        while (t.getCause() != null) {
            t = t.getCause();
        }
        return t.getClass().getSimpleName();
    }

    private record Pending(int index, String id, CompletableFuture<Void> future) {
    }
}
