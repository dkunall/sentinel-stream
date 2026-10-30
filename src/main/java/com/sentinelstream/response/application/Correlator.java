package com.sentinelstream.response.application;

import com.sentinelstream.detection.domain.engine.Confidence;
import com.sentinelstream.detection.domain.engine.Signal;
import com.sentinelstream.response.domain.AlertFingerprint;
import com.sentinelstream.shared.audit.AuditRecorder;
import com.sentinelstream.shared.config.SentinelProperties;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import java.util.UUID;

/**
 * Turns detector signals into alerts and incidents. Idempotent per signal id: the signal row's primary
 * key is the authority, Redis only saves a database round trip for recent repeats. HIGH-confidence
 * alerts join the entity's open incident if it saw an alert within the correlation window, otherwise
 * they open one; the per-entity advisory lock makes "find or open" atomic, so concurrent alerts about
 * one user end up in one incident.
 */
@Service
public class Correlator {

    public enum Outcome { DUPLICATE, ALERT_CREATED, ALERT_UPDATED }

    private final CorrelationStore store;
    private final SignalSeen seen;
    private final AuditRecorder audit;
    private final TransactionTemplate tx;
    private final Clock clock;
    private final Duration window;
    private final Timer latency;
    private final Counter duplicates;

    Correlator(CorrelationStore store, SignalSeen seen, AuditRecorder audit, TransactionTemplate tx, Clock clock,
               SentinelProperties props, MeterRegistry meters) {
        this.store = store;
        this.seen = seen;
        this.audit = audit;
        this.tx = tx;
        this.clock = clock;
        this.window = props.correlation().incidentWindow();
        this.latency = Timer.builder("sentinel.detection.latency")
                .description("ingest API accepted the event → correlator committed the signal")
                .publishPercentiles(0.5, 0.95, 0.99).register(meters);
        this.duplicates = meters.counter("sentinel.signals.duplicate");
    }

    public Outcome onSignal(Signal s) {
        if (seen.seen(s.id())) {
            duplicates.increment();
            return Outcome.DUPLICATE;
        }
        Outcome outcome = tx.execute(status -> correlate(s));
        seen.remember(s.id());
        if (outcome == Outcome.DUPLICATE) {
            duplicates.increment();
        } else {
            latency.record(Duration.between(s.ingestedAt(), clock.instant()));
        }
        return outcome;
    }

    private Outcome correlate(Signal s) {
        String fp = AlertFingerprint.of(s);
        UUID alertId = AlertFingerprint.alertId(fp);
        if (!store.recordSignal(s, alertId)) {
            return Outcome.DUPLICATE;
        }
        boolean created = store.upsertAlert(alertId, fp, s);
        if (created) {
            audit.record(s.tenant(), "system:correlator", "alert.created", alertId.toString(),
                    Map.of("rule", s.ruleId() + "@" + s.ruleVersion(), "entity", s.entityKind() + ":" + s.entityKey(),
                            "severity", s.severity().name(), "confidence", s.confidence().name()));
        }
        if (s.confidence() == Confidence.HIGH) {
            String kind = s.entityKind().name();
            store.lockEntity(s.tenant(), kind, s.entityKey());
            var linked = store.incidentOfAlert(alertId);
            if (linked.isPresent()) {
                store.touchIncident(linked.get(), s.ts(), s.severity());
            } else {
                var open = store.latestOpenIncident(s.tenant(), kind, s.entityKey(), s.ts().minus(window));
                if (open.isPresent()) {
                    store.attach(open.get().id(), alertId);
                    store.touchIncident(open.get().id(), s.ts(), s.severity());
                } else {
                    UUID incident = store.openIncident(s);
                    store.attach(incident, alertId);
                    audit.record(s.tenant(), "system:correlator", "incident.opened", incident.toString(),
                            Map.of("alert", alertId.toString(), "entity", kind + ":" + s.entityKey()));
                }
            }
        }
        return created ? Outcome.ALERT_CREATED : Outcome.ALERT_UPDATED;
    }
}
