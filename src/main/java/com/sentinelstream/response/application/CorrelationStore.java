package com.sentinelstream.response.application;

import com.sentinelstream.detection.domain.engine.Signal;
import com.sentinelstream.detection.domain.rule.Severity;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/** Port used inside the correlator's transaction. */
public interface CorrelationStore {

    /** False if this signal id was already recorded (a redelivery). */
    boolean recordSignal(Signal s, UUID alertId);

    /** Insert or bump the alert. Returns true if the alert is new. */
    boolean upsertAlert(UUID alertId, String fingerprint, Signal s);

    Optional<UUID> incidentOfAlert(UUID alertId);

    /** Serializes incident decisions for one entity across threads and instances, until commit. */
    void lockEntity(String tenant, String entityKind, String entityKey);

    Optional<OpenIncident> latestOpenIncident(String tenant, String entityKind, String entityKey, Instant notBefore);

    UUID openIncident(Signal s);

    void attach(UUID incidentId, UUID alertId);

    void touchIncident(UUID incidentId, Instant alertAt, Severity severity);

    record OpenIncident(UUID id, Severity severity) {
    }
}
