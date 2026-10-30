package com.sentinelstream.response.application;

import com.sentinelstream.response.domain.IncidentState;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface IncidentStore {

    Optional<Incident> find(String tenant, UUID id);

    boolean hasSucceededPlaybook(UUID incidentId);

    /** Compare-and-set on state and version. False means someone else moved it first. */
    boolean move(UUID id, IncidentState from, int version, IncidentState to);

    void logTransition(UUID id, IncidentState from, IncidentState to, String actor, String note);

    void setAlertStatus(UUID incidentId, String status);

    record Incident(UUID id, String tenant, String entityKind, String entityKey, IncidentState state, String severity,
                    String title, Instant openedAt, Instant lastAlertAt, Instant updatedAt, int version) {
    }
}
