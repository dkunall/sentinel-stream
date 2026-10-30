package com.sentinelstream.response.application;

import com.sentinelstream.response.domain.IncidentState;
import com.sentinelstream.response.domain.TransitionRules;
import com.sentinelstream.shared.audit.AuditRecorder;
import com.sentinelstream.shared.error.ApiException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Service
public class IncidentService {

    private final IncidentStore store;
    private final AuditRecorder audit;

    IncidentService(IncidentStore store, AuditRecorder audit) {
        this.store = store;
        this.audit = audit;
    }

    public IncidentStore.Incident get(String tenant, UUID id) {
        return store.find(tenant, id).orElseThrow(() -> ApiException.notFound("incident"));
    }

    /**
     * Moves an incident. {@code expectedVersion} is optional; when given, a stale view gets 409 instead
     * of silently applying on top of someone else's change.
     */
    @Transactional
    public IncidentStore.Incident transition(String tenant, String actor, UUID id, IncidentState to, String note,
                                             Integer expectedVersion) {
        var current = get(tenant, id);
        if (expectedVersion != null && expectedVersion != current.version()) {
            throw ApiException.conflict("stale-version", "incident is at version " + current.version());
        }
        boolean playbookDone = to == IncidentState.CONTAINED && store.hasSucceededPlaybook(id);
        TransitionRules.refuse(current.state(), to, note, playbookDone).ifPresent(reason -> {
            throw ApiException.conflict("invalid-transition", reason);
        });
        if (!store.move(id, current.state(), current.version(), to)) {
            throw ApiException.conflict("stale-version", "incident changed concurrently; reload and retry");
        }
        store.logTransition(id, current.state(), to, actor, note);
        if (!to.isOpen()) {
            store.setAlertStatus(id, "CLOSED");
        } else if (!current.state().isOpen()) {
            store.setAlertStatus(id, "OPEN");
        }
        Map<String, Object> detail = new HashMap<>();
        detail.put("from", current.state().name());
        detail.put("to", to.name());
        if (note != null) {
            detail.put("note", note);
        }
        audit.record(tenant, actor, "incident.transition", id.toString(), detail);
        return get(tenant, id);
    }
}
