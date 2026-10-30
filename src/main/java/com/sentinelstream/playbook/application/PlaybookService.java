package com.sentinelstream.playbook.application;

import com.sentinelstream.playbook.domain.RunStatus;
import com.sentinelstream.playbook.domain.Step;
import com.sentinelstream.response.application.IncidentService;
import com.sentinelstream.response.domain.IncidentState;
import com.sentinelstream.shared.audit.AuditRecorder;
import com.sentinelstream.shared.config.SentinelProperties;
import com.sentinelstream.shared.error.ApiException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Service
public class PlaybookService {

    private static final Pattern ID = Pattern.compile("[a-z0-9][a-z0-9-]{1,63}");

    private final PlaybookStore store;
    private final IncidentService incidents;
    private final AuditRecorder audit;
    private final Clock clock;
    private final Set<String> allowedHosts;

    PlaybookService(PlaybookStore store, IncidentService incidents, AuditRecorder audit, Clock clock, SentinelProperties props) {
        this.store = store;
        this.incidents = incidents;
        this.audit = audit;
        this.clock = clock;
        this.allowedHosts = props.webhooks().allowedHosts().stream().map(String::toLowerCase).collect(Collectors.toUnmodifiableSet());
    }

    @Transactional
    public PlaybookStore.Playbook define(String tenant, String actor, String id, String name, List<String> triggerRules,
                                         List<Step> steps, boolean needsApproval) {
        if (!ID.matcher(id).matches()) {
            throw ApiException.invalid("playbook id must match " + ID.pattern());
        }
        if (steps.isEmpty() || steps.size() > 10) {
            throw ApiException.invalid("a playbook has 1 to 10 steps");
        }
        for (Step s : steps) {
            try {
                s.validate(allowedHosts);
            } catch (IllegalArgumentException e) {
                throw ApiException.invalid(e.getMessage());
            }
        }
        var p = new PlaybookStore.Playbook(tenant, id, name, triggerRules == null ? List.of() : List.copyOf(triggerRules),
                steps, needsApproval);
        store.savePlaybook(p);
        audit.record(tenant, actor, "playbook.defined", id, Map.of("steps", steps.size(), "needsApproval", needsApproval));
        return p;
    }

    public List<PlaybookStore.Playbook> list(String tenant) {
        return store.playbooks(tenant);
    }

    @Transactional
    public PlaybookStore.Run request(String tenant, String actor, UUID incidentId, String playbookId) {
        var incident = incidents.get(tenant, incidentId);
        if (incident.state() != IncidentState.INVESTIGATING) {
            throw ApiException.conflict("incident-not-investigating", "playbooks run on INVESTIGATING incidents; this one is " + incident.state());
        }
        var pb = store.playbook(tenant, playbookId).orElseThrow(() -> ApiException.notFound("playbook"));
        var run = new PlaybookStore.Run(UUID.randomUUID(), tenant, pb.id(), incidentId,
                pb.needsApproval() ? RunStatus.PENDING_APPROVAL : RunStatus.APPROVED, actor, null, clock.instant(), null, null, null);
        if (!store.createRun(run)) {
            throw ApiException.conflict("run-exists", "this playbook already has a live run for the incident");
        }
        audit.record(tenant, actor, "playbook.requested", run.id().toString(),
                Map.of("playbook", pb.id(), "incident", incidentId.toString(), "status", run.status().name()));
        return run;
    }

    /** Four-eyes: the approver must be an admin who is not the requester. Only one decision wins. */
    @Transactional
    public PlaybookStore.Run decide(String tenant, String actor, UUID runId, boolean approve) {
        var run = store.run(tenant, runId).orElseThrow(() -> ApiException.notFound("playbook run"));
        if (run.requestedBy().equals(actor)) {
            throw ApiException.forbidden("four-eyes", "the requester cannot approve their own run");
        }
        if (run.status() != RunStatus.PENDING_APPROVAL || !store.decide(runId, approve, actor)) {
            throw ApiException.conflict("already-decided", "run is no longer pending approval");
        }
        audit.record(tenant, actor, approve ? "playbook.approved" : "playbook.rejected", runId.toString(), Map.of("playbook", run.playbookId()));
        return store.run(tenant, runId).orElseThrow();
    }

    public PlaybookStore.Run run(String tenant, UUID id) {
        return store.run(tenant, id).orElseThrow(() -> ApiException.notFound("playbook run"));
    }
}
