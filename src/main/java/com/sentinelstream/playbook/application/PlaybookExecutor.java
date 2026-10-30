package com.sentinelstream.playbook.application;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.sentinelstream.detection.application.RuleService;
import com.sentinelstream.playbook.domain.RunStatus;
import com.sentinelstream.playbook.domain.Step;
import com.sentinelstream.response.application.IncidentService;
import com.sentinelstream.response.application.IncidentStore;
import com.sentinelstream.response.domain.IncidentState;
import com.sentinelstream.shared.Json;
import com.sentinelstream.shared.audit.AuditRecorder;
import com.sentinelstream.shared.error.ApiException;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Runs approved playbooks. Claiming uses SKIP LOCKED so several instances share the queue without
 * double-claiming; each step commits together with its result row, and a step whose row exists is
 * skipped, so a run resumed after a crash never repeats a finished step.
 */
@Component
public class PlaybookExecutor {

    private static final Logger log = LoggerFactory.getLogger(PlaybookExecutor.class);
    static final Duration STALE = Duration.ofMinutes(2);
    static final String ACTOR = "system:playbook";

    private final PlaybookStore store;
    private final IncidentService incidents;
    private final RuleService rules;
    private final AuditRecorder audit;
    private final TransactionTemplate tx;
    private final MeterRegistry meters;

    PlaybookExecutor(PlaybookStore store, IncidentService incidents, RuleService rules, AuditRecorder audit,
                     TransactionTemplate tx, MeterRegistry meters) {
        this.store = store;
        this.incidents = incidents;
        this.rules = rules;
        this.audit = audit;
        this.tx = tx;
        this.meters = meters;
    }

    @Scheduled(fixedDelayString = "${sentinel.playbooks.poll}")
    public void poll() {
        for (int i = 0; i < 10; i++) {
            var run = tx.execute(s -> store.claimNext(STALE));
            if (run == null || run.isEmpty()) {
                return;
            }
            execute(run.get());
        }
    }

    void execute(PlaybookStore.Run run) {
        var pb = store.playbook(run.tenant(), run.playbookId()).orElse(null);
        var incident = incidents.get(run.tenant(), run.incidentId());
        if (pb == null) {
            fail(run, "playbook was deleted");
            return;
        }
        List<Step> steps = pb.steps();
        for (int i = 0; i < steps.size(); i++) {
            int idx = i;
            Step step = steps.get(i);
            try {
                tx.executeWithoutResult(s -> {
                    if (store.stepRecorded(run.id(), idx)) {
                        return;
                    }
                    String[] outcome = perform(run, incident, step, idx);
                    store.recordStep(run.id(), idx, step.kind().name(), outcome[0], outcome[1]);
                });
            } catch (RuntimeException e) {
                log.warn("playbook run {} step {} failed: {}", run.id(), idx, e.toString());
                tx.executeWithoutResult(s -> store.recordStep(run.id(), idx, step.kind().name(), "FAILED", trim(e.getMessage())));
                fail(run, "step " + idx + " (" + step.kind() + ") failed");
                return;
            }
        }
        tx.executeWithoutResult(s -> {
            if (!store.finish(run.id(), RunStatus.SUCCEEDED, null)) {
                return;
            }
            audit.record(run.tenant(), ACTOR, "playbook.succeeded", run.id().toString(), Map.of("playbook", run.playbookId()));
            var now = incidents.get(run.tenant(), run.incidentId());
            if (now.state() == IncidentState.INVESTIGATING) {
                try {
                    incidents.transition(run.tenant(), ACTOR, run.incidentId(), IncidentState.CONTAINED, null, null);
                } catch (ApiException e) {
                    log.info("run {} succeeded but incident {} was not contained: {}", run.id(), run.incidentId(), e.getMessage());
                }
            }
        });
        meters.counter("sentinel.playbook.runs", "status", "SUCCEEDED").increment();
    }

    private String[] perform(PlaybookStore.Run run, IncidentStore.Incident incident, Step step, int idx) {
        return switch (step.kind()) {
            case LOCK_ACCOUNT -> {
                if (!incident.entityKind().equals("USER")) {
                    yield new String[]{"SKIPPED", "incident entity is not a user"};
                }
                boolean changed = store.lockDemoAccount(run.tenant(), incident.entityKey(), run.id());
                audit.record(run.tenant(), ACTOR, "demo_account.locked", incident.entityKey(), Map.of("run", run.id().toString(), "changed", changed));
                yield new String[]{"DONE", changed ? "demo account locked" : "demo account was already locked"};
            }
            case ADD_TO_IOC_LIST -> {
                if (!incident.entityKind().equals("IP")) {
                    yield new String[]{"SKIPPED", "incident entity is not an IP"};
                }
                int added = rules.addIocs(run.tenant(), ACTOR, step.params().get("list"), "ip", List.of(incident.entityKey()));
                yield new String[]{"DONE", added == 1 ? "added to " + step.params().get("list") : "already listed"};
            }
            case NOTIFY_WEBHOOK -> {
                Map<String, Object> payload = new LinkedHashMap<>();
                payload.put("deliveryKey", run.id() + ":" + idx);
                payload.put("tenant", run.tenant());
                payload.put("incidentId", incident.id().toString());
                payload.put("runId", run.id().toString());
                payload.put("playbook", run.playbookId());
                payload.put("entity", incident.entityKind() + ":" + incident.entityKey());
                payload.put("severity", incident.severity());
                payload.put("title", incident.title());
                try {
                    boolean queued = store.enqueueWebhook(run.tenant(), run.id(), run.id() + ":" + idx, step.params().get("url"),
                            Json.MAPPER.writeValueAsString(payload));
                    yield new String[]{"DONE", queued ? "webhook queued" : "webhook already queued"};
                } catch (JsonProcessingException e) {
                    throw new IllegalStateException(e);
                }
            }
        };
    }

    private void fail(PlaybookStore.Run run, String error) {
        tx.executeWithoutResult(s -> {
            if (store.finish(run.id(), RunStatus.FAILED, error)) {
                audit.record(run.tenant(), ACTOR, "playbook.failed", run.id().toString(), Map.of("error", error));
            }
        });
        meters.counter("sentinel.playbook.runs", "status", "FAILED").increment();
    }

    private static String trim(String s) {
        return s == null ? "error" : s.length() > 500 ? s.substring(0, 500) : s;
    }
}
