package com.sentinelstream.playbook.application;

import com.sentinelstream.playbook.domain.RunStatus;
import com.sentinelstream.playbook.domain.Step;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface PlaybookStore {

    void savePlaybook(Playbook p);

    Optional<Playbook> playbook(String tenant, String id);

    List<Playbook> playbooks(String tenant);

    /** False if a live run of this playbook already exists for the incident. */
    boolean createRun(Run r);

    Optional<Run> run(String tenant, UUID id);

    /** Compare-and-set from PENDING_APPROVAL; false if someone already decided. */
    boolean decide(UUID runId, boolean approve, String approver);

    /** Claims one APPROVED run, or a RUNNING one whose worker went quiet for longer than {@code stale}. */
    Optional<Run> claimNext(Duration stale);

    boolean stepRecorded(UUID runId, int idx);

    void recordStep(UUID runId, int idx, String kind, String status, String detail);

    boolean finish(UUID runId, RunStatus status, String error);

    /** Sets the lock flag on a synthetic demo account; true if it was not locked before. */
    boolean lockDemoAccount(String tenant, String user, UUID runId);

    /** Idempotent on the dedup key. */
    boolean enqueueWebhook(String tenant, UUID runId, String dedupKey, String url, String payloadJson);

    record Playbook(String tenant, String id, String name, List<String> triggerRules, List<Step> steps, boolean needsApproval) {
    }

    record Run(UUID id, String tenant, String playbookId, UUID incidentId, RunStatus status, String requestedBy,
               String approvedBy, Instant createdAt, Instant startedAt, Instant finishedAt, String error) {
    }
}
