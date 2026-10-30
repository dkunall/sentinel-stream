package com.sentinelstream.playbook.adapter.web;

import com.sentinelstream.playbook.application.PlaybookService;
import com.sentinelstream.playbook.application.PlaybookStore;
import com.sentinelstream.playbook.domain.Step;
import com.sentinelstream.shared.security.Actor;
import com.sentinelstream.shared.security.Actors;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
class PlaybooksController {

    private final PlaybookService playbooks;
    private final JdbcTemplate jdbc;

    PlaybooksController(PlaybookService playbooks, JdbcTemplate jdbc) {
        this.playbooks = playbooks;
        this.jdbc = jdbc;
    }

    record PlaybookRequest(@NotBlank @Size(max = 200) String name, List<String> triggerRules, @NotNull List<Step> steps,
                           boolean needsApproval) {
    }

    @PutMapping("/v1/playbooks/{id}")
    PlaybookStore.Playbook define(@PathVariable String id, @Valid @RequestBody PlaybookRequest req) {
        Actor actor = Actors.require(Actor.ADMIN);
        return playbooks.define(actor.tenant(), actor.subject(), id, req.name(), req.triggerRules(), req.steps(), req.needsApproval());
    }

    @GetMapping("/v1/playbooks")
    List<PlaybookStore.Playbook> list() {
        return playbooks.list(Actors.current().tenant());
    }

    @PostMapping("/v1/incidents/{incidentId}/playbooks/{playbookId}:run")
    ResponseEntity<PlaybookStore.Run> run(@PathVariable UUID incidentId, @PathVariable String playbookId) {
        Actor actor = Actors.current();
        return ResponseEntity.status(201).body(playbooks.request(actor.tenant(), actor.subject(), incidentId, playbookId));
    }

    @GetMapping("/v1/playbook-runs/{id}")
    Map<String, Object> get(@PathVariable UUID id) {
        Actor actor = Actors.current();
        var run = playbooks.run(actor.tenant(), id);
        return Map.of("run", run, "steps", jdbc.queryForList(
                "select idx, kind, status, detail, at from playbook_step_result where run_id = ? order by idx", id));
    }

    @PostMapping("/v1/playbook-runs/{id}:approve")
    PlaybookStore.Run approve(@PathVariable UUID id) {
        Actor actor = Actors.require(Actor.ADMIN);
        return playbooks.decide(actor.tenant(), actor.subject(), id, true);
    }

    @PostMapping("/v1/playbook-runs/{id}:reject")
    PlaybookStore.Run reject(@PathVariable UUID id) {
        Actor actor = Actors.require(Actor.ADMIN);
        return playbooks.decide(actor.tenant(), actor.subject(), id, false);
    }

    @GetMapping("/v1/demo/accounts")
    List<Map<String, Object>> accounts() {
        return jdbc.queryForList("select user_name, locked, locked_at, locked_by_run from demo_account where tenant_id = ? order by user_name",
                Actors.current().tenant());
    }
}
