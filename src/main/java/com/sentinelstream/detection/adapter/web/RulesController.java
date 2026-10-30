package com.sentinelstream.detection.adapter.web;

import com.sentinelstream.detection.application.RuleService;
import com.sentinelstream.detection.application.RuleStore;
import com.sentinelstream.detection.domain.rule.Severity;
import com.sentinelstream.shared.security.Actor;
import com.sentinelstream.shared.security.Actors;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;
import java.util.Map;

@RestController
class RulesController {

    private final RuleService rules;

    RulesController(RuleService rules) {
        this.rules = rules;
    }

    record RuleRequest(@NotBlank @Size(max = 64) String id, @NotBlank @Size(max = 200) String name,
                       @NotBlank String dsl, @NotNull Severity severity, Boolean enabled) {
    }

    /** 201 with a new version, or 200 if the rule was already exactly this. */
    @PostMapping("/v1/rules")
    ResponseEntity<RuleStore.StoredRule> save(@Valid @RequestBody RuleRequest req) {
        Actor actor = Actors.require(Actor.ADMIN);
        var result = rules.save(actor.tenant(), actor.subject(), req.id(), req.name(), req.dsl(), req.severity(),
                req.enabled() == null || req.enabled());
        return ResponseEntity.status(result.changed() ? 201 : 200).body(result.rule());
    }

    @GetMapping("/v1/rules")
    List<RuleStore.StoredRule> list() {
        return rules.list(Actors.current().tenant());
    }

    record BacktestRequest(String dsl, Instant from, Instant to) {
    }

    @PostMapping("/v1/rules/{id}:backtest")
    RuleService.Backtest backtest(@PathVariable String id, @RequestBody(required = false) BacktestRequest req) {
        Actor actor = Actors.current();
        var r = req == null ? new BacktestRequest(null, null, null) : req;
        return rules.backtest(actor.tenant(), id, r.dsl(), r.from(), r.to());
    }

    record IocRequest(@NotBlank String kind, @NotNull List<String> values) {
    }

    @PostMapping("/v1/iocs/{list}")
    Map<String, Integer> addIocs(@PathVariable String list, @Valid @RequestBody IocRequest req) {
        Actor actor = Actors.require(Actor.ADMIN);
        return Map.of("added", rules.addIocs(actor.tenant(), actor.subject(), list, req.kind(), req.values()));
    }

    @DeleteMapping("/v1/iocs/{list}")
    ResponseEntity<Void> removeIoc(@PathVariable String list, @RequestParam String kind, @RequestParam String value) {
        Actor actor = Actors.require(Actor.ADMIN);
        return rules.removeIoc(actor.tenant(), actor.subject(), list, kind, value)
                ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    @GetMapping("/v1/iocs")
    List<RuleStore.IocEntry> iocs() {
        return rules.iocs(Actors.current().tenant());
    }
}
