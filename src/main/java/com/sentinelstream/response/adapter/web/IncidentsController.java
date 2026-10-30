package com.sentinelstream.response.adapter.web;

import com.sentinelstream.response.adapter.persistence.ResponseQueries;
import com.sentinelstream.response.application.IncidentService;
import com.sentinelstream.response.application.IncidentStore;
import com.sentinelstream.response.domain.IncidentState;
import com.sentinelstream.shared.error.ApiException;
import com.sentinelstream.shared.security.Actor;
import com.sentinelstream.shared.security.Actors;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@RestController
class IncidentsController {

    private static final Set<String> ALERT_STATUS = Set.of("OPEN", "CLOSED");

    private final ResponseQueries queries;
    private final IncidentService incidents;

    IncidentsController(ResponseQueries queries, IncidentService incidents) {
        this.queries = queries;
        this.incidents = incidents;
    }

    @GetMapping("/v1/alerts")
    List<Map<String, Object>> alerts(@RequestParam(required = false) String status,
                                     @RequestParam(defaultValue = "50") int limit) {
        Actor actor = Actors.current();
        if (status != null && !ALERT_STATUS.contains(status)) {
            throw ApiException.invalid("status must be OPEN or CLOSED");
        }
        return queries.alerts(actor.tenant(), status, clamp(limit));
    }

    @GetMapping("/v1/incidents")
    List<IncidentStore.Incident> list(@RequestParam(required = false) String state,
                                      @RequestParam(defaultValue = "50") int limit) {
        Actor actor = Actors.current();
        return queries.incidents(actor.tenant(), state == null ? null : parse(state).name(), clamp(limit));
    }

    @GetMapping("/v1/incidents/{id}")
    Map<String, Object> get(@PathVariable UUID id) {
        Actor actor = Actors.current();
        var incident = incidents.get(actor.tenant(), id);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("incident", incident);
        body.put("allowedNext", incident.state().next());
        body.put("alerts", queries.incidentAlerts(id));
        body.put("transitions", queries.transitions(id));
        body.put("playbookRuns", queries.playbookRuns(id));
        return body;
    }

    record TransitionRequest(@NotNull String to, @Size(max = 2000) String note, Integer expectedVersion) {
    }

    @PostMapping("/v1/incidents/{id}/transition")
    IncidentStore.Incident transition(@PathVariable UUID id, @Valid @RequestBody TransitionRequest req) {
        Actor actor = Actors.current();
        return incidents.transition(actor.tenant(), actor.subject(), id, parse(req.to()), req.note(), req.expectedVersion());
    }

    private static IncidentState parse(String s) {
        try {
            return IncidentState.valueOf(s);
        } catch (IllegalArgumentException e) {
            throw ApiException.invalid("unknown incident state " + s);
        }
    }

    private static int clamp(int limit) {
        return Math.max(1, Math.min(limit, 200));
    }
}
