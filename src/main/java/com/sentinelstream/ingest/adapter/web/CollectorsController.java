package com.sentinelstream.ingest.adapter.web;

import com.sentinelstream.ingest.adapter.persistence.JdbcCollectors;
import com.sentinelstream.shared.audit.AuditRecorder;
import com.sentinelstream.shared.security.Actor;
import com.sentinelstream.shared.security.Actors;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Pattern;
import org.springframework.http.HttpStatus;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
class CollectorsController {

    record CreateCollector(@Pattern(regexp = "[a-z0-9][a-z0-9._-]{0,63}") String name) {
    }

    private final JdbcCollectors collectors;
    private final AuditRecorder audit;

    CollectorsController(JdbcCollectors collectors, AuditRecorder audit) {
        this.collectors = collectors;
        this.audit = audit;
    }

    @PostMapping("/v1/collectors")
    @ResponseStatus(HttpStatus.CREATED)
    @Transactional
    JdbcCollectors.Issued create(@Valid @RequestBody CreateCollector body) {
        Actor admin = Actors.require(Actor.ADMIN);
        var issued = collectors.issue(admin.tenant(), body.name(), admin.subject());
        audit.record(admin.tenant(), admin.subject(), "collector.created", issued.id().toString(),
                Map.of("name", body.name()));
        return issued;
    }

    @GetMapping("/v1/collectors")
    List<JdbcCollectors.Collector> list() {
        return collectors.list(Actors.current().tenant());
    }
}
