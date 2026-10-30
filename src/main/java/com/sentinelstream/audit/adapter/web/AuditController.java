package com.sentinelstream.audit.adapter.web;

import com.sentinelstream.audit.application.AuditService;
import com.sentinelstream.audit.application.AuditStore;
import com.sentinelstream.shared.security.Actor;
import com.sentinelstream.shared.security.Actors;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@RestController
class AuditController {

    private final AuditService audit;

    AuditController(AuditService audit) {
        this.audit = audit;
    }

    @GetMapping("/v1/audit/batches")
    List<AuditStore.Batch> batches(@RequestParam(defaultValue = "20") int limit) {
        Actor actor = Actors.require(Actor.ADMIN);
        return audit.batches(actor.tenant(), Math.max(1, Math.min(limit, 200)));
    }

    /** Seals what is pending now instead of waiting for the schedule; handy for demos and tests. */
    @PostMapping("/v1/audit/batches:seal")
    List<AuditStore.Batch> sealNow() {
        Actor actor = Actors.require(Actor.ADMIN);
        return audit.seal(actor.tenant()).map(List::of).orElse(List.of());
    }

    @GetMapping("/v1/audit/batches/{id}/verify")
    AuditService.Verification verify(@PathVariable UUID id) {
        Actor actor = Actors.require(Actor.ADMIN);
        return audit.verify(actor.tenant(), id);
    }

    @GetMapping(value = "/v1/audit/public-key", produces = MediaType.TEXT_PLAIN_VALUE)
    String publicKey() {
        return audit.publicKeyPem();
    }
}
