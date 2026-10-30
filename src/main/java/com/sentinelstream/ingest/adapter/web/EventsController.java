package com.sentinelstream.ingest.adapter.web;

import com.sentinelstream.ingest.application.IngestService;
import com.sentinelstream.shared.security.Actor;
import com.sentinelstream.shared.security.Actors;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
class EventsController {

    record BatchRequest(List<Map<String, Object>> events) {
    }

    private final IngestService ingest;

    EventsController(IngestService ingest) {
        this.ingest = ingest;
    }

    /**
     * 202 even when some entries were rejected: the batch was processed, and the body says which
     * indexes to fix ({@code rejected}) or simply resend ({@code failed}). Resending a whole batch is
     * safe; ids already accepted come back as duplicates.
     */
    @PostMapping("/v1/events:batch")
    ResponseEntity<IngestService.BatchResult> batch(@RequestBody BatchRequest body) {
        Actor collector = Actors.require(Actor.COLLECTOR);
        var result = ingest.ingest(collector.tenant(), body.events());
        HttpStatus status = !result.failed().isEmpty() && result.accepted() == 0 ? HttpStatus.SERVICE_UNAVAILABLE
                : HttpStatus.ACCEPTED;
        return ResponseEntity.status(status).body(result);
    }
}
