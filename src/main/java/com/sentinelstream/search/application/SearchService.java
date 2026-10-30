package com.sentinelstream.search.application;

import com.sentinelstream.search.domain.PiiMasker;
import com.sentinelstream.search.domain.SearchCursor;
import com.sentinelstream.shared.audit.AuditRecorder;
import com.sentinelstream.shared.error.ApiException;
import com.sentinelstream.shared.security.Actor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
public class SearchService {

    static final int MAX_LIMIT = 200;
    static final Duration DEFAULT_WINDOW = Duration.ofHours(24);
    static final Duration MAX_WINDOW = Duration.ofDays(31);

    public record Page(List<EventRow> events, String nextCursor, boolean masked) {
    }

    private final EventStore store;
    private final AuditRecorder audit;
    private final Clock clock;

    SearchService(EventStore store, AuditRecorder audit, Clock clock) {
        this.store = store;
        this.audit = audit;
        this.clock = clock;
    }

    /**
     * Masked unless the caller holds the PII scope and asks for raw values; every unmasked search is
     * audited with its filters, so "who looked at which user's raw events" has an answer.
     */
    @Transactional
    public Page search(Actor actor, Map<String, String> filters, Instant from, Instant to, Integer limit, String cursor,
                       boolean unmasked) {
        Instant end = to != null ? to : clock.instant();
        Instant start = from != null ? from : end.minus(DEFAULT_WINDOW);
        if (!start.isBefore(end)) {
            throw ApiException.invalid("from must be before to");
        }
        if (Duration.between(start, end).compareTo(MAX_WINDOW) > 0) {
            throw ApiException.invalid("search window is at most 31 days");
        }
        int n = limit == null ? 50 : limit;
        if (n < 1 || n > MAX_LIMIT) {
            throw ApiException.invalid("limit must be 1.." + MAX_LIMIT);
        }
        SearchCursor after;
        try {
            after = cursor == null || cursor.isBlank() ? null : SearchCursor.decode(cursor);
        } catch (IllegalArgumentException e) {
            throw ApiException.invalid(e.getMessage());
        }
        if (unmasked && !actor.has(Actor.PII)) {
            throw ApiException.forbidden("forbidden", "unmasked search requires scope " + Actor.PII);
        }
        var q = new EventQuery(actor.tenant(), filters.get("user"), filters.get("ip"), filters.get("action"),
                filters.get("outcome"), start, end, n + 1, after);
        List<EventRow> rows = store.search(q);
        String next = null;
        if (rows.size() > n) {
            rows = rows.subList(0, n);
            EventRow last = rows.getLast();
            next = new SearchCursor(last.ts(), last.id()).encode();
        }
        if (unmasked) {
            Map<String, Object> detail = new LinkedHashMap<>(filters);
            detail.put("from", start.toString());
            detail.put("to", end.toString());
            detail.put("returned", rows.size());
            audit.record(actor.tenant(), actor.subject(), "events.search.unmasked", "events", detail);
            return new Page(List.copyOf(rows), next, false);
        }
        return new Page(rows.stream().map(r -> r.masked(PiiMasker::user, PiiMasker::ip)).toList(), next, true);
    }
}
