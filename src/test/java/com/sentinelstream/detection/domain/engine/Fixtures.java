package com.sentinelstream.detection.domain.engine;

import com.sentinelstream.detection.domain.rule.RuleCompiler;
import com.sentinelstream.detection.domain.rule.Severity;
import com.sentinelstream.event.EnrichedEvent;
import com.sentinelstream.event.Outcome;
import com.sentinelstream.event.SecurityEvent;
import com.sentinelstream.ingest.domain.enrich.EnricherChain;
import com.sentinelstream.ingest.domain.enrich.IpRangeTable;

import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/** Synthetic events over the bundled documentation-range IP table. */
final class Fixtures {

    static final Instant T0 = Instant.parse("2026-10-30T08:00:00Z");
    static final String BENGALURU = "198.51.100.7";
    static final String MUMBAI_MOBILE = "198.51.100.150";
    static final String DELHI_CORP = "198.18.4.4";
    static final String FRANKFURT_HOSTING = "203.0.113.9";
    static final String NEWYORK_VPN = "203.0.113.200";

    static final EnricherChain CHAIN;
    private static final AtomicInteger SEQ = new AtomicInteger();

    static {
        try (var in = Fixtures.class.getResourceAsStream("/geo/synthetic-ip-table.csv")) {
            CHAIN = EnricherChain.standard(IpRangeTable.fromCsv(new InputStreamReader(in, StandardCharsets.UTF_8)));
        } catch (java.io.IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private Fixtures() {
    }

    static EnrichedEvent ev(long secondsAfterT0, String user, String ip, Outcome outcome) {
        return ev(secondsAfterT0, user, ip, "login", outcome, "dev-" + user);
    }

    static EnrichedEvent ev(long secondsAfterT0, String user, String ip, String action, Outcome outcome, String device) {
        Instant ts = T0.plusSeconds(secondsAfterT0);
        String id = "e" + SEQ.incrementAndGet();
        return CHAIN.enrich(new SecurityEvent(id, "acme", ts, user, ip, action, outcome, "Mozilla/5.0", device, "http", ts));
    }

    static ActiveRule rule(String id, String dsl) {
        return new ActiveRule(id, 1, id, Severity.HIGH, new RuleCompiler().compile(dsl));
    }

    static RuleSet set(ActiveRule... rules) {
        return new RuleSet(1, List.of(rules), Map.of());
    }
}
