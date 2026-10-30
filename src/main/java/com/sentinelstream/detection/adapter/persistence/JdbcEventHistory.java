package com.sentinelstream.detection.adapter.persistence;

import com.sentinelstream.detection.application.EventHistory;
import com.sentinelstream.event.EnrichedEvent;
import com.sentinelstream.event.NetworkType;
import com.sentinelstream.event.Outcome;
import com.sentinelstream.event.SecurityEvent;
import com.sentinelstream.ingest.domain.enrich.EnricherChain;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;

/**
 * Rebuilds enriched events from the search table. Coordinates are not stored, so geo is looked up
 * again from the same synthetic table the pipeline uses; device fingerprint, ASN and network come
 * from the stored row.
 */
@Repository
class JdbcEventHistory implements EventHistory {

    private final JdbcTemplate jdbc;
    private final EnricherChain enricher;

    JdbcEventHistory(JdbcTemplate jdbc, EnricherChain enricher) {
        this.jdbc = jdbc;
        this.enricher = enricher;
    }

    @Override
    public List<EnrichedEvent> replay(String tenant, Instant from, Instant to, int max) {
        return jdbc.query("""
                select id, ts, ingested_at, user_name, ip, action, outcome, user_agent, device_fp, source, asn, network
                from event where tenant_id = ? and ts >= ? and ts < ? order by ts, id limit ?
                """, (rs, i) -> {
            var ev = new SecurityEvent(rs.getString("id"), tenant, rs.getTimestamp("ts").toInstant(), rs.getString("user_name"),
                    rs.getString("ip"), rs.getString("action"), Outcome.parse(rs.getString("outcome")), rs.getString("user_agent"),
                    null, rs.getString("source"), rs.getTimestamp("ingested_at").toInstant());
            var geo = enricher.enrich(ev).geo();
            Integer asn = (Integer) rs.getObject("asn");
            return new EnrichedEvent(ev, geo, asn, null, NetworkType.valueOf(rs.getString("network")), rs.getString("device_fp"));
        }, tenant, Timestamp.from(from), Timestamp.from(to), max);
    }
}
