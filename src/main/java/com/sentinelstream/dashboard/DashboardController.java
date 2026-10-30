package com.sentinelstream.dashboard;

import com.sentinelstream.shared.error.ApiException;
import com.sentinelstream.shared.security.Actors;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A read model over the tables the other modules write. The three counts (signals, alerts,
 * incidents) show how much dedup and correlation reduce what an analyst has to look at, and the
 * latency percentiles come from stored timestamps, not from this process's in-memory timer.
 */
@RestController
class DashboardController {

    record HourCount(Instant hour, String outcome, long events) {
    }

    record Latency(long samples, Double p50Ms, Double p95Ms, Double p99Ms) {
    }

    record Summary(Instant from, Instant to, List<HourCount> eventsPerHour, Map<String, Long> alertsBySeverity,
                   Map<String, Long> incidentsByState, long signals, long alerts, long incidentsOpened,
                   Latency detectionLatency) {
    }

    private final JdbcTemplate jdbc;
    private final Clock clock;

    DashboardController(JdbcTemplate jdbc, Clock clock) {
        this.jdbc = jdbc;
        this.clock = clock;
    }

    @GetMapping("/v1/dashboard/summary")
    Summary summary(@RequestParam(defaultValue = "24") int hours) {
        if (hours < 1 || hours > 168) {
            throw ApiException.invalid("hours must be 1..168");
        }
        String tenant = Actors.current().tenant();
        Instant to = clock.instant();
        Instant from = to.minus(Duration.ofHours(hours));
        Timestamp f = Timestamp.from(from);
        Timestamp t = Timestamp.from(to);
        var perHour = jdbc.query("""
                select date_trunc('hour', ts) as h, outcome, count(*) from event
                where tenant_id = ? and ts >= ? and ts < ? group by 1, 2 order by 1, 2
                """, (rs, i) -> new HourCount(rs.getTimestamp(1).toInstant(), rs.getString(2), rs.getLong(3)), tenant, f, t);
        Map<String, Long> bySeverity = counts("""
                select severity, count(*) from alert where tenant_id = ? and last_seen >= ? and last_seen < ? group by 1
                """, tenant, f, t);
        Map<String, Long> byState = counts("select state, count(*) from incident where tenant_id = ? group by 1", tenant);
        long signals = count("select count(*) from alert_signal where tenant_id = ? and received_at >= ? and received_at < ?", tenant, f, t);
        long alerts = count("select count(*) from alert where tenant_id = ? and created_at >= ? and created_at < ?", tenant, f, t);
        long incidents = count("select count(*) from incident where tenant_id = ? and opened_at >= ? and opened_at < ?", tenant, f, t);
        Latency latency = jdbc.queryForObject("""
                select count(*),
                       percentile_cont(0.5) within group (order by ms),
                       percentile_cont(0.95) within group (order by ms),
                       percentile_cont(0.99) within group (order by ms)
                from (select extract(epoch from (received_at - ingested_at)) * 1000 as ms
                      from alert_signal where tenant_id = ? and received_at >= ? and received_at < ?) s
                """, (rs, i) -> new Latency(rs.getLong(1), (Double) rs.getObject(2), (Double) rs.getObject(3),
                (Double) rs.getObject(4)), tenant, f, t);
        return new Summary(from, to, perHour, bySeverity, byState, signals, alerts, incidents, latency);
    }

    private Map<String, Long> counts(String sql, Object... args) {
        Map<String, Long> out = new LinkedHashMap<>();
        jdbc.query(sql, rs -> {
            out.put(rs.getString(1), rs.getLong(2));
        }, args);
        return out;
    }

    private long count(String sql, Object... args) {
        Long n = jdbc.queryForObject(sql, Long.class, args);
        return n == null ? 0 : n;
    }
}
