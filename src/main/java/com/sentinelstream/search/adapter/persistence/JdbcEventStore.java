package com.sentinelstream.search.adapter.persistence;

import com.sentinelstream.event.EnrichedEvent;
import com.sentinelstream.search.application.EventQuery;
import com.sentinelstream.search.application.EventRow;
import com.sentinelstream.search.application.EventStore;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Repository
class JdbcEventStore implements EventStore {

    private static final String INSERT = """
            insert into event (tenant_id, id, ts, ingested_at, user_name, ip, action, outcome, user_agent, device_fp,
                               source, country, city, asn, network)
            values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            on conflict do nothing
            """;

    private final JdbcTemplate jdbc;

    JdbcEventStore(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public int store(List<EnrichedEvent> events) {
        if (events.isEmpty()) {
            return 0;
        }
        int[][] counts = jdbc.batchUpdate(INSERT, events, 500, (ps, e) -> {
            var ev = e.event();
            ps.setString(1, ev.tenant());
            ps.setString(2, ev.id());
            ps.setTimestamp(3, Timestamp.from(ev.ts()));
            ps.setTimestamp(4, Timestamp.from(ev.ingestedAt()));
            ps.setString(5, ev.user());
            ps.setString(6, ev.ip());
            ps.setString(7, ev.action());
            ps.setString(8, ev.outcome().dsl());
            ps.setString(9, ev.userAgent());
            ps.setString(10, e.deviceFingerprint());
            ps.setString(11, ev.source());
            ps.setString(12, e.geo() == null ? null : e.geo().country());
            ps.setString(13, e.geo() == null ? null : e.geo().city());
            if (e.asn() == null) {
                ps.setNull(14, Types.INTEGER);
            } else {
                ps.setInt(14, e.asn());
            }
            ps.setString(15, e.network() == null ? "UNKNOWN" : e.network().name());
        });
        return Arrays.stream(counts).flatMapToInt(Arrays::stream).map(c -> Math.max(c, 0)).sum();
    }

    @Override
    public List<EventRow> search(EventQuery q) {
        StringBuilder sql = new StringBuilder("""
                select id, ts, ingested_at, user_name, ip, action, outcome, user_agent, device_fp, source, country, city,
                       asn, network
                from event where tenant_id = ? and ts >= ? and ts < ?
                """);
        List<Object> args = new ArrayList<>(List.of(q.tenant(), Timestamp.from(q.from()), Timestamp.from(q.to())));
        if (q.user() != null) {
            sql.append(" and user_name = ?");
            args.add(q.user().toLowerCase());
        }
        if (q.ip() != null) {
            sql.append(" and ip = ?");
            args.add(q.ip());
        }
        if (q.action() != null) {
            sql.append(" and action = ?");
            args.add(q.action());
        }
        if (q.outcome() != null) {
            sql.append(" and outcome = ?");
            args.add(q.outcome());
        }
        if (q.after() != null) {
            sql.append(" and (ts, id) < (?, ?)");
            args.add(Timestamp.from(q.after().ts()));
            args.add(q.after().id());
        }
        sql.append(" order by ts desc, id desc limit ?");
        args.add(q.limit());
        return jdbc.query(sql.toString(), JdbcEventStore::row, args.toArray());
    }

    private static EventRow row(ResultSet rs, int i) throws SQLException {
        Integer asn = rs.getObject(13) == null ? null : rs.getInt(13);
        return new EventRow(rs.getString(1), rs.getTimestamp(2).toInstant(), rs.getTimestamp(3).toInstant(),
                rs.getString(4), rs.getString(5), rs.getString(6), rs.getString(7), rs.getString(8), rs.getString(9),
                rs.getString(10), rs.getString(11), rs.getString(12), asn, rs.getString(14));
    }
}
