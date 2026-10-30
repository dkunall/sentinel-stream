package com.sentinelstream.response.adapter.persistence;

import com.sentinelstream.detection.domain.engine.Signal;
import com.sentinelstream.detection.domain.rule.Severity;
import com.sentinelstream.response.application.CorrelationStore;
import com.sentinelstream.shared.Json;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Repository
class JdbcCorrelationStore implements CorrelationStore {

    private static final int MAX_EVENT_IDS = 50;

    private final JdbcTemplate jdbc;

    JdbcCorrelationStore(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public boolean recordSignal(Signal s, UUID alertId) {
        return jdbc.update("""
                insert into alert_signal (signal_id, tenant_id, alert_id, event_ts, ingested_at)
                values (?, ?, ?, ?, ?) on conflict (signal_id) do nothing
                """, s.id(), s.tenant(), alertId, Timestamp.from(s.ts()), Timestamp.from(s.ingestedAt())) == 1;
    }

    @Override
    public boolean upsertAlert(UUID alertId, String fingerprint, Signal s) {
        String ids;
        try {
            ids = Json.MAPPER.writeValueAsString(s.eventIds());
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
        return Boolean.TRUE.equals(jdbc.queryForObject("""
                insert into alert (id, tenant_id, fingerprint, rule_id, rule_version, rule_name, severity, confidence,
                                   entity_kind, entity_key, count, first_seen, last_seen, status, summary, event_ids)
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, 'OPEN', ?, ?::jsonb)
                on conflict (fingerprint) do update set
                    count = alert.count + 1,
                    first_seen = least(alert.first_seen, excluded.first_seen),
                    last_seen = greatest(alert.last_seen, excluded.last_seen),
                    confidence = case when excluded.confidence = 'HIGH' then 'HIGH' else alert.confidence end,
                    event_ids = case when jsonb_array_length(alert.event_ids) < ?
                                     then alert.event_ids || excluded.event_ids else alert.event_ids end
                returning (xmax = 0)
                """, Boolean.class, alertId, s.tenant(), fingerprint, s.ruleId(), s.ruleVersion(), s.ruleName(),
                s.severity().name(), s.confidence().name(), s.entityKind().name(), s.entityKey(),
                Timestamp.from(s.ts()), Timestamp.from(s.ts()), s.summary(), ids, MAX_EVENT_IDS));
    }

    @Override
    public Optional<UUID> incidentOfAlert(UUID alertId) {
        return jdbc.queryForList("select incident_id from incident_alert where alert_id = ?", UUID.class, alertId)
                .stream().findFirst();
    }

    @Override
    public void lockEntity(String tenant, String entityKind, String entityKey) {
        jdbc.queryForObject("select pg_advisory_xact_lock(hashtextextended(?, 0))", Object.class,
                "incident|" + tenant + "|" + entityKind + "|" + entityKey);
    }

    @Override
    public Optional<OpenIncident> latestOpenIncident(String tenant, String entityKind, String entityKey, Instant notBefore) {
        return jdbc.query("""
                select id, severity from incident
                where tenant_id = ? and entity_kind = ? and entity_key = ?
                  and state not in ('FALSE_POSITIVE', 'RESOLVED') and last_alert_at >= ?
                order by last_alert_at desc limit 1
                """, (rs, i) -> new OpenIncident(rs.getObject(1, UUID.class), Severity.valueOf(rs.getString(2))),
                tenant, entityKind, entityKey, Timestamp.from(notBefore)).stream().findFirst();
    }

    @Override
    public UUID openIncident(Signal s) {
        UUID id = UUID.randomUUID();
        Timestamp ts = Timestamp.from(s.ts());
        jdbc.update("""
                insert into incident (id, tenant_id, entity_kind, entity_key, state, severity, title, opened_at,
                                      last_alert_at, updated_at)
                values (?, ?, ?, ?, 'NEW', ?, ?, now(), ?, now())
                """, id, s.tenant(), s.entityKind().name(), s.entityKey(), s.severity().name(),
                s.ruleName() + " on " + s.entityKind().name().toLowerCase() + " " + s.entityKey(), ts);
        jdbc.update("insert into incident_transition (incident_id, from_state, to_state, actor, note) values (?, '-', 'NEW', ?, ?)",
                id, "system:correlator", s.summary());
        return id;
    }

    @Override
    public void attach(UUID incidentId, UUID alertId) {
        jdbc.update("insert into incident_alert (incident_id, alert_id) values (?, ?) on conflict do nothing", incidentId, alertId);
    }

    @Override
    public void touchIncident(UUID incidentId, Instant alertAt, Severity severity) {
        jdbc.update("""
                update incident set last_alert_at = greatest(last_alert_at, ?), updated_at = now(),
                    severity = case when array_position(array['LOW','MEDIUM','HIGH','CRITICAL'], ?)
                                       > array_position(array['LOW','MEDIUM','HIGH','CRITICAL'], severity)
                                    then ? else severity end
                where id = ?
                """, Timestamp.from(alertAt), severity.name(), severity.name(), incidentId);
    }
}
