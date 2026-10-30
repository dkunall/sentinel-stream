package com.sentinelstream.response.adapter.persistence;

import com.sentinelstream.response.application.IncidentStore;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Read models for the API. Every query is scoped by tenant. */
@Component
public class ResponseQueries {

    private final JdbcTemplate jdbc;

    ResponseQueries(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public List<Map<String, Object>> alerts(String tenant, String status, int limit) {
        String base = """
                select a.id, a.rule_id, a.rule_version, a.rule_name, a.severity, a.confidence, a.entity_kind,
                       a.entity_key, a.count, a.first_seen, a.last_seen, a.status, a.summary, a.event_ids::text as event_ids,
                       ia.incident_id
                from alert a left join incident_alert ia on ia.alert_id = a.id
                where a.tenant_id = ?
                """;
        return status == null
                ? jdbc.queryForList(base + " order by a.last_seen desc limit ?", tenant, limit)
                : jdbc.queryForList(base + " and a.status = ? order by a.last_seen desc limit ?", tenant, status, limit);
    }

    public List<IncidentStore.Incident> incidents(String tenant, String state, int limit) {
        return state == null
                ? jdbc.query("select * from incident where tenant_id = ? order by updated_at desc limit ?",
                        JdbcIncidentStore.ROW, tenant, limit)
                : jdbc.query("select * from incident where tenant_id = ? and state = ? order by updated_at desc limit ?",
                        JdbcIncidentStore.ROW, tenant, state, limit);
    }

    public List<Map<String, Object>> incidentAlerts(UUID incidentId) {
        return jdbc.queryForList("""
                select a.id, a.rule_id, a.rule_name, a.severity, a.confidence, a.count, a.first_seen, a.last_seen,
                       a.status, a.summary
                from alert a join incident_alert ia on ia.alert_id = a.id
                where ia.incident_id = ? order by a.first_seen
                """, incidentId);
    }

    public List<Map<String, Object>> transitions(UUID incidentId) {
        return jdbc.queryForList(
                "select from_state, to_state, actor, note, at from incident_transition where incident_id = ? order by id",
                incidentId);
    }

    public List<Map<String, Object>> playbookRuns(UUID incidentId) {
        return jdbc.queryForList("""
                select id, playbook_id, status, requested_by, approved_by, created_at, started_at, finished_at, error
                from playbook_run where incident_id = ? order by created_at
                """, incidentId);
    }
}
