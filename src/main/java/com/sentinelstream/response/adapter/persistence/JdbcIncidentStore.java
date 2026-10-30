package com.sentinelstream.response.adapter.persistence;

import com.sentinelstream.response.application.IncidentStore;
import com.sentinelstream.response.domain.IncidentState;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
class JdbcIncidentStore implements IncidentStore {

    static final RowMapper<Incident> ROW = (rs, i) -> new Incident(
            rs.getObject("id", UUID.class), rs.getString("tenant_id"), rs.getString("entity_kind"),
            rs.getString("entity_key"), IncidentState.valueOf(rs.getString("state")), rs.getString("severity"),
            rs.getString("title"), rs.getTimestamp("opened_at").toInstant(), rs.getTimestamp("last_alert_at").toInstant(),
            rs.getTimestamp("updated_at").toInstant(), rs.getInt("version"));

    private final JdbcTemplate jdbc;

    JdbcIncidentStore(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public Optional<Incident> find(String tenant, UUID id) {
        return jdbc.query("select * from incident where tenant_id = ? and id = ?", ROW, tenant, id).stream().findFirst();
    }

    @Override
    public boolean hasSucceededPlaybook(UUID incidentId) {
        return Boolean.TRUE.equals(jdbc.queryForObject(
                "select exists (select 1 from playbook_run where incident_id = ? and status = 'SUCCEEDED')",
                Boolean.class, incidentId));
    }

    @Override
    public boolean move(UUID id, IncidentState from, int version, IncidentState to) {
        return jdbc.update("""
                update incident set state = ?, version = version + 1, updated_at = now()
                where id = ? and state = ? and version = ?
                """, to.name(), id, from.name(), version) == 1;
    }

    @Override
    public void logTransition(UUID id, IncidentState from, IncidentState to, String actor, String note) {
        jdbc.update("insert into incident_transition (incident_id, from_state, to_state, actor, note) values (?, ?, ?, ?, ?)",
                id, from.name(), to.name(), actor, note);
    }

    @Override
    public void setAlertStatus(UUID incidentId, String status) {
        jdbc.update("update alert set status = ? where id in (select alert_id from incident_alert where incident_id = ?)",
                status, incidentId);
    }
}
