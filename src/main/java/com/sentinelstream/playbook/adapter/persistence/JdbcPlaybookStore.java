package com.sentinelstream.playbook.adapter.persistence;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.sentinelstream.playbook.application.PlaybookStore;
import com.sentinelstream.playbook.domain.RunStatus;
import com.sentinelstream.playbook.domain.Step;
import com.sentinelstream.shared.Json;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
class JdbcPlaybookStore implements PlaybookStore {

    private static final TypeReference<List<Step>> STEPS = new TypeReference<>() {
    };
    private static final TypeReference<List<String>> STRINGS = new TypeReference<>() {
    };

    private final RowMapper<Playbook> playbookRow = (rs, i) -> new Playbook(rs.getString("tenant_id"), rs.getString("id"),
            rs.getString("name"), read(rs.getString("trigger_rules"), STRINGS), read(rs.getString("steps"), STEPS),
            rs.getBoolean("needs_approval"));
    private static final RowMapper<Run> RUN = (rs, i) -> new Run(rs.getObject("id", UUID.class), rs.getString("tenant_id"),
            rs.getString("playbook_id"), rs.getObject("incident_id", UUID.class), RunStatus.valueOf(rs.getString("status")),
            rs.getString("requested_by"), rs.getString("approved_by"), instant(rs.getTimestamp("created_at")),
            instant(rs.getTimestamp("started_at")), instant(rs.getTimestamp("finished_at")), rs.getString("error"));

    private final JdbcTemplate jdbc;

    JdbcPlaybookStore(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public void savePlaybook(Playbook p) {
        jdbc.update("""
                insert into playbook (tenant_id, id, name, trigger_rules, steps, needs_approval) values (?, ?, ?, ?::jsonb, ?::jsonb, ?)
                on conflict (tenant_id, id) do update set name = excluded.name, trigger_rules = excluded.trigger_rules,
                    steps = excluded.steps, needs_approval = excluded.needs_approval
                """, p.tenant(), p.id(), p.name(), write(p.triggerRules()), write(p.steps()), p.needsApproval());
    }

    @Override
    public Optional<Playbook> playbook(String tenant, String id) {
        return jdbc.query("select * from playbook where tenant_id = ? and id = ?", playbookRow, tenant, id).stream().findFirst();
    }

    @Override
    public List<Playbook> playbooks(String tenant) {
        return jdbc.query("select * from playbook where tenant_id = ? order by id", playbookRow, tenant);
    }

    @Override
    public boolean createRun(Run r) {
        try {
            jdbc.update("""
                    insert into playbook_run (id, tenant_id, playbook_id, incident_id, status, requested_by, created_at)
                    values (?, ?, ?, ?, ?, ?, ?)
                    """, r.id(), r.tenant(), r.playbookId(), r.incidentId(), r.status().name(), r.requestedBy(),
                    Timestamp.from(r.createdAt()));
            return true;
        } catch (DuplicateKeyException e) {
            return false;
        }
    }

    @Override
    public Optional<Run> run(String tenant, UUID id) {
        return jdbc.query("select * from playbook_run where tenant_id = ? and id = ?", RUN, tenant, id).stream().findFirst();
    }

    @Override
    public boolean decide(UUID runId, boolean approve, String approver) {
        return jdbc.update("update playbook_run set status = ?, approved_by = ? where id = ? and status = 'PENDING_APPROVAL'",
                approve ? "APPROVED" : "REJECTED", approver, runId) == 1;
    }

    @Override
    public Optional<Run> claimNext(Duration stale) {
        return jdbc.query("""
                update playbook_run set status = 'RUNNING', started_at = now()
                where id = (select id from playbook_run
                            where status = 'APPROVED'
                               or (status = 'RUNNING' and started_at < now() - make_interval(secs => ?))
                            order by created_at limit 1 for update skip locked)
                returning *
                """, RUN, (double) stale.toSeconds()).stream().findFirst();
    }

    @Override
    public boolean stepRecorded(UUID runId, int idx) {
        return Boolean.TRUE.equals(jdbc.queryForObject(
                "select exists (select 1 from playbook_step_result where run_id = ? and idx = ?)", Boolean.class, runId, idx));
    }

    @Override
    public void recordStep(UUID runId, int idx, String kind, String status, String detail) {
        jdbc.update("insert into playbook_step_result (run_id, idx, kind, status, detail) values (?, ?, ?, ?, ?) on conflict do nothing",
                runId, idx, kind, status, detail);
    }

    @Override
    public boolean finish(UUID runId, RunStatus status, String error) {
        return jdbc.update("update playbook_run set status = ?, finished_at = now(), error = ? where id = ? and status = 'RUNNING'",
                status.name(), error, runId) == 1;
    }

    @Override
    public boolean lockDemoAccount(String tenant, String user, UUID runId) {
        return Boolean.TRUE.equals(jdbc.queryForObject("""
                with before as (select locked from demo_account where tenant_id = ? and user_name = ?)
                insert into demo_account (tenant_id, user_name, locked, locked_at, locked_by_run) values (?, ?, true, now(), ?)
                on conflict (tenant_id, user_name) do update set locked = true,
                    locked_at = coalesce(demo_account.locked_at, excluded.locked_at),
                    locked_by_run = coalesce(demo_account.locked_by_run, excluded.locked_by_run)
                returning not coalesce((select locked from before), false)
                """, Boolean.class, tenant, user, tenant, user, runId));
    }

    @Override
    public boolean enqueueWebhook(String tenant, UUID runId, String dedupKey, String url, String payloadJson) {
        return jdbc.update("""
                insert into outbox (tenant_id, run_id, dedup_key, target_url, payload) values (?, ?, ?, ?, ?::jsonb)
                on conflict (dedup_key) do nothing
                """, tenant, runId, dedupKey, url, payloadJson) == 1;
    }

    private static Instant instant(Timestamp t) {
        return t == null ? null : t.toInstant();
    }

    private static <T> T read(String json, TypeReference<T> type) {
        try {
            return Json.MAPPER.readValue(json, type);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("corrupt playbook json", e);
        }
    }

    private static String write(Object o) {
        try {
            return Json.MAPPER.writeValueAsString(o);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }
}
