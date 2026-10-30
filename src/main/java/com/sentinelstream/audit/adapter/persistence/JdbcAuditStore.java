package com.sentinelstream.audit.adapter.persistence;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.sentinelstream.audit.application.AuditStore;
import com.sentinelstream.audit.domain.AuditEntry;
import com.sentinelstream.shared.Json;
import com.sentinelstream.shared.audit.AuditRecorder;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/** Audit rows and batches. Recording joins the caller's transaction, so an entry commits with its change. */
@Repository
class JdbcAuditStore implements AuditStore, AuditRecorder {

    private static final RowMapper<AuditEntry> ENTRY = (rs, i) -> new AuditEntry(rs.getLong("seq"), rs.getString("tenant_id"),
            rs.getTimestamp("at").toInstant(), rs.getString("actor"), rs.getString("action"), rs.getString("target"),
            rs.getString("detail"));
    private static final RowMapper<Batch> BATCH = (rs, i) -> new Batch(rs.getObject("id", UUID.class), rs.getString("tenant_id"),
            rs.getLong("from_seq"), rs.getLong("to_seq"), rs.getInt("entries"), rs.getString("prev_digest"),
            rs.getString("digest"), rs.getString("signature"), rs.getString("object_key"),
            rs.getTimestamp("sealed_at").toInstant(), rs.getTimestamp("retain_until").toInstant());
    private static final String ENTRY_COLS = "seq, tenant_id, at, actor, action, target, detail::text as detail";

    private final JdbcTemplate jdbc;

    JdbcAuditStore(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public void record(String tenant, String actor, String action, String target, Map<String, ?> detail) {
        String json;
        try {
            json = Json.MAPPER.writeValueAsString(detail);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("audit detail is not serializable", e);
        }
        jdbc.update("insert into audit_log (tenant_id, actor, action, target, detail) values (?, ?, ?, ?, ?::jsonb)",
                tenant, actor, action, target, json);
    }

    @Override
    public List<String> tenantsWithUnsealed() {
        return jdbc.queryForList("select distinct tenant_id from audit_log where batch_id is null", String.class);
    }

    @Override
    public void lockTenant(String tenant) {
        jdbc.queryForObject("select pg_advisory_xact_lock(hashtextextended(?, 0))", Object.class, "audit-seal|" + tenant);
    }

    @Override
    public List<AuditEntry> unsealed(String tenant, int max) {
        return jdbc.query("select " + ENTRY_COLS + " from audit_log where tenant_id = ? and batch_id is null order by seq limit ?",
                ENTRY, tenant, max);
    }

    @Override
    public Optional<Batch> lastBatch(String tenant) {
        return jdbc.query("select * from audit_batch where tenant_id = ? order by sealed_at desc, to_seq desc limit 1", BATCH, tenant)
                .stream().findFirst();
    }

    @Override
    public Optional<Batch> batch(String tenant, UUID id) {
        return jdbc.query("select * from audit_batch where tenant_id = ? and id = ?", BATCH, tenant, id).stream().findFirst();
    }

    @Override
    public Optional<Batch> previousBatch(Batch b) {
        return jdbc.query("select * from audit_batch where tenant_id = ? and digest = ? and id <> ?", BATCH,
                b.tenant(), b.prevDigest(), b.id()).stream().findFirst();
    }

    @Override
    public boolean hasEarlierBatch(Batch b) {
        return Boolean.TRUE.equals(jdbc.queryForObject(
                "select exists (select 1 from audit_batch where tenant_id = ? and sealed_at < ?)", Boolean.class,
                b.tenant(), Timestamp.from(b.sealedAt())));
    }

    @Override
    public List<Batch> batches(String tenant, int limit) {
        return jdbc.query("select * from audit_batch where tenant_id = ? order by sealed_at desc, to_seq desc limit ?", BATCH, tenant, limit);
    }

    @Override
    public void saveBatch(Batch b, List<Long> seqs) {
        jdbc.update("""
                insert into audit_batch (id, tenant_id, from_seq, to_seq, entries, prev_digest, digest, signature, object_key,
                                         sealed_at, retain_until)
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, b.id(), b.tenant(), b.fromSeq(), b.toSeq(), b.entries(), b.prevDigest(), b.digest(), b.signature(),
                b.objectKey(), Timestamp.from(b.sealedAt()), Timestamp.from(b.retainUntil()));
        jdbc.batchUpdate("update audit_log set batch_id = ? where seq = ? and batch_id is null", seqs, 500, (ps, seq) -> {
            ps.setObject(1, b.id());
            ps.setLong(2, seq);
        });
    }

    @Override
    public List<AuditEntry> entriesOf(UUID batchId) {
        return jdbc.query("select " + ENTRY_COLS + " from audit_log where batch_id = ? order by seq", ENTRY, batchId);
    }
}
