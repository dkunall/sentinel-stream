package com.sentinelstream.detection.adapter.persistence;

import com.sentinelstream.detection.application.RuleStore;
import com.sentinelstream.detection.domain.rule.Severity;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

@Repository
class JdbcRuleStore implements RuleStore {

    private static final RowMapper<StoredRule> ROW = (rs, i) -> new StoredRule(rs.getString("tenant_id"), rs.getString("id"),
            rs.getInt("version"), rs.getString("name"), rs.getString("dsl"), rs.getString("canonical"),
            rs.getString("compiled_hash"), Severity.valueOf(rs.getString("severity")), rs.getBoolean("enabled"),
            rs.getString("created_by"), rs.getTimestamp("created_at").toInstant());
    private static final String LATEST = """
            select distinct on (tenant_id, id) * from rule %s order by tenant_id, id, version desc
            """;

    private final JdbcTemplate jdbc;

    JdbcRuleStore(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public long changeVersion() {
        return jdbc.queryForObject("select version from ruleset_version where id = 1", Long.class);
    }

    @Override
    public void bumpChangeVersion() {
        jdbc.update("update ruleset_version set version = version + 1 where id = 1");
    }

    @Override
    public List<StoredRule> latestVersions() {
        return jdbc.query(LATEST.formatted(""), ROW);
    }

    @Override
    public List<StoredRule> latestVersions(String tenant) {
        return jdbc.query(LATEST.formatted("where tenant_id = ?"), ROW, tenant);
    }

    @Override
    public Optional<StoredRule> latest(String tenant, String id) {
        return jdbc.query("select * from rule where tenant_id = ? and id = ? order by version desc limit 1", ROW, tenant, id)
                .stream().findFirst();
    }

    @Override
    public boolean insert(StoredRule r) {
        try {
            jdbc.update("""
                    insert into rule (tenant_id, id, version, name, dsl, canonical, compiled_hash, severity, enabled, created_by, created_at)
                    values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, r.tenant(), r.id(), r.version(), r.name(), r.dsl(), r.canonical(), r.hash(), r.severity().name(),
                    r.enabled(), r.createdBy(), Timestamp.from(r.createdAt()));
            return true;
        } catch (DuplicateKeyException e) {
            return false;
        }
    }

    @Override
    public List<IocEntry> iocs() {
        return jdbc.query("select tenant_id, list_name, kind, value from ioc_entry",
                (rs, i) -> new IocEntry(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4)));
    }

    @Override
    public List<IocEntry> iocs(String tenant) {
        return jdbc.query("select tenant_id, list_name, kind, value from ioc_entry where tenant_id = ? order by list_name, kind, value",
                (rs, i) -> new IocEntry(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4)), tenant);
    }

    @Override
    public int addIocs(String tenant, String list, String kind, Collection<String> values) {
        int[][] counts = jdbc.batchUpdate("""
                insert into ioc_entry (tenant_id, list_name, kind, value) values (?, ?, ?, ?) on conflict do nothing
                """, values, 500, (ps, v) -> {
            ps.setString(1, tenant);
            ps.setString(2, list);
            ps.setString(3, kind);
            ps.setString(4, v);
        });
        return Arrays.stream(counts).flatMapToInt(Arrays::stream).map(c -> Math.max(c, 0)).sum();
    }

    @Override
    public int removeIoc(String tenant, String list, String kind, String value) {
        return jdbc.update("delete from ioc_entry where tenant_id = ? and list_name = ? and kind = ? and value = ?",
                tenant, list, kind, value);
    }
}
