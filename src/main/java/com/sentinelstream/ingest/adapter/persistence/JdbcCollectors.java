package com.sentinelstream.ingest.adapter.persistence;

import com.sentinelstream.shared.security.CollectorKeyFilter;
import com.sentinelstream.shared.security.CollectorKeys;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public class JdbcCollectors implements CollectorKeys {

    private static final SecureRandom RANDOM = new SecureRandom();

    public record Collector(UUID id, String name, String createdBy, Instant createdAt) {
    }

    public record Issued(UUID id, String name, String apiKey) {
    }

    private final JdbcClient jdbc;

    JdbcCollectors(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public Optional<CollectorIdentity> byHash(String sha256Hex) {
        return jdbc.sql("select tenant_id, id, name from collector where key_hash = ? and revoked_at is null")
                .param(sha256Hex)
                .query((rs, i) -> new CollectorIdentity(rs.getString(1), rs.getString(2), rs.getString(3)))
                .optional();
    }

    /** Returns the key once; only its hash is kept. */
    public Issued issue(String tenant, String name, String createdBy) {
        byte[] secret = new byte[32];
        RANDOM.nextBytes(secret);
        String key = "ssk_" + Base64.getUrlEncoder().withoutPadding().encodeToString(secret);
        UUID id = jdbc.sql("insert into collector (tenant_id, name, key_hash, created_by) values (?, ?, ?, ?) returning id")
                .params(tenant, name, CollectorKeyFilter.sha256(key), createdBy)
                .query(UUID.class).single();
        return new Issued(id, name, key);
    }

    public List<Collector> list(String tenant) {
        return jdbc.sql("select id, name, created_by, created_at from collector where tenant_id = ? and revoked_at is null order by created_at")
                .param(tenant)
                .query((rs, i) -> new Collector(rs.getObject(1, UUID.class), rs.getString(2), rs.getString(3),
                        rs.getTimestamp(4).toInstant()))
                .list();
    }
}
