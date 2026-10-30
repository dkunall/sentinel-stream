package com.sentinelstream.audit.application;

import com.sentinelstream.audit.domain.AuditEntry;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface AuditStore {

    List<String> tenantsWithUnsealed();

    /** Serializes sealing per tenant until the transaction ends. */
    void lockTenant(String tenant);

    List<AuditEntry> unsealed(String tenant, int max);

    Optional<Batch> lastBatch(String tenant);

    Optional<Batch> batch(String tenant, UUID id);

    /** The batch whose digest this batch chains from. */
    Optional<Batch> previousBatch(Batch b);

    boolean hasEarlierBatch(Batch b);

    List<Batch> batches(String tenant, int limit);

    void saveBatch(Batch b, List<Long> seqs);

    List<AuditEntry> entriesOf(UUID batchId);

    record Batch(UUID id, String tenant, long fromSeq, long toSeq, int entries, String prevDigest, String digest,
                 String signature, String objectKey, Instant sealedAt, Instant retainUntil) {
    }
}
