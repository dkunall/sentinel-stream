package com.sentinelstream.audit.application;

import com.sentinelstream.audit.domain.AuditChain;
import com.sentinelstream.audit.domain.AuditEntry;
import com.sentinelstream.audit.domain.Ed25519Signer;
import com.sentinelstream.shared.config.SentinelProperties;
import com.sentinelstream.shared.error.ApiException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeSet;
import java.util.UUID;

/**
 * Seals unsealed audit rows into signed, hash-chained batches, writes each batch to retention-locked
 * object storage, and verifies a batch against both its object and the live rows.
 */
@Service
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger(AuditService.class);

    private final AuditStore store;
    private final LockedObjectStore objects;
    private final Ed25519Signer signer;
    private final TransactionTemplate tx;
    private final Clock clock;
    private final int maxBatch;
    private final Duration retention;

    AuditService(AuditStore store, LockedObjectStore objects, Ed25519Signer signer, TransactionTemplate tx, Clock clock,
                 SentinelProperties props) {
        this.store = store;
        this.objects = objects;
        this.signer = signer;
        this.tx = tx;
        this.clock = clock;
        this.maxBatch = props.audit().maxBatch();
        this.retention = Duration.ofDays(props.audit().retentionDays());
    }

    @Scheduled(fixedDelayString = "${sentinel.audit.seal-every}", initialDelayString = "${sentinel.audit.seal-every}")
    public void sealAll() {
        for (String tenant : store.tenantsWithUnsealed()) {
            try {
                while (seal(tenant).isPresent()) {
                    // keep going while full batches remain
                }
            } catch (RuntimeException e) {
                log.warn("sealing audit batch for {} failed, will retry: {}", tenant, e.toString());
            }
        }
    }

    /**
     * Seals up to maxBatch rows. The object is written before the transaction commits: if the write
     * fails nothing is sealed; if the commit fails afterwards an unreferenced object is left behind,
     * which verification never reads.
     */
    public Optional<AuditStore.Batch> seal(String tenant) {
        return tx.execute(status -> {
            store.lockTenant(tenant);
            List<AuditEntry> entries = store.unsealed(tenant, maxBatch);
            if (entries.isEmpty()) {
                return Optional.<AuditStore.Batch>empty();
            }
            String prev = store.lastBatch(tenant).map(AuditStore.Batch::digest).orElse(AuditChain.GENESIS);
            String digest = AuditChain.digest(prev, entries);
            UUID id = UUID.randomUUID();
            String signature = signer.sign(AuditChain.signedMessage(id.toString(), tenant, prev, digest, entries.size()));
            Instant now = clock.instant();
            String key = "audit/" + tenant + "/" + id + ".tsv";
            Instant until = now.plus(retention);
            objects.putLocked(key, render(id, tenant, prev, digest, signature, entries), until);
            var batch = new AuditStore.Batch(id, tenant, entries.getFirst().seq(), entries.getLast().seq(), entries.size(),
                    prev, digest, signature, key, now, until);
            store.saveBatch(batch, entries.stream().map(AuditEntry::seq).toList());
            return Optional.of(batch);
        });
    }

    public List<AuditStore.Batch> batches(String tenant, int limit) {
        return store.batches(tenant, limit);
    }

    public String publicKeyPem() {
        return signer.publicKeyPem();
    }

    public record Verification(UUID batchId, boolean valid, boolean signatureOk, boolean objectDigestOk, boolean chainLinkOk,
                               String objectLockMode, Instant objectRetainUntil, List<Long> modifiedSeqs,
                               List<Long> missingSeqs, List<Long> extraSeqs) {
    }

    public Verification verify(String tenant, UUID id) {
        var b = store.batch(tenant, id).orElseThrow(() -> ApiException.notFound("audit batch"));
        boolean sigOk = signer.verify(AuditChain.signedMessage(b.id().toString(), b.tenant(), b.prevDigest(), b.digest(), b.entries()),
                b.signature());
        boolean linkOk = AuditChain.GENESIS.equals(b.prevDigest())
                ? !store.hasEarlierBatch(b)
                : store.previousBatch(b).isPresent();

        List<AuditEntry> fromObject = parse(objects.get(b.objectKey()));
        boolean objectOk = fromObject.size() == b.entries() && AuditChain.digest(b.prevDigest(), fromObject).equals(b.digest());

        Map<Long, String> sealed = new HashMap<>();
        fromObject.forEach(e -> sealed.put(e.seq(), e.line()));
        Map<Long, String> live = new HashMap<>();
        store.entriesOf(b.id()).forEach(e -> live.put(e.seq(), e.line()));
        var modified = new TreeSet<Long>();
        var missing = new TreeSet<Long>();
        sealed.forEach((seq, line) -> {
            String now = live.get(seq);
            if (now == null) {
                missing.add(seq);
            } else if (!now.equals(line)) {
                modified.add(seq);
            }
        });
        var extra = new TreeSet<>(live.keySet());
        extra.removeAll(sealed.keySet());
        var ret = objects.retention(b.objectKey());
        boolean valid = sigOk && linkOk && objectOk && modified.isEmpty() && missing.isEmpty() && extra.isEmpty();
        return new Verification(b.id(), valid, sigOk, objectOk, linkOk, ret.map(LockedObjectStore.Retention::mode).orElse(null),
                ret.map(LockedObjectStore.Retention::until).orElse(null), List.copyOf(modified), List.copyOf(missing),
                List.copyOf(extra));
    }

    static byte[] render(UUID id, String tenant, String prev, String digest, String signature, List<AuditEntry> entries) {
        StringBuilder b = new StringBuilder();
        b.append("# sentinel-audit-v1 batch=").append(id).append(" tenant=").append(tenant).append(" prev=").append(prev)
                .append(" digest=").append(digest).append(" signature=").append(signature).append('\n');
        for (AuditEntry e : entries) {
            b.append(e.line()).append('\n');
        }
        return b.toString().getBytes(StandardCharsets.UTF_8);
    }

    static List<AuditEntry> parse(byte[] body) {
        List<AuditEntry> out = new ArrayList<>();
        for (String line : new String(body, StandardCharsets.UTF_8).split("\n")) {
            if (!line.isEmpty() && !line.startsWith("#")) {
                out.add(AuditEntry.parse(line));
            }
        }
        return out;
    }
}
