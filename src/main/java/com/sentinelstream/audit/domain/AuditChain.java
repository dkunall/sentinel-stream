package com.sentinelstream.audit.domain;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;

/**
 * Hash chain over audit lines: h0 is the previous batch's digest (or 64 zeros for a tenant's first
 * batch), h(i) = sha256(h(i-1) || line(i)). The batch digest is the last h, so changing, removing or
 * reordering any entry, or any earlier batch, changes every digest after it.
 */
public final class AuditChain {

    public static final String GENESIS = "0".repeat(64);

    private AuditChain() {
    }

    public static String digest(String prev, List<AuditEntry> entries) {
        String h = prev;
        for (AuditEntry e : entries) {
            h = sha256(h + e.line());
        }
        return h;
    }

    /** What the signature covers: binds the digest to the batch, tenant and the chain position. */
    public static String signedMessage(String batchId, String tenant, String prev, String digest, int entries) {
        return "sentinel-audit-v1|" + batchId + "|" + tenant + "|" + prev + "|" + digest + "|" + entries;
    }

    static String sha256(String s) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
