package com.sentinelstream.ingest.domain.enrich;

import com.sentinelstream.event.SecurityEvent;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Device fingerprint from the collector's device id and the user agent. With no device id the
 * fingerprint is the user agent alone, which is weak (many people share a browser build) but still
 * catches a login from a different client.
 */
public final class DeviceEnricher implements Enricher {

    @Override
    public void enrich(SecurityEvent event, Enrichment out) {
        if (event.deviceId() == null && event.userAgent() == null) {
            return;
        }
        String basis = (event.deviceId() == null ? "" : event.deviceId()) + "|"
                + (event.userAgent() == null ? "" : event.userAgent().toLowerCase());
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(basis.getBytes(StandardCharsets.UTF_8));
            out.deviceFingerprint(HexFormat.of().formatHex(d, 0, 8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
