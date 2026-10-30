package com.sentinelstream.response.domain;

import com.sentinelstream.detection.domain.engine.Signal;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.UUID;

/**
 * Signals of one rule about one entity within the same UTC hour are one alert with a count. The alert
 * id is derived from the fingerprint, so it is known before the row exists and every instance
 * computes the same one.
 */
public final class AlertFingerprint {

    private AlertFingerprint() {
    }

    public static String of(Signal s) {
        long hour = Math.floorDiv(s.ts().getEpochSecond(), 3600);
        return sha256(s.tenant() + "|" + s.ruleId() + "|" + s.entityKind() + ":" + s.entityKey() + "|" + hour);
    }

    public static UUID alertId(String fingerprint) {
        return UUID.nameUUIDFromBytes(("alert:" + fingerprint).getBytes(StandardCharsets.UTF_8));
    }

    static String sha256(String s) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
