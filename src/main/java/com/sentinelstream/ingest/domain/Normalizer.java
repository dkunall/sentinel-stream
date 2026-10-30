package com.sentinelstream.ingest.domain;

import com.sentinelstream.event.Outcome;
import com.sentinelstream.event.SecurityEvent;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Maps collector input onto {@link SecurityEvent}. Validation lives here rather than in the ingest API
 * so both inputs (HTTP and syslog) are held to the same rules, and so a rejected event becomes a DLQ
 * record with a reason instead of disappearing.
 */
public final class Normalizer {

    private static final Pattern ID = Pattern.compile("[A-Za-z0-9._:-]{1,64}");
    private static final Pattern ACTION = Pattern.compile("[a-z][a-z_]{0,31}");
    private static final Pattern USER = Pattern.compile("[A-Za-z0-9._@+-]{1,128}");
    private static final Pattern IPV4 = Pattern.compile(
            "((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)");
    private static final int MAX_UA = 512;

    private final Clock clock;
    private final Duration maxAge;
    private final Duration maxSkew;
    private final SyslogParser syslog = new SyslogParser();

    public Normalizer(Clock clock, Duration maxAge, Duration maxSkew) {
        this.clock = clock;
        this.maxAge = maxAge;
        this.maxSkew = maxSkew;
    }

    public Normalized normalize(RawEnvelope raw) {
        if (raw.tenant() == null || raw.tenant().isBlank()) {
            return new Normalized.Rejected("missing tenant");
        }
        Map<String, Object> fields;
        if (raw.line() != null) {
            var parsed = syslog.parse(raw.line());
            if (parsed instanceof SyslogParser.Result.Unparsed u) {
                return new Normalized.Rejected("syslog: " + u.reason());
            }
            fields = ((SyslogParser.Result.Parsed) parsed).fields();
        } else if (raw.payload() != null) {
            fields = raw.payload();
        } else {
            return new Normalized.Rejected("empty envelope");
        }
        try {
            return new Normalized.Ok(toEvent(raw, fields));
        } catch (IllegalArgumentException e) {
            return new Normalized.Rejected(e.getMessage());
        }
    }

    private SecurityEvent toEvent(RawEnvelope raw, Map<String, Object> f) {
        String id = required(f, "id");
        if (!ID.matcher(id).matches()) {
            throw new IllegalArgumentException("id must match " + ID.pattern());
        }
        Instant ts = timestamp(required(f, "ts"));
        Instant now = clock.instant();
        if (ts.isAfter(now.plus(maxSkew))) {
            throw new IllegalArgumentException("ts is more than " + maxSkew.toMinutes() + " min in the future");
        }
        if (ts.isBefore(now.minus(maxAge))) {
            throw new IllegalArgumentException("ts is older than " + maxAge.toDays() + " days");
        }
        String action = required(f, "action").toLowerCase();
        if (!ACTION.matcher(action).matches()) {
            throw new IllegalArgumentException("action must match " + ACTION.pattern());
        }
        Outcome outcome = Outcome.parse(required(f, "outcome"));
        String user = optional(f, "user");
        if (user != null && !USER.matcher(user).matches()) {
            throw new IllegalArgumentException("user has unexpected characters");
        }
        String ip = optional(f, "ip");
        if (ip != null && !IPV4.matcher(ip).matches()) {
            throw new IllegalArgumentException("ip must be an IPv4 address");
        }
        if (user == null && ip == null) {
            throw new IllegalArgumentException("an event needs a user or an ip");
        }
        String ua = optional(f, "user_agent");
        if (ua != null && ua.length() > MAX_UA) {
            ua = ua.substring(0, MAX_UA);
        }
        String device = optional(f, "device_id");
        if (device != null && device.length() > 128) {
            throw new IllegalArgumentException("device_id longer than 128");
        }
        return new SecurityEvent(id, raw.tenant(), ts, user == null ? null : user.toLowerCase(), ip, action, outcome,
                ua, device, raw.source(), raw.receivedAt());
    }

    private static Instant timestamp(String raw) {
        try {
            return Instant.parse(raw);
        } catch (DateTimeParseException e) {
            throw new IllegalArgumentException("ts must be ISO-8601 UTC, got '" + raw + "'");
        }
    }

    private static String required(Map<String, Object> f, String key) {
        String v = optional(f, key);
        if (v == null) {
            throw new IllegalArgumentException(key + " is required");
        }
        return v;
    }

    private static String optional(Map<String, Object> f, String key) {
        Object v = f.get(key);
        if (v == null) {
            return null;
        }
        String s = v.toString().trim();
        return s.isEmpty() ? null : s;
    }
}
