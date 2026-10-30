package com.sentinelstream.event;

import java.time.Instant;

/** A normalized event plus what the enricher chain could find out about its address and device. */
public record EnrichedEvent(
        SecurityEvent event,
        Geo geo,
        Integer asn,
        String asnOrg,
        NetworkType network,
        String deviceFingerprint) {

    public String id() {
        return event.id();
    }

    public String tenant() {
        return event.tenant();
    }

    public Instant ts() {
        return event.ts();
    }

    /**
     * Field lookup by DSL name. Values are strings so rule conditions compare them uniformly;
     * a missing value is null and never equals anything.
     */
    public String field(String name) {
        return switch (name) {
            case "user" -> event.user();
            case "ip" -> event.ip();
            case "action" -> event.action();
            case "outcome" -> event.outcome().dsl();
            case "user_agent" -> event.userAgent();
            case "source" -> event.source();
            case "device" -> deviceFingerprint;
            case "asn" -> asn == null ? null : asn.toString();
            case "country" -> geo == null ? null : geo.country();
            case "city" -> geo == null ? null : geo.city();
            case "network" -> network == null ? null : network.name().toLowerCase();
            default -> throw new IllegalArgumentException("unknown field " + name);
        };
    }

    public static final java.util.Set<String> FIELDS = java.util.Set.of(
            "user", "ip", "action", "outcome", "user_agent", "source", "device", "asn", "country", "city", "network");
}
