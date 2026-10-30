package com.sentinelstream.shared;

public final class Topics {
    public static final String RAW = "sentinel.events.raw";
    public static final String NORMALIZED = "sentinel.events.normalized";
    public static final String BY_USER = "sentinel.events.by-user";
    public static final String BY_IP = "sentinel.events.by-ip";
    public static final String DLQ = "sentinel.events.dlq";
    public static final String ALERTS = "sentinel.alerts";

    private Topics() {
    }
}
