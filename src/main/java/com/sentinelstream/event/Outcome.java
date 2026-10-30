package com.sentinelstream.event;

public enum Outcome {
    SUCCESS, FAILURE;

    public static Outcome parse(String raw) {
        if (raw == null) {
            throw new IllegalArgumentException("outcome is required");
        }
        return switch (raw.trim().toLowerCase()) {
            case "success", "ok", "succeeded", "accepted" -> SUCCESS;
            case "failure", "fail", "failed", "denied", "rejected" -> FAILURE;
            default -> throw new IllegalArgumentException("unknown outcome '" + raw + "'");
        };
    }

    public String dsl() {
        return name().toLowerCase();
    }
}
