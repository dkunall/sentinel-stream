package com.sentinelstream.detection.domain.rule;

public enum Severity {
    LOW, MEDIUM, HIGH, CRITICAL;

    public Severity max(Severity other) {
        return other.ordinal() > ordinal() ? other : this;
    }
}
