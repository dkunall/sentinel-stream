package com.sentinelstream.detection.domain.rule;

public final class RuleSyntaxException extends RuntimeException {

    private final int position;

    public RuleSyntaxException(String message, int position) {
        super(message + " at position " + position);
        this.position = position;
    }

    public int position() {
        return position;
    }
}
