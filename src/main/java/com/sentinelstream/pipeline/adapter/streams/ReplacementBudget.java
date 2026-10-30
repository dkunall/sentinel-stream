package com.sentinelstream.pipeline.adapter.streams;

import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Deque;

/** Allows at most {@link #MAX} stream-thread replacements in any sliding {@link #WINDOW}. */
final class ReplacementBudget {

    static final int MAX = 5;
    static final Duration WINDOW = Duration.ofMinutes(1);

    private final Deque<Long> recent = new ArrayDeque<>();

    synchronized boolean tryReplace(long nowNanos) {
        while (!recent.isEmpty() && nowNanos - recent.peekFirst() > WINDOW.toNanos()) {
            recent.pollFirst();
        }
        if (recent.size() >= MAX) {
            return false;
        }
        recent.addLast(nowNanos);
        return true;
    }
}
