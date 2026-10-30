package com.sentinelstream.detection.domain.rule;

import java.util.List;
import java.util.stream.Collectors;

/** One element of a sequence: a pattern repeated between {@code min} and {@code max} times (max -1 = unbounded). */
public record Step(EventPattern pattern, List<Condition> where, int min, int max) {

    public static final int UNBOUNDED = -1;

    public Step {
        where = List.copyOf(where);
        if (min < 1) {
            throw new IllegalArgumentException("a step must match at least once");
        }
        if (max != UNBOUNDED && max < min) {
            throw new IllegalArgumentException("{" + min + "," + max + "}: max below min");
        }
    }

    public static Step once(EventPattern pattern, List<Condition> where) {
        return new Step(pattern, where, 1, 1);
    }

    /** The highest count worth remembering: past {@code min} an unbounded step has nothing more to learn. */
    public int countCap() {
        return max == UNBOUNDED ? min : max;
    }

    public String canonical() {
        String q = (min == 1 && max == 1) ? "" : "{" + min + "," + (max == UNBOUNDED ? "" : max) + "}";
        String w = where.isEmpty() ? "" : " where " + where.stream().map(Condition::canonical).collect(Collectors.joining(" and "));
        return pattern.canonical() + q + w;
    }
}
