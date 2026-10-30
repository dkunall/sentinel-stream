package com.sentinelstream.detection.domain.rule;

import java.util.List;
import java.util.stream.Collectors;

/**
 * A {@code where} clause term. {@code same} and {@code changed} compare against the partial match
 * (the first and the previous matched event), {@code is new} against what the entity has done before.
 */
public sealed interface Condition {

    String field();

    String canonical();

    record Equals(String field, String value, boolean negated) implements Condition {
        public String canonical() {
            return field + (negated ? " != " : " = ") + quote(value);
        }
    }

    record In(String field, List<String> values, boolean negated) implements Condition {
        public String canonical() {
            return field + (negated ? " not in (" : " in (")
                    + values.stream().map(Condition::quote).collect(Collectors.joining(", ")) + ")";
        }
    }

    record IsNew(String field) implements Condition {
        public String canonical() {
            return field + " is new";
        }
    }

    record Same(String field) implements Condition {
        public String canonical() {
            return field + " same";
        }
    }

    record Changed(String field) implements Condition {
        public String canonical() {
            return field + " changed";
        }
    }

    private static String quote(String v) {
        return "\"" + v.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }
}
