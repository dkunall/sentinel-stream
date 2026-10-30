package com.sentinelstream.detection.domain.rule;

import java.time.Duration;
import java.util.List;

/** The parsed form of a rule; one record per detector kind. */
public sealed interface RuleSpec {

    EntityKind entity();

    /** Sequence of steps that must happen in order within the window. */
    record Sequence(List<Step> steps, EntityKind entity, Duration within) implements RuleSpec {
        public Sequence {
            steps = List.copyOf(steps);
        }
    }

    /** At least {@code count} matching events within a sliding window. */
    record Threshold(Step step, int count, EntityKind entity, Duration within) implements RuleSpec {
    }

    /** z-score of log(1 + events per bucket) against the entity's own history, after {@code minObservations} buckets. */
    record Anomaly(Step step, EntityKind entity, Duration bucket, double zScore, int minObservations) implements RuleSpec {
    }

    /** Indicator match: {@code ip} exact, {@code user_agent} substring (Aho-Corasick), against a named list. */
    record Ioc(String field, String list, EntityKind entity) implements RuleSpec {
    }

    /** Implied speed between consecutive matching events above {@code maxKmh}. */
    record Travel(Step step, EntityKind entity, double maxKmh) implements RuleSpec {
    }

    /** A matching event from a device the entity has not used before, once it has a history of {@code after} events. */
    record NewDevice(Step step, EntityKind entity, int after) implements RuleSpec {
    }
}
