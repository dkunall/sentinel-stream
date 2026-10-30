package com.sentinelstream.detection.domain.engine;

import com.sentinelstream.detection.domain.rule.RuleSpec;
import com.sentinelstream.event.EnrichedEvent;

import java.util.List;
import java.util.Optional;

/**
 * Per-entity baseline of how many matching events land in each bucket. Counts are log-scaled
 * (log(1 + n)) because event counts are heavy-tailed, and empty buckets between two events count as
 * zeros so a quiet user's baseline stays low. Fires at most once per bucket, and only once the entity
 * has {@code minObservations} closed buckets. A perfectly regular history has zero variance, so the
 * standard deviation is floored at {@link #MIN_STDDEV} to keep one extra event from being infinite z.
 */
public final class AnomalyDetector implements Detector {

    static final double MIN_STDDEV = 0.5;
    static final int MAX_GAP_BUCKETS = 168;

    @Override
    public Optional<Detection> evaluate(ActiveRule rule, EnrichedEvent e, RuleState st, Profile profile, RuleSet set) {
        RuleSpec.Anomaly spec = (RuleSpec.Anomaly) rule.compiled().spec();
        if (!Conditions.matches(spec.step(), e, null, profile)) {
            return Optional.empty();
        }
        long size = spec.bucket().toMillis();
        long bucket = Math.floorDiv(e.ts().toEpochMilli(), size) * size;
        if (st.bucketStart == null) {
            st.bucketStart = bucket;
        } else if (bucket > st.bucketStart) {
            st.baseline.add(Math.log1p(st.bucketCount));
            long gaps = Math.min((bucket - st.bucketStart) / size - 1, MAX_GAP_BUCKETS);
            for (long i = 0; i < gaps; i++) {
                st.baseline.add(0);
            }
            st.bucketStart = bucket;
            st.bucketCount = 0;
            st.alertedThisBucket = false;
        } else if (bucket < st.bucketStart) {
            return Optional.empty(); // late for a bucket already folded into the baseline
        }
        st.bucketCount++;
        if (st.alertedThisBucket || st.baseline.n < spec.minObservations()) {
            return Optional.empty();
        }
        double sd = Math.max(st.baseline.stddev(), MIN_STDDEV);
        double z = (Math.log1p(st.bucketCount) - st.baseline.mean) / sd;
        if (z <= spec.zScore()) {
            return Optional.empty();
        }
        st.alertedThisBucket = true;
        double typical = Math.expm1(st.baseline.mean);
        return Optional.of(new Detection(List.of(e.id()), Confidence.HIGH, String.format(
                "%d %s this %s against a typical %.1f (z=%.1f over %d buckets)", st.bucketCount,
                spec.step().pattern().canonical(), humanBucket(size), typical, z, st.baseline.n)));
    }

    private static String humanBucket(long ms) {
        return ms % 3_600_000 == 0 ? (ms / 3_600_000) + "h" : (ms / 60_000) + "m";
    }
}
