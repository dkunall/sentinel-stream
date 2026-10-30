package com.sentinelstream.detection.domain.engine;

import com.sentinelstream.detection.domain.rule.RuleSpec;
import com.sentinelstream.event.EnrichedEvent;

import java.util.List;
import java.util.Optional;

/** A matching event from a device fingerprint the entity has never succeeded from, once it has some history. */
public final class NewDeviceDetector implements Detector {

    @Override
    public Optional<Detection> evaluate(ActiveRule rule, EnrichedEvent e, RuleState st, Profile profile, RuleSet set) {
        RuleSpec.NewDevice spec = (RuleSpec.NewDevice) rule.compiled().spec();
        if (!Conditions.matches(spec.step(), e, null, profile) || e.deviceFingerprint() == null) {
            return Optional.empty();
        }
        boolean fire = st.seen >= spec.after() && !profile.knows("device", e.deviceFingerprint());
        st.seen++;
        if (!fire) {
            return Optional.empty();
        }
        return Optional.of(new Detection(List.of(e.id()), Confidence.HIGH,
                "first login from device " + e.deviceFingerprint() + " after " + (st.seen - 1) + " known logins"));
    }
}
