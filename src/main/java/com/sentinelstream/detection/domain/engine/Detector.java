package com.sentinelstream.detection.domain.engine;

import com.sentinelstream.event.EnrichedEvent;

import java.util.Optional;

/** One strategy per rule kind. Detectors are stateless; everything they remember lives in {@link RuleState}. */
public interface Detector {

    Optional<Detection> evaluate(ActiveRule rule, EnrichedEvent event, RuleState state, Profile profile, RuleSet set);
}
