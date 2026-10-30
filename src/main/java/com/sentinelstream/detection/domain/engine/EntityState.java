package com.sentinelstream.detection.domain.engine;

import java.util.HashMap;
import java.util.Map;

/** Everything the detectors remember about one entity (one user or one IP of one tenant). */
public final class EntityState {
    public Map<String, RuleState> rules = new HashMap<>();
    public Profile profile = new Profile();
    public long lastEventMs;

    public RuleState rule(String key) {
        return rules.computeIfAbsent(key, k -> new RuleState());
    }
}
