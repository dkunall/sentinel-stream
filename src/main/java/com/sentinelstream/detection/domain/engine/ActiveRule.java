package com.sentinelstream.detection.domain.engine;

import com.sentinelstream.detection.domain.rule.CompiledRule;
import com.sentinelstream.detection.domain.rule.Severity;

/** A rule version that is switched on, as the engine sees it. */
public record ActiveRule(String id, int version, String name, Severity severity, CompiledRule compiled) {

    /** State is kept per rule version, so editing a rule starts its partial matches from scratch. */
    public String stateKey() {
        return id + "@" + version;
    }
}
