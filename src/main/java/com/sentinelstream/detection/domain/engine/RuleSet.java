package com.sentinelstream.detection.domain.engine;

import com.sentinelstream.detection.domain.rule.EntityKind;

import java.util.List;
import java.util.Map;

/** Everything the engine needs for one tenant at one version: its enabled rules and IOC lists. */
public record RuleSet(long version, List<ActiveRule> rules, Map<String, IocList> iocs) {

    public static final RuleSet EMPTY = new RuleSet(0, List.of(), Map.of());

    public RuleSet {
        rules = List.copyOf(rules);
        iocs = Map.copyOf(iocs);
    }

    public List<ActiveRule> rulesFor(EntityKind kind) {
        return rules.stream().filter(r -> r.compiled().spec().entity() == kind).toList();
    }
}
