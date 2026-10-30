package com.sentinelstream.detection.application;

import com.sentinelstream.detection.domain.engine.ActiveRule;
import com.sentinelstream.detection.domain.engine.IocList;
import com.sentinelstream.detection.domain.engine.RuleSet;
import com.sentinelstream.detection.domain.rule.RuleCompiler;
import com.sentinelstream.detection.domain.rule.RuleSyntaxException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/** Compiles stored rules and IOC rows into per-tenant rule sets. */
final class RuleSetBuilder {

    private static final Logger log = LoggerFactory.getLogger(RuleSetBuilder.class);

    private RuleSetBuilder() {
    }

    static Map<String, RuleSet> build(long version, List<RuleStore.StoredRule> rules, List<RuleStore.IocEntry> iocs) {
        RuleCompiler compiler = new RuleCompiler();
        Map<String, List<ActiveRule>> active = new HashMap<>();
        for (var r : rules) {
            if (!r.enabled()) {
                continue;
            }
            try {
                active.computeIfAbsent(r.tenant(), t -> new ArrayList<>())
                        .add(new ActiveRule(r.id(), r.version(), r.name(), r.severity(), compiler.compile(r.dsl())));
            } catch (RuleSyntaxException e) {
                // stored rules were compiled on write, so this only happens across incompatible upgrades
                log.error("stored rule {}/{}@{} no longer compiles: {}", r.tenant(), r.id(), r.version(), e.getMessage());
            }
        }
        Map<String, Map<String, IocList>> lists = new HashMap<>();
        iocs.stream().collect(Collectors.groupingBy(RuleStore.IocEntry::tenant, Collectors.groupingBy(RuleStore.IocEntry::list)))
                .forEach((tenant, byList) -> byList.forEach((name, entries) -> lists
                        .computeIfAbsent(tenant, t -> new HashMap<>())
                        .put(name, new IocList(name,
                                entries.stream().filter(e -> e.kind().equals("ip")).map(RuleStore.IocEntry::value).toList(),
                                entries.stream().filter(e -> e.kind().equals("user_agent")).map(RuleStore.IocEntry::value).toList()))));
        Map<String, RuleSet> out = new HashMap<>();
        for (String tenant : union(active.keySet(), lists.keySet())) {
            out.put(tenant, new RuleSet(version, active.getOrDefault(tenant, List.of()), lists.getOrDefault(tenant, Map.of())));
        }
        return Map.copyOf(out);
    }

    private static List<String> union(java.util.Set<String> a, java.util.Set<String> b) {
        var s = new java.util.HashSet<>(a);
        s.addAll(b);
        return List.copyOf(s);
    }
}
