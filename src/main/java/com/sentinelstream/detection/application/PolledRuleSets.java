package com.sentinelstream.detection.application;

import com.sentinelstream.detection.domain.engine.RuleSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/**
 * The live rule sets, swapped atomically. Detector threads read a plain reference; a scheduled poll
 * of the change counter rebuilds everything when a rule or IOC changed. Rules therefore take effect
 * within one poll interval (2 s by default) on every instance, with no restart.
 */
@Component
public class PolledRuleSets implements RuleSets {

    private static final Logger log = LoggerFactory.getLogger(PolledRuleSets.class);

    private final RuleStore store;
    private final AtomicReference<Snapshot> current = new AtomicReference<>(new Snapshot(-1, Map.of()));

    PolledRuleSets(RuleStore store) {
        this.store = store;
        refresh();
    }

    @Override
    public RuleSet current(String tenant) {
        return current.get().sets().getOrDefault(tenant, RuleSet.EMPTY);
    }

    public long loadedVersion() {
        return current.get().version();
    }

    @Scheduled(fixedDelayString = "${sentinel.streams.rules-poll}")
    public void refresh() {
        try {
            long v = store.changeVersion();
            if (v == current.get().version()) {
                return;
            }
            var sets = RuleSetBuilder.build(v, store.latestVersions(), store.iocs());
            current.set(new Snapshot(v, sets));
            log.info("loaded rule sets at change version {} for {} tenants", v, sets.size());
        } catch (RuntimeException e) {
            log.warn("rule reload failed, keeping version {}: {}", current.get().version(), e.toString());
        }
    }

    private record Snapshot(long version, Map<String, RuleSet> sets) {
    }
}
