package com.sentinelstream.detection.application;

import com.sentinelstream.detection.domain.engine.ActiveRule;
import com.sentinelstream.detection.domain.engine.DetectionEngine;
import com.sentinelstream.detection.domain.engine.EntityState;
import com.sentinelstream.detection.domain.engine.RuleSet;
import com.sentinelstream.detection.domain.engine.Signal;
import com.sentinelstream.detection.domain.rule.CompiledRule;
import com.sentinelstream.detection.domain.rule.RuleCompiler;
import com.sentinelstream.detection.domain.rule.RuleSyntaxException;
import com.sentinelstream.detection.domain.rule.Severity;
import com.sentinelstream.event.EnrichedEvent;
import com.sentinelstream.shared.audit.AuditRecorder;
import com.sentinelstream.shared.error.ApiException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

@Service
public class RuleService {

    private static final Pattern ID = Pattern.compile("[a-z0-9][a-z0-9-]{1,63}");
    private static final Pattern LIST = Pattern.compile("[a-z0-9][a-z0-9_-]{0,63}");
    static final Duration MAX_BACKTEST = Duration.ofHours(24);
    static final int MAX_BACKTEST_EVENTS = 50_000;

    private final RuleStore store;
    private final RuleSets live;
    private final EventHistory history;
    private final AuditRecorder audit;
    private final Clock clock;
    private final RuleCompiler compiler = new RuleCompiler();

    RuleService(RuleStore store, RuleSets live, EventHistory history, AuditRecorder audit, Clock clock) {
        this.store = store;
        this.live = live;
        this.history = history;
        this.audit = audit;
        this.clock = clock;
    }

    public record SaveResult(RuleStore.StoredRule rule, boolean changed) {
    }

    /** Appends a new version unless the rule is unchanged (same compiled form, name, severity, enabled). */
    @Transactional
    public SaveResult save(String tenant, String actor, String id, String name, String dsl, Severity severity, boolean enabled) {
        if (!ID.matcher(id).matches()) {
            throw ApiException.invalid("rule id must match " + ID.pattern());
        }
        CompiledRule compiled = compile(dsl);
        var latest = store.latest(tenant, id);
        if (latest.isPresent()) {
            var l = latest.get();
            if (l.hash().equals(compiled.hash()) && l.name().equals(name) && l.severity() == severity && l.enabled() == enabled) {
                return new SaveResult(l, false);
            }
        }
        int version = latest.map(r -> r.version() + 1).orElse(1);
        var rule = new RuleStore.StoredRule(tenant, id, version, name, dsl, compiled.canonical(), compiled.hash(), severity,
                enabled, actor, clock.instant());
        if (!store.insert(rule)) {
            throw ApiException.conflict("concurrent-edit", "rule " + id + " was changed concurrently; retry");
        }
        store.bumpChangeVersion();
        audit.record(tenant, actor, "rule.saved", id, Map.of("version", version, "enabled", enabled, "hash", compiled.hash()));
        return new SaveResult(rule, true);
    }

    public List<RuleStore.StoredRule> list(String tenant) {
        return store.latestVersions(tenant);
    }

    public record Backtest(String ruleId, int ruleVersion, Instant from, Instant to, int eventsScanned, boolean truncated,
                           int signals, int distinctEntities, int distinctAlerts, List<Signal> samples) {
    }

    /**
     * Runs the rule (or an unsaved DSL override) over stored events with a fresh engine and fresh state.
     * Nothing is published; this is what the rule would have raised, not what it did raise.
     */
    public Backtest backtest(String tenant, String id, String dslOverride, Instant from, Instant to) {
        Instant end = to == null ? clock.instant() : to;
        Instant start = from == null ? end.minus(MAX_BACKTEST) : from;
        if (!start.isBefore(end) || Duration.between(start, end).compareTo(MAX_BACKTEST) > 0) {
            throw ApiException.invalid("backtest window must be positive and at most 24h");
        }
        ActiveRule rule;
        if (dslOverride != null) {
            var base = store.latest(tenant, id);
            rule = new ActiveRule(id, 0, base.map(RuleStore.StoredRule::name).orElse(id),
                    base.map(RuleStore.StoredRule::severity).orElse(Severity.MEDIUM), compile(dslOverride));
        } else {
            var stored = store.latest(tenant, id).orElseThrow(() -> ApiException.notFound("rule"));
            rule = new ActiveRule(id, stored.version(), stored.name(), stored.severity(), compile(stored.dsl()));
        }
        RuleSet set = new RuleSet(0, List.of(rule), live.current(tenant).iocs());
        var kind = rule.compiled().spec().entity();
        List<EnrichedEvent> events = history.replay(tenant, start, end, MAX_BACKTEST_EVENTS + 1);
        boolean truncated = events.size() > MAX_BACKTEST_EVENTS;
        if (truncated) {
            events = events.subList(0, MAX_BACKTEST_EVENTS);
        }
        DetectionEngine engine = new DetectionEngine();
        Map<String, EntityState> states = new HashMap<>();
        List<Signal> signals = new ArrayList<>();
        for (EnrichedEvent e : events) {
            String key = kind.keyOf(e);
            if (key == null) {
                continue;
            }
            signals.addAll(engine.process(set, kind, states.computeIfAbsent(key, k -> new EntityState()), e));
        }
        Set<String> entities = new HashSet<>();
        Set<String> alerts = new HashSet<>();
        for (Signal s : signals) {
            entities.add(s.entityKey());
            alerts.add(s.entityKey() + "|" + Math.floorDiv(s.ts().getEpochSecond(), 3600));
        }
        return new Backtest(id, rule.version(), start, end, events.size(), truncated, signals.size(), entities.size(),
                alerts.size(), signals.stream().limit(20).toList());
    }

    @Transactional
    public int addIocs(String tenant, String actor, String list, String kind, List<String> values) {
        checkIoc(list, kind);
        if (values.isEmpty() || values.size() > 10_000) {
            throw ApiException.invalid("between 1 and 10000 values per request");
        }
        List<String> clean = values.stream().map(String::trim).filter(v -> !v.isEmpty() && v.length() <= 256).distinct().toList();
        int added = store.addIocs(tenant, list, kind, clean);
        if (added > 0) {
            store.bumpChangeVersion();
            audit.record(tenant, actor, "ioc.added", list, Map.of("kind", kind, "added", added));
        }
        return added;
    }

    @Transactional
    public boolean removeIoc(String tenant, String actor, String list, String kind, String value) {
        checkIoc(list, kind);
        boolean removed = store.removeIoc(tenant, list, kind, value) > 0;
        if (removed) {
            store.bumpChangeVersion();
            audit.record(tenant, actor, "ioc.removed", list, Map.of("kind", kind, "value", value));
        }
        return removed;
    }

    public List<RuleStore.IocEntry> iocs(String tenant) {
        return store.iocs(tenant);
    }

    private static void checkIoc(String list, String kind) {
        if (!LIST.matcher(list).matches()) {
            throw ApiException.invalid("list name must match " + LIST.pattern());
        }
        if (!kind.equals("ip") && !kind.equals("user_agent")) {
            throw ApiException.invalid("kind must be ip or user_agent");
        }
    }

    private CompiledRule compile(String dsl) {
        if (dsl == null || dsl.isBlank() || dsl.length() > 4000) {
            throw ApiException.invalid("dsl must be 1-4000 characters");
        }
        try {
            return compiler.compile(dsl);
        } catch (RuleSyntaxException e) {
            throw new ApiException(400, "rule-syntax", e.getMessage(), Map.of("position", e.position()));
        }
    }
}
