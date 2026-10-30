package com.sentinelstream.detection.domain.engine;

import com.sentinelstream.detection.domain.rule.EntityKind;
import com.sentinelstream.detection.domain.rule.RuleKind;
import com.sentinelstream.event.EnrichedEvent;
import com.sentinelstream.event.Outcome;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Feeds one event through every rule that groups by the given entity kind, then updates the entity's
 * profile. Pure: the same rule set, state and event always give the same signals, which is what lets
 * the backtest reuse this class on stored events.
 */
public final class DetectionEngine {

    private final Map<RuleKind, Detector> detectors = new EnumMap<>(RuleKind.class);

    public DetectionEngine() {
        detectors.put(RuleKind.SEQUENCE, new SequenceDetector());
        detectors.put(RuleKind.THRESHOLD, new ThresholdDetector());
        detectors.put(RuleKind.ANOMALY, new AnomalyDetector());
        detectors.put(RuleKind.IOC, new IocDetector());
        detectors.put(RuleKind.TRAVEL, new TravelDetector());
        detectors.put(RuleKind.NEW_DEVICE, new NewDeviceDetector());
    }

    public List<Signal> process(RuleSet set, EntityKind kind, EntityState state, EnrichedEvent e) {
        String entity = kind.keyOf(e);
        if (entity == null) {
            return List.of();
        }
        List<ActiveRule> rules = set.rulesFor(kind);
        Set<String> live = rules.stream().map(ActiveRule::stateKey).collect(Collectors.toSet());
        state.rules.keySet().retainAll(live);

        List<Signal> out = new ArrayList<>();
        for (ActiveRule rule : rules) {
            Optional<Detection> d = detectors.get(rule.compiled().kind())
                    .evaluate(rule, e, state.rule(rule.stateKey()), state.profile, set);
            d.ifPresent(det -> out.add(signal(rule, kind, entity, e, det)));
        }
        if (e.event().outcome() == Outcome.SUCCESS) {
            state.profile.successes++;
            for (String f : Profile.TRACKED) {
                state.profile.learn(f, e.field(f));
            }
        }
        state.lastEventMs = Math.max(state.lastEventMs, e.ts().toEpochMilli());
        return out;
    }

    private static Signal signal(ActiveRule rule, EntityKind kind, String entity, EnrichedEvent e, Detection d) {
        String id = sha256(rule.stateKey() + "|" + kind + ":" + entity + "|" + e.id()).substring(0, 32);
        return new Signal(id, e.tenant(), rule.id(), rule.version(), rule.name(), rule.severity(), d.confidence(), kind,
                entity, e.ts(), e.id(), d.eventIds(), e.event().ingestedAt(), d.summary());
    }

    static String sha256(String s) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }
}
