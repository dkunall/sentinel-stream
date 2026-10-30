package com.sentinelstream.detection.domain.engine;

import com.sentinelstream.detection.domain.rule.RuleSpec;
import com.sentinelstream.event.EnrichedEvent;

import java.util.List;
import java.util.Optional;

public final class IocDetector implements Detector {

    @Override
    public Optional<Detection> evaluate(ActiveRule rule, EnrichedEvent e, RuleState st, Profile profile, RuleSet set) {
        RuleSpec.Ioc spec = (RuleSpec.Ioc) rule.compiled().spec();
        IocList list = set.iocs().get(spec.list());
        if (list == null) {
            return Optional.empty();
        }
        return list.match(spec.field(), e.field(spec.field())).map(hit -> new Detection(List.of(e.id()), Confidence.HIGH,
                spec.field() + " matched indicator '" + hit + "' in list " + spec.list()));
    }
}
