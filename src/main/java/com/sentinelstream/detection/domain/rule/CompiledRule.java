package com.sentinelstream.detection.domain.rule;

/** A parsed rule plus its canonical text and the SHA-256 of that text (two spellings of one rule hash the same). */
public record CompiledRule(RuleSpec spec, String canonical, String hash) {

    public RuleKind kind() {
        return switch (spec) {
            case RuleSpec.Sequence s -> RuleKind.SEQUENCE;
            case RuleSpec.Threshold t -> RuleKind.THRESHOLD;
            case RuleSpec.Anomaly a -> RuleKind.ANOMALY;
            case RuleSpec.Ioc i -> RuleKind.IOC;
            case RuleSpec.Travel t -> RuleKind.TRAVEL;
            case RuleSpec.NewDevice n -> RuleKind.NEW_DEVICE;
        };
    }
}
