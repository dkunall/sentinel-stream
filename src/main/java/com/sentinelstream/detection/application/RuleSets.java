package com.sentinelstream.detection.application;

import com.sentinelstream.detection.domain.engine.RuleSet;

/** Port: the rule set currently live for a tenant. Must be cheap; detectors call it per event. */
public interface RuleSets {

    RuleSet current(String tenant);
}
