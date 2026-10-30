package com.sentinelstream.detection.domain.engine;

import java.util.ArrayList;
import java.util.List;

/**
 * Per-entity, per-rule-version state. One class with a field group per detector kind keeps the
 * serialized form flat; each detector only touches its own fields.
 */
public final class RuleState {
    // sequence
    public List<Run> runs = new ArrayList<>();
    // threshold: timestamps and ids of the matching events still inside the window
    public List<Long> times = new ArrayList<>();
    public List<String> ids = new ArrayList<>();
    // anomaly
    public Long bucketStart;
    public long bucketCount;
    public boolean alertedThisBucket;
    public Welford baseline = new Welford();
    // travel
    public Long lastMs;
    public Double lastLat;
    public Double lastLon;
    public String lastCity;
    public String lastNetwork;
    // new device
    public long seen;
}
