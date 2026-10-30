package com.sentinelstream.detection.domain.engine;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** One partial match of a sequence rule: which step it is on, how many times that step has matched. */
public final class Run {
    public int step;
    public int count;
    public long startMs;
    public Map<String, String> first = new HashMap<>();
    public Map<String, String> last = new HashMap<>();
    public List<String> eventIds = new ArrayList<>();

    public Run copy() {
        Run r = new Run();
        r.step = step;
        r.count = count;
        r.startMs = startMs;
        r.first = new HashMap<>(first);
        r.last = new HashMap<>(last);
        r.eventIds = new ArrayList<>(eventIds);
        return r;
    }
}
