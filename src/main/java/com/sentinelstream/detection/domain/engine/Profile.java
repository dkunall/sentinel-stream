package com.sentinelstream.detection.domain.engine;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * What an entity is known to do, learned only from successful events: a failed login from a new ASN
 * must not make that ASN look familiar to the success that follows it. Each field keeps at most
 * {@link #MAX_VALUES} values, oldest evicted first.
 */
public final class Profile {
    public static final int MAX_VALUES = 64;
    public static final List<String> TRACKED = List.of("asn", "country", "city", "device", "ip", "user", "network");

    public Map<String, List<String>> known = new HashMap<>();
    public long successes;

    public boolean knows(String field, String value) {
        List<String> values = known.get(field);
        return values != null && values.contains(value);
    }

    public void learn(String field, String value) {
        if (value == null) {
            return;
        }
        List<String> values = known.computeIfAbsent(field, k -> new ArrayList<>());
        values.remove(value);
        values.add(value);
        if (values.size() > MAX_VALUES) {
            values.removeFirst();
        }
    }
}
