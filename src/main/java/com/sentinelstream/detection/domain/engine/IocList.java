package com.sentinelstream.detection.domain.engine;

import java.util.Collection;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/** A named indicator list: exact IPs and user-agent substrings. */
public final class IocList {

    private final String name;
    private final Set<String> ips;
    private final AhoCorasick agents;

    public IocList(String name, Collection<String> ips, Collection<String> agentPatterns) {
        this.name = name;
        this.ips = ips.stream().map(String::trim).collect(Collectors.toUnmodifiableSet());
        this.agents = new AhoCorasick(agentPatterns);
    }

    public String name() {
        return name;
    }

    public Optional<String> match(String field, String value) {
        if (value == null) {
            return Optional.empty();
        }
        return switch (field) {
            case "ip" -> ips.contains(value) ? Optional.of(value) : Optional.empty();
            case "user_agent" -> agents.firstMatch(value);
            default -> Optional.empty();
        };
    }
}
