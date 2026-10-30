package com.sentinelstream.shared.security;

import java.util.Set;

/** Who is calling: a person or service from a JWT, or a collector from an API key. */
public record Actor(String tenant, String subject, Set<String> scopes) {

    public static final String ANALYST = "sentinel.analyst";
    public static final String ADMIN = "sentinel.admin";
    public static final String PII = "sentinel.pii";
    public static final String COLLECTOR = "sentinel.collector";

    public boolean has(String scope) {
        return scopes.contains(scope);
    }

    public static Actor system(String tenant, String component) {
        return new Actor(tenant, "system:" + component, Set.of());
    }
}
