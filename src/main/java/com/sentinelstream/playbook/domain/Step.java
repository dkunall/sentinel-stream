package com.sentinelstream.playbook.domain;

import java.net.URI;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

public record Step(StepKind kind, Map<String, String> params) {

    private static final Pattern LIST = Pattern.compile("[a-z0-9][a-z0-9_-]{0,63}");

    public Step {
        params = params == null ? Map.of() : Map.copyOf(params);
    }

    /** Throws IllegalArgumentException with a client-readable reason. */
    public void validate(Set<String> allowedHosts) {
        switch (kind) {
            case LOCK_ACCOUNT -> {
            }
            case ADD_TO_IOC_LIST -> {
                String list = params.get("list");
                if (list == null || !LIST.matcher(list).matches()) {
                    throw new IllegalArgumentException("ADD_TO_IOC_LIST needs a 'list' matching " + LIST.pattern());
                }
            }
            case NOTIFY_WEBHOOK -> checkUrl(params.get("url"), allowedHosts);
        }
    }

    public static URI checkUrl(String url, Set<String> allowedHosts) {
        if (url == null) {
            throw new IllegalArgumentException("NOTIFY_WEBHOOK needs a 'url'");
        }
        URI u;
        try {
            u = URI.create(url);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("webhook url is not a valid URI");
        }
        if (!"http".equals(u.getScheme()) && !"https".equals(u.getScheme())) {
            throw new IllegalArgumentException("webhook url must be http or https");
        }
        if (u.getHost() == null || !allowedHosts.contains(u.getHost().toLowerCase()) || u.getUserInfo() != null) {
            throw new IllegalArgumentException("webhook host must be one of " + allowedHosts);
        }
        return u;
    }
}
