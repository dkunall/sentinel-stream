package com.sentinelstream.search.application;

import com.sentinelstream.search.domain.SearchCursor;

import java.time.Instant;

public record EventQuery(String tenant, String user, String ip, String action, String outcome, Instant from, Instant to,
                         int limit, SearchCursor after) {
}
