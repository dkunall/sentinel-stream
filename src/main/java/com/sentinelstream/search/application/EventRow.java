package com.sentinelstream.search.application;

import java.time.Instant;

public record EventRow(String id, Instant ts, Instant ingestedAt, String user, String ip, String action, String outcome,
                       String userAgent, String device, String source, String country, String city, Integer asn,
                       String network) {

    public EventRow masked(java.util.function.UnaryOperator<String> userMask, java.util.function.UnaryOperator<String> ipMask) {
        return new EventRow(id, ts, ingestedAt, userMask.apply(user), ipMask.apply(ip), action, outcome, userAgent, device,
                source, country, city, asn, network);
    }
}
