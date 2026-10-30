package com.sentinelstream.ingest.domain.enrich;

import com.sentinelstream.event.SecurityEvent;

public final class GeoIpEnricher implements Enricher {

    private final IpRangeTable table;

    public GeoIpEnricher(IpRangeTable table) {
        this.table = table;
    }

    @Override
    public void enrich(SecurityEvent event, Enrichment out) {
        table.lookup(event.ip()).ifPresent(r -> out.geo(r.geo()));
    }
}
