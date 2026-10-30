package com.sentinelstream.ingest.domain.enrich;

import com.sentinelstream.event.SecurityEvent;

public final class AsnEnricher implements Enricher {

    private final IpRangeTable table;

    public AsnEnricher(IpRangeTable table) {
        this.table = table;
    }

    @Override
    public void enrich(SecurityEvent event, Enrichment out) {
        table.lookup(event.ip()).ifPresent(r -> {
            out.asn(r.asn(), r.asnOrg());
            out.network(r.network());
        });
    }
}
