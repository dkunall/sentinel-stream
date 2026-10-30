package com.sentinelstream.ingest.domain.enrich;

import com.sentinelstream.event.EnrichedEvent;
import com.sentinelstream.event.SecurityEvent;

import java.util.List;

public final class EnricherChain {

    private final List<Enricher> links;

    public EnricherChain(List<Enricher> links) {
        this.links = List.copyOf(links);
    }

    public static EnricherChain standard(IpRangeTable table) {
        return new EnricherChain(List.of(new GeoIpEnricher(table), new AsnEnricher(table), new DeviceEnricher()));
    }

    public EnrichedEvent enrich(SecurityEvent event) {
        Enrichment out = new Enrichment();
        for (Enricher link : links) {
            link.enrich(event, out);
        }
        return out.build(event);
    }
}
