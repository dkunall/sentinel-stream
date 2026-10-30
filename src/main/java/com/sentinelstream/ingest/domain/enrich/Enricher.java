package com.sentinelstream.ingest.domain.enrich;

import com.sentinelstream.event.SecurityEvent;

/** One link in the enrichment chain; each link fills in what it knows and leaves the rest alone. */
public interface Enricher {

    void enrich(SecurityEvent event, Enrichment out);
}
