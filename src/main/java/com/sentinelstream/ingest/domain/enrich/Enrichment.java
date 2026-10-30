package com.sentinelstream.ingest.domain.enrich;

import com.sentinelstream.event.EnrichedEvent;
import com.sentinelstream.event.Geo;
import com.sentinelstream.event.NetworkType;
import com.sentinelstream.event.SecurityEvent;

/** Mutable accumulator passed along the chain, frozen into an {@link EnrichedEvent} at the end. */
public final class Enrichment {
    Geo geo;
    Integer asn;
    String asnOrg;
    NetworkType network = NetworkType.UNKNOWN;
    String deviceFingerprint;

    public void geo(Geo geo) {
        this.geo = geo;
    }

    public void asn(Integer asn, String org) {
        this.asn = asn;
        this.asnOrg = org;
    }

    public void network(NetworkType network) {
        this.network = network;
    }

    public void deviceFingerprint(String fp) {
        this.deviceFingerprint = fp;
    }

    EnrichedEvent build(SecurityEvent e) {
        return new EnrichedEvent(e, geo, asn, asnOrg, network, deviceFingerprint);
    }
}
