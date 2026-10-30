package com.sentinelstream.ingest.domain.enrich;

import com.sentinelstream.event.Geo;
import com.sentinelstream.event.NetworkType;

/** One row of the IP table: an inclusive IPv4 range and what is known about it. */
public record IpRange(long start, long end, Geo geo, Integer asn, String asnOrg, NetworkType network) {
}
