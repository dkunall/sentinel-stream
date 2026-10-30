package com.sentinelstream.ingest.domain.enrich;

import com.sentinelstream.event.Geo;
import com.sentinelstream.event.NetworkType;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

/**
 * IPv4 range lookup by binary search over sorted, non-overlapping ranges, the same shape as a GeoLite2
 * CSV export. The bundled data is synthetic and only covers documentation and benchmarking ranges
 * (RFC 5737, RFC 2544) with documentation ASNs (RFC 5398), so the demo never resolves a real address.
 */
public final class IpRangeTable {

    private final long[] starts;
    private final IpRange[] ranges;

    public IpRangeTable(List<IpRange> rows) {
        List<IpRange> sorted = new ArrayList<>(rows);
        sorted.sort(Comparator.comparingLong(IpRange::start));
        for (int i = 1; i < sorted.size(); i++) {
            if (sorted.get(i).start() <= sorted.get(i - 1).end()) {
                throw new IllegalArgumentException("overlapping ranges at row " + i);
            }
        }
        this.ranges = sorted.toArray(IpRange[]::new);
        this.starts = sorted.stream().mapToLong(IpRange::start).toArray();
    }

    public Optional<IpRange> lookup(String ip) {
        if (ip == null) {
            return Optional.empty();
        }
        long addr;
        try {
            addr = toLong(ip);
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
        int lo = 0, hi = starts.length - 1, found = -1;
        while (lo <= hi) {
            int mid = (lo + hi) >>> 1;
            if (starts[mid] <= addr) {
                found = mid;
                lo = mid + 1;
            } else {
                hi = mid - 1;
            }
        }
        if (found < 0 || ranges[found].end() < addr) {
            return Optional.empty();
        }
        return Optional.of(ranges[found]);
    }

    public int size() {
        return ranges.length;
    }

    /** Reads {@code cidr,country,city,lat,lon,asn,asn_org,network}; '#' starts a comment. */
    public static IpRangeTable fromCsv(Reader in) throws IOException {
        List<IpRange> rows = new ArrayList<>();
        try (BufferedReader r = new BufferedReader(in)) {
            String line;
            int n = 0;
            while ((line = r.readLine()) != null) {
                n++;
                line = line.strip();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                String[] c = line.split(",", -1);
                if (c.length != 8) {
                    throw new IOException("line " + n + ": expected 8 columns");
                }
                long[] span = cidr(c[0]);
                Geo geo = c[1].isEmpty() ? null : new Geo(c[1], c[2], Double.parseDouble(c[3]), Double.parseDouble(c[4]));
                Integer asn = c[5].isEmpty() ? null : Integer.valueOf(c[5]);
                rows.add(new IpRange(span[0], span[1], geo, asn, c[6].isEmpty() ? null : c[6], NetworkType.valueOf(c[7])));
            }
        }
        return new IpRangeTable(rows);
    }

    static long[] cidr(String cidr) {
        String[] p = cidr.split("/");
        long base = toLong(p[0]);
        int bits = Integer.parseInt(p[1]);
        long size = 1L << (32 - bits);
        long start = base & ~(size - 1) & 0xFFFFFFFFL;
        return new long[]{start, start + size - 1};
    }

    static long toLong(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) {
            throw new IllegalArgumentException("not IPv4: " + ip);
        }
        long v = 0;
        for (String part : parts) {
            int octet = Integer.parseInt(part);
            if (octet < 0 || octet > 255) {
                throw new IllegalArgumentException("not IPv4: " + ip);
            }
            v = (v << 8) | octet;
        }
        return v;
    }
}
