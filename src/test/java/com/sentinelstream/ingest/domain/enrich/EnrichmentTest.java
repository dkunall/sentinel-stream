package com.sentinelstream.ingest.domain.enrich;

import com.sentinelstream.event.NetworkType;
import com.sentinelstream.event.Outcome;
import com.sentinelstream.event.SecurityEvent;
import org.junit.jupiter.api.Test;

import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class EnrichmentTest {

    static IpRangeTable bundled() throws Exception {
        try (var in = EnrichmentTest.class.getResourceAsStream("/geo/synthetic-ip-table.csv")) {
            return IpRangeTable.fromCsv(new InputStreamReader(in, StandardCharsets.UTF_8));
        }
    }

    static SecurityEvent event(String ip, String device, String ua) {
        Instant t = Instant.parse("2026-10-30T10:00:00Z");
        return new SecurityEvent("e1", "acme", t, "asha", ip, "login", Outcome.SUCCESS, ua, device, "http", t);
    }

    @Test
    void bundledTableOnlyCoversDocumentationRanges() throws Exception {
        IpRangeTable t = bundled();
        assertThat(t.size()).isEqualTo(8);
        assertThat(t.lookup("198.51.100.7")).get().satisfies(r -> {
            assertThat(r.geo().city()).isEqualTo("Bengaluru");
            assertThat(r.asn()).isEqualTo(64496);
        });
        assertThat(t.lookup("198.51.100.200").get().network()).isEqualTo(NetworkType.MOBILE);
        assertThat(t.lookup("203.0.113.130").get().network()).isEqualTo(NetworkType.VPN);
        assertThat(t.lookup("10.1.2.3").get().geo()).isNull();
        assertThat(t.lookup("8.8.8.8")).isEmpty();
        assertThat(t.lookup("not-an-ip")).isEmpty();
    }

    @Test
    void rangeEdgesAreInclusive() {
        long[] span = IpRangeTable.cidr("192.0.2.0/24");
        var t = new IpRangeTable(List.of(new IpRange(span[0], span[1], null, 1, "x", NetworkType.HOSTING)));
        assertThat(t.lookup("192.0.2.0")).isPresent();
        assertThat(t.lookup("192.0.2.255")).isPresent();
        assertThat(t.lookup("192.0.3.0")).isEmpty();
        assertThat(t.lookup("192.0.1.255")).isEmpty();
    }

    @Test
    void overlappingRangesAreRefused() {
        assertThatThrownBy(() -> new IpRangeTable(List.of(
                new IpRange(0, 10, null, 1, "a", NetworkType.UNKNOWN),
                new IpRange(10, 20, null, 2, "b", NetworkType.UNKNOWN))))
                .hasMessageContaining("overlapping");
    }

    @Test
    void chainFillsGeoAsnAndDevice() throws Exception {
        var chain = EnricherChain.standard(bundled());
        var e = chain.enrich(event("203.0.113.5", "dev-1", "Mozilla/5.0"));
        assertThat(e.geo().city()).isEqualTo("Frankfurt");
        assertThat(e.asn()).isEqualTo(64500);
        assertThat(e.network()).isEqualTo(NetworkType.HOSTING);
        assertThat(e.deviceFingerprint()).hasSize(16)
                .isEqualTo(chain.enrich(event("198.51.100.1", "dev-1", "MOZILLA/5.0")).deviceFingerprint());

        var unknown = chain.enrich(event("8.8.4.4", null, null));
        assertThat(unknown.geo()).isNull();
        assertThat(unknown.network()).isEqualTo(NetworkType.UNKNOWN);
        assertThat(unknown.deviceFingerprint()).isNull();
    }
}
