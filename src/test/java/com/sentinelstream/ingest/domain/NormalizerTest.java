package com.sentinelstream.ingest.domain;

import com.sentinelstream.event.Outcome;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class NormalizerTest {

    static final Instant NOW = Instant.parse("2026-10-30T12:00:00Z");
    final Normalizer normalizer = new Normalizer(Clock.fixed(NOW, ZoneOffset.UTC), Duration.ofDays(30), Duration.ofMinutes(5));

    Map<String, Object> login() {
        Map<String, Object> m = new HashMap<>();
        m.put("id", "evt-1");
        m.put("ts", "2026-10-30T11:59:00Z");
        m.put("user", "Asha@Example.test");
        m.put("ip", "198.51.100.7");
        m.put("action", "login");
        m.put("outcome", "failed");
        m.put("user_agent", "Mozilla/5.0");
        m.put("password", "never-kept");
        return m;
    }

    @Test
    void mapsAnSdkEventOntoTheCommonSchema() {
        var result = normalizer.normalize(RawEnvelope.http("acme", NOW, login()));

        assertThat(result).isInstanceOf(Normalized.Ok.class);
        var e = ((Normalized.Ok) result).event();
        assertThat(e.user()).isEqualTo("asha@example.test");
        assertThat(e.outcome()).isEqualTo(Outcome.FAILURE);
        assertThat(e.tenant()).isEqualTo("acme");
        assertThat(e.source()).isEqualTo("http");
        assertThat(e.ingestedAt()).isEqualTo(NOW);
    }

    @Test
    void rejectsWithAReasonInsteadOfThrowing() {
        var m = login();
        m.remove("id");
        assertThat(reason(m)).isEqualTo("id is required");

        m = login();
        m.put("ts", "2026-10-30T12:10:00Z");
        assertThat(reason(m)).contains("in the future");

        m = login();
        m.put("ts", "2026-09-01T00:00:00Z");
        assertThat(reason(m)).contains("older than 30 days");

        m = login();
        m.put("ip", "999.1.1.1");
        assertThat(reason(m)).contains("IPv4");

        m = login();
        m.put("outcome", "maybe");
        assertThat(reason(m)).contains("unknown outcome");

        m = login();
        m.remove("user");
        m.remove("ip");
        assertThat(reason(m)).contains("user or an ip");

        m = login();
        m.put("ts", "yesterday");
        assertThat(reason(m)).contains("ISO-8601");
    }

    @Test
    void truncatesVeryLongUserAgents() {
        var m = login();
        m.put("user_agent", "x".repeat(2000));
        var e = ((Normalized.Ok) normalizer.normalize(RawEnvelope.http("acme", NOW, m))).event();
        assertThat(e.userAgent()).hasSize(512);
    }

    @Test
    void normalizesSyslogLinesThroughTheSameRules() {
        String line = "<38>1 2026-10-30T11:58:00Z bastion sshd 811 - - Failed password for invalid user admin from 203.0.113.9 port 50122 ssh2";
        var e = ((Normalized.Ok) normalizer.normalize(RawEnvelope.syslog("acme", NOW, line))).event();
        assertThat(e.action()).isEqualTo("login");
        assertThat(e.outcome()).isEqualTo(Outcome.FAILURE);
        assertThat(e.user()).isEqualTo("admin");
        assertThat(e.ip()).isEqualTo("203.0.113.9");
        assertThat(e.source()).isEqualTo("syslog");

        var bad = normalizer.normalize(RawEnvelope.syslog("acme", NOW, "hello world"));
        assertThat(((Normalized.Rejected) bad).reason()).isEqualTo("syslog: not RFC 5424");
    }

    private String reason(Map<String, Object> payload) {
        var r = normalizer.normalize(RawEnvelope.http("acme", NOW, payload));
        assertThat(r).isInstanceOf(Normalized.Rejected.class);
        return ((Normalized.Rejected) r).reason();
    }
}
