package com.sentinelstream.ingest.domain;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SyslogParserTest {

    final SyslogParser parser = new SyslogParser();

    @Test
    void readsFieldsFromTheLoginStructuredDataElement() {
        String line = "<86>1 2026-10-30T10:00:00Z idp auth - LOGIN [meta@1 x=\"y\"][login@32473 id=\"e-9\" user=\"ravi\" "
                + "ip=\"198.51.100.20\" action=\"login\" outcome=\"success\" ua=\"Agent \\\"quoted\\\"\" device=\"d-1\"] ok";
        var fields = ((SyslogParser.Result.Parsed) parser.parse(line)).fields();
        assertThat(fields)
                .containsEntry("id", "e-9")
                .containsEntry("user", "ravi")
                .containsEntry("outcome", "success")
                .containsEntry("user_agent", "Agent \"quoted\"")
                .containsEntry("device_id", "d-1")
                .containsEntry("ts", "2026-10-30T10:00:00Z")
                .doesNotContainKey("x");
    }

    @Test
    void understandsOpenSshAcceptedLines() {
        String line = "<38>1 2026-10-30T10:00:00Z bastion sshd 77 - - Accepted publickey for deploy from 198.18.0.5 port 4222 ssh2";
        var fields = ((SyslogParser.Result.Parsed) parser.parse(line)).fields();
        assertThat(fields).containsEntry("outcome", "success").containsEntry("user", "deploy")
                .containsEntry("ip", "198.18.0.5").containsEntry("user_agent", "sshd");
    }

    @Test
    void derivesAStableIdSoResentLinesDeduplicate() {
        String line = "<38>1 2026-10-30T10:00:00Z bastion sshd 77 - - Failed password for root from 203.0.113.1 port 1 ssh2";
        var a = ((SyslogParser.Result.Parsed) parser.parse(line)).fields().get("id");
        var b = ((SyslogParser.Result.Parsed) parser.parse(line + "  ")).fields().get("id");
        assertThat(a).isEqualTo(b).asString().startsWith("sl-");
    }

    @Test
    void saysWhyALineWasNotUnderstood() {
        assertThat(parser.parse("")).isEqualTo(new SyslogParser.Result.Unparsed("empty line"));
        assertThat(parser.parse("<38>1 2026-10-30T10:00:00Z host cron 1 - - job finished"))
                .isEqualTo(new SyslogParser.Result.Unparsed("no login@ structured data and no recognised cron message"));
    }
}
