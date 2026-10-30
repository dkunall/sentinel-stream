package com.sentinelstream.search.domain;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PiiMaskerTest {

    @Test
    void masksUsersKeepingTheDomain() {
        assertThat(PiiMasker.user("asha@example.test")).isEqualTo("a***@example.test");
        assertThat(PiiMasker.user("svc-backup")).isEqualTo("s***");
        assertThat(PiiMasker.user(null)).isNull();
    }

    @Test
    void masksTheHostPartOfAddresses() {
        assertThat(PiiMasker.ip("198.51.100.7")).isEqualTo("198.51.100.x");
        assertThat(PiiMasker.ip("2001:db8:1:2:3:4:5:6")).isEqualTo("2001:db8:1:2:x");
        assertThat(PiiMasker.ip(null)).isNull();
    }

    @Test
    void cursorRoundTripsAndRejectsGarbage() {
        var c = new SearchCursor(Instant.parse("2026-10-30T12:00:00.123Z"), "evt|with|bars");
        assertThat(SearchCursor.decode(c.encode())).isEqualTo(c);
        assertThatThrownBy(() -> SearchCursor.decode("!!!")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SearchCursor.decode("bm9iYXI")).isInstanceOf(IllegalArgumentException.class);
    }
}
