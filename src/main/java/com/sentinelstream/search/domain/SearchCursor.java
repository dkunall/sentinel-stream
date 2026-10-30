package com.sentinelstream.search.domain;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Base64;

/** Keyset position: the (ts, id) of the last row returned, opaque to clients. */
public record SearchCursor(Instant ts, String id) {

    public String encode() {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString((ts.toString() + "|" + id).getBytes(StandardCharsets.UTF_8));
    }

    public static SearchCursor decode(String s) {
        try {
            String plain = new String(Base64.getUrlDecoder().decode(s), StandardCharsets.UTF_8);
            int bar = plain.indexOf('|');
            if (bar <= 0 || bar == plain.length() - 1) {
                throw new IllegalArgumentException("malformed cursor");
            }
            return new SearchCursor(Instant.parse(plain.substring(0, bar)), plain.substring(bar + 1));
        } catch (IllegalArgumentException | DateTimeParseException e) {
            throw new IllegalArgumentException("malformed cursor");
        }
    }
}
