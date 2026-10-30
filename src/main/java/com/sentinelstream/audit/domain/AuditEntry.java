package com.sentinelstream.audit.domain;

import java.time.Instant;

/** One audit row. {@code detailJson} is Postgres' canonical jsonb text, so it reads back byte-identical. */
public record AuditEntry(long seq, String tenant, Instant at, String actor, String action, String target, String detailJson) {

    /** The exact text that is hashed. Fields are tab-separated; tabs and newlines inside values are escaped. */
    public String line() {
        return seq + "\t" + esc(tenant) + "\t" + at + "\t" + esc(actor) + "\t" + esc(action) + "\t" + esc(target) + "\t" + esc(detailJson);
    }

    public static AuditEntry parse(String line) {
        String[] f = line.split("\t", -1);
        if (f.length != 7) {
            throw new IllegalArgumentException("malformed audit line");
        }
        return new AuditEntry(Long.parseLong(f[0]), unesc(f[1]), Instant.parse(f[2]), unesc(f[3]), unesc(f[4]), unesc(f[5]), unesc(f[6]));
    }

    private static String esc(String s) {
        return s.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n");
    }

    private static String unesc(String s) {
        StringBuilder b = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' && i + 1 < s.length()) {
                char n = s.charAt(++i);
                b.append(n == 't' ? '\t' : n == 'n' ? '\n' : n);
            } else {
                b.append(c);
            }
        }
        return b.toString();
    }
}
