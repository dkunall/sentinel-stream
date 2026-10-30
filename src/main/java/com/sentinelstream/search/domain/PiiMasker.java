package com.sentinelstream.search.domain;

/**
 * What an analyst without the PII scope sees: enough to tell users and networks apart in a list,
 * not enough to identify a person. {@code asha@example.test → a***@example.test},
 * {@code 198.51.100.7 → 198.51.100.x}, IPv6 keeps its first four groups.
 */
public final class PiiMasker {

    private PiiMasker() {
    }

    public static String user(String user) {
        if (user == null || user.isEmpty()) {
            return user;
        }
        int at = user.indexOf('@');
        if (at > 0) {
            return user.charAt(0) + "***" + user.substring(at);
        }
        return user.charAt(0) + "***";
    }

    public static String ip(String ip) {
        if (ip == null || ip.isEmpty()) {
            return ip;
        }
        if (ip.indexOf(':') >= 0) {
            String[] groups = ip.split(":", -1);
            StringBuilder b = new StringBuilder();
            for (int i = 0; i < Math.min(4, groups.length); i++) {
                b.append(groups[i]).append(':');
            }
            return b.append('x').toString();
        }
        int last = ip.lastIndexOf('.');
        return last < 0 ? "x" : ip.substring(0, last) + ".x";
    }
}
