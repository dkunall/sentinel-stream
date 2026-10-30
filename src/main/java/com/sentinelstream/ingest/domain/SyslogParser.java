package com.sentinelstream.ingest.domain;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses RFC 5424 syslog lines into the same field map the HTTP SDK sends. Two message shapes are
 * understood: a structured-data element {@code [login@32473 ...]} carrying the fields directly, and
 * OpenSSH-style "Failed password for ... from ..." text. Lines without an event id get one derived
 * from a hash of the line, so a collector re-sending the same line is deduplicated downstream.
 */
public final class SyslogParser {

    public sealed interface Result {
        record Parsed(Map<String, Object> fields) implements Result {
        }

        record Unparsed(String reason) implements Result {
        }
    }

    // <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA [MSG]
    private static final Pattern HEADER = Pattern.compile(
            "^<(\\d{1,3})>1 (\\S+) (\\S+) (\\S+) (\\S+) (\\S+) (-|(?:\\[.*?(?<!\\\\)\\])+)(?: (.*))?$");
    private static final Pattern SD_ELEMENT = Pattern.compile("\\[(\\S+?)((?: [^=\\s]+=\"(?:[^\"\\\\]|\\\\.)*\")*)\\]");
    private static final Pattern SD_PARAM = Pattern.compile(" ([^=\\s]+)=\"((?:[^\"\\\\]|\\\\.)*)\"");
    private static final Pattern SSH_FAILED = Pattern.compile(
            "Failed (?:password|publickey) for (?:invalid user )?(\\S+) from (\\S+) port \\d+");
    private static final Pattern SSH_ACCEPTED = Pattern.compile(
            "Accepted (?:password|publickey|keyboard-interactive/pam) for (\\S+) from (\\S+) port \\d+");

    public Result parse(String line) {
        if (line == null || line.isBlank()) {
            return new Result.Unparsed("empty line");
        }
        if (line.length() > 8192) {
            return new Result.Unparsed("line longer than 8192 characters");
        }
        Matcher h = HEADER.matcher(line.strip());
        if (!h.matches()) {
            return new Result.Unparsed("not RFC 5424");
        }
        Map<String, Object> fields = new HashMap<>();
        fields.put("ts", h.group(2));
        String app = h.group(4);
        String sd = h.group(7);
        String msg = h.group(8) == null ? "" : h.group(8);
        if (!"-".equals(sd)) {
            Matcher el = SD_ELEMENT.matcher(sd);
            while (el.find()) {
                if (el.group(1).startsWith("login@")) {
                    Matcher p = SD_PARAM.matcher(el.group(2));
                    while (p.find()) {
                        fields.put(sdKey(p.group(1)), p.group(2).replace("\\\"", "\"").replace("\\]", "]")
                                .replace("\\\\", "\\"));
                    }
                }
            }
        }
        if (!fields.containsKey("action")) {
            Matcher m;
            if ((m = SSH_FAILED.matcher(msg)).find()) {
                fields.put("action", "login");
                fields.put("outcome", "failure");
                fields.put("user", m.group(1));
                fields.put("ip", m.group(2));
            } else if ((m = SSH_ACCEPTED.matcher(msg)).find()) {
                fields.put("action", "login");
                fields.put("outcome", "success");
                fields.put("user", m.group(1));
                fields.put("ip", m.group(2));
            } else {
                return new Result.Unparsed("no login@ structured data and no recognised " + app + " message");
            }
            fields.putIfAbsent("user_agent", app);
        }
        fields.putIfAbsent("id", "sl-" + sha256(line.strip()).substring(0, 32));
        return new Result.Parsed(fields);
    }

    private static String sdKey(String k) {
        return switch (k) {
            case "ua" -> "user_agent";
            case "device" -> "device_id";
            default -> k;
        };
    }

    static String sha256(String s) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
