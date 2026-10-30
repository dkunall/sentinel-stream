package com.sentinelstream.playbook.adapter.http;

import com.sentinelstream.shared.config.SentinelProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.HexFormat;

/** The HMAC key shared with webhook receivers. Never logged. */
@Component
class WebhookSecret {

    private static final Logger log = LoggerFactory.getLogger(WebhookSecret.class);

    private final String value;

    WebhookSecret(SentinelProperties props) {
        String configured = props.webhooks().secret();
        if (configured == null || configured.length() < 16) {
            byte[] b = new byte[32];
            new SecureRandom().nextBytes(b);
            this.value = HexFormat.of().formatHex(b);
            log.warn("SENTINEL_WEBHOOK_SECRET is unset or shorter than 16 characters; using a random per-process secret");
        } else {
            this.value = configured;
        }
    }

    String value() {
        return value;
    }

    @Override
    public String toString() {
        return "WebhookSecret[redacted]";
    }
}
