package com.sentinelstream.playbook.adapter.http;

import com.sentinelstream.playbook.domain.WebhookSignature;
import com.sentinelstream.shared.security.Actor;
import com.sentinelstream.shared.security.Actors;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/**
 * A receiver living in the same app so the demo can show the whole webhook path without an outside
 * service. It checks the HMAC and stores only correctly signed deliveries, deduplicated on the
 * delivery key, so an unauthenticated caller cannot fill the table.
 */
@RestController
class DemoWebhookSink {

    private final JdbcTemplate jdbc;
    private final WebhookSecret secret;
    private final MeterRegistry meters;

    DemoWebhookSink(JdbcTemplate jdbc, WebhookSecret secret, MeterRegistry meters) {
        this.jdbc = jdbc;
        this.secret = secret;
        this.meters = meters;
    }

    @PostMapping(value = "/demo/webhook-sink", consumes = "application/json")
    ResponseEntity<Void> receive(@RequestBody byte[] body, @RequestHeader(value = "X-Sentinel-Signature", required = false) String sig,
                                 @RequestHeader(value = "X-Sentinel-Delivery", required = false) String delivery) {
        if (body.length > 16_384 || !WebhookSignature.verify(secret.value(), body, sig)) {
            meters.counter("sentinel.webhook_sink", "result", "rejected").increment();
            return ResponseEntity.status(401).build();
        }
        String json = new String(body, StandardCharsets.UTF_8);
        jdbc.update("""
                insert into webhook_delivery (signature_ok, delivery_id, body)
                select true, ?, ?::jsonb
                where not exists (select 1 from webhook_delivery where body->>'deliveryKey' = (?::jsonb)->>'deliveryKey')
                """, delivery, json, json);
        meters.counter("sentinel.webhook_sink", "result", "accepted").increment();
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/v1/demo/webhook-deliveries")
    List<Map<String, Object>> deliveries() {
        Actor actor = Actors.require(Actor.ADMIN);
        return jdbc.queryForList("""
                select id, received_at, signature_ok, delivery_id, body::text as body from webhook_delivery
                where body->>'tenant' = ? order by id desc limit 50
                """, actor.tenant());
    }
}
