package com.sentinelstream.playbook.domain;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class StepTest {

    private static final Set<String> HOSTS = Set.of("localhost", "127.0.0.1");

    @ParameterizedTest
    @ValueSource(strings = {"http://example.com/hook", "file:///etc/passwd", "http://user@localhost/x", "ftp://localhost/x",
            "http://localhost.example.com/x", "http://169.254.169.254/latest", "not a url"})
    void webhooksOnlyGoToAllowListedHosts(String url) {
        assertThatThrownBy(() -> new Step(StepKind.NOTIFY_WEBHOOK, Map.of("url", url)).validate(HOSTS))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void localWebhookAndIocStepsValidate() {
        new Step(StepKind.NOTIFY_WEBHOOK, Map.of("url", "http://localhost:8080/demo/webhook-sink")).validate(HOSTS);
        new Step(StepKind.ADD_TO_IOC_LIST, Map.of("list", "blocked")).validate(HOSTS);
        assertThatThrownBy(() -> new Step(StepKind.ADD_TO_IOC_LIST, Map.of()).validate(HOSTS)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void signatureCoversTheExactBody() {
        byte[] body = "{\"a\":1}".getBytes(StandardCharsets.UTF_8);
        String sig = WebhookSignature.sign("0123456789abcdef", body);
        assertThat(sig).startsWith("sha256=").hasSize(7 + 64);
        assertThat(WebhookSignature.verify("0123456789abcdef", body, sig)).isTrue();
        assertThat(WebhookSignature.verify("0123456789abcdef", "{\"a\":2}".getBytes(StandardCharsets.UTF_8), sig)).isFalse();
        assertThat(WebhookSignature.verify("other-secret-xxxxxx", body, sig)).isFalse();
        assertThat(WebhookSignature.verify("0123456789abcdef", body, null)).isFalse();
    }
}
