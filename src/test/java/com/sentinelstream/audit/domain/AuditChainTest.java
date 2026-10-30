package com.sentinelstream.audit.domain;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuditChainTest {

    private static List<AuditEntry> entries() {
        List<AuditEntry> out = new ArrayList<>();
        for (int i = 1; i <= 5; i++) {
            out.add(new AuditEntry(i, "acme", Instant.parse("2026-10-30T10:00:00.123456Z").plusSeconds(i), "analyst@acme",
                    "incident.transition", "inc-" + i, "{\"to\": \"TRIAGED\", \"note\": \"tab\\there\"}"));
        }
        return out;
    }

    @Test
    void anyEditRemovalOrReorderChangesTheDigest() {
        var base = entries();
        String d = AuditChain.digest(AuditChain.GENESIS, base);
        assertThat(AuditChain.digest(AuditChain.GENESIS, entries())).isEqualTo(d);

        var edited = entries();
        var e = edited.get(2);
        edited.set(2, new AuditEntry(e.seq(), e.tenant(), e.at(), "admin@acme", e.action(), e.target(), e.detailJson()));
        assertThat(AuditChain.digest(AuditChain.GENESIS, edited)).isNotEqualTo(d);

        var removed = entries();
        removed.remove(1);
        assertThat(AuditChain.digest(AuditChain.GENESIS, removed)).isNotEqualTo(d);

        var swapped = entries();
        java.util.Collections.swap(swapped, 0, 1);
        assertThat(AuditChain.digest(AuditChain.GENESIS, swapped)).isNotEqualTo(d);

        assertThat(AuditChain.digest(d, base)).as("a different predecessor changes this batch too").isNotEqualTo(d);
    }

    @Test
    void linesRoundTripIncludingTabsAndNewlines() {
        var e = new AuditEntry(9, "acme", Instant.parse("2026-10-30T10:00:00.000001Z"), "a\tb", "x\ny", "back\\slash", "{}");
        assertThat(AuditEntry.parse(e.line())).isEqualTo(e);
        assertThat(e.line().split("\t", -1)).hasSize(7);
    }

    @Test
    void signaturesVerifyOnlyForTheSignedMessage() {
        var signer = Ed25519Signer.generate();
        String msg = AuditChain.signedMessage("b1", "acme", AuditChain.GENESIS, "ab", 5);
        String sig = signer.sign(msg);
        assertThat(signer.verify(msg, sig)).isTrue();
        assertThat(signer.verify(msg.replace("acme", "globex"), sig)).isFalse();
        assertThat(signer.verify(msg, "not-base64!")).isFalse();
    }

    @Test
    void aPemPrivateKeyLoadsAndDerivesTheMatchingPublicKey() throws Exception {
        var kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        String pem = "-----BEGIN PRIVATE KEY-----\n" + Base64.getMimeEncoder().encodeToString(kp.getPrivate().getEncoded())
                + "\n-----END PRIVATE KEY-----\n";
        var signer = Ed25519Signer.fromPem(pem);
        String sig = signer.sign("hello");
        assertThat(Ed25519Signer.verify(kp.getPublic(), "hello", sig)).isTrue();
        assertThat(Ed25519Signer.verify(Ed25519Signer.publicFromPem(signer.publicKeyPem()), "hello", sig)).isTrue();
        assertThatThrownBy(() -> Ed25519Signer.fromPem("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(pem.getBytes(StandardCharsets.US_ASCII)).isNotEmpty();
    }
}
