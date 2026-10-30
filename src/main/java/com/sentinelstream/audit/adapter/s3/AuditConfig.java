package com.sentinelstream.audit.adapter.s3;

import com.sentinelstream.audit.application.LockedObjectStore;
import com.sentinelstream.audit.domain.Ed25519Signer;
import com.sentinelstream.shared.config.SentinelProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
class AuditConfig {

    private static final Logger log = LoggerFactory.getLogger(AuditConfig.class);

    @Bean
    @ConditionalOnMissingBean(LockedObjectStore.class)
    LockedObjectStore lockedObjectStore(SentinelProperties props) {
        return new S3LockedObjectStore(props.audit());
    }

    @Bean
    Ed25519Signer auditSigner(SentinelProperties props) {
        String pem = props.audit().signingKeyPem();
        if (pem == null || pem.isBlank()) {
            log.warn("SENTINEL_AUDIT_SIGNING_KEY is not set: using an ephemeral key; batches sealed now will not "
                    + "verify after a restart");
            return Ed25519Signer.generate();
        }
        return Ed25519Signer.fromPem(pem);
    }
}
