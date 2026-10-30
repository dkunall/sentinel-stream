package com.sentinelstream.shared.security;

import java.util.Optional;

/** Port: look up which tenant a collector API key belongs to, by the key's SHA-256. */
public interface CollectorKeys {

    Optional<CollectorIdentity> byHash(String sha256Hex);

    record CollectorIdentity(String tenant, String collectorId, String name) {
    }
}
