package com.sentinelstream.audit.application;

import java.time.Instant;
import java.util.Optional;

/** Port: write-once object storage with a compliance retention lock. */
public interface LockedObjectStore {

    void putLocked(String key, byte[] body, Instant retainUntil);

    byte[] get(String key);

    /** The retention the store reports for the object, if any. */
    Optional<Retention> retention(String key);

    record Retention(String mode, Instant until) {
    }
}
