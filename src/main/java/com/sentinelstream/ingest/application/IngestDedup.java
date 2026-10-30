package com.sentinelstream.ingest.application;

import java.time.Duration;

/** Port: remembers which event ids a tenant already sent, for a bounded time. */
public interface IngestDedup {

    /** True if this id was not seen before (and is now claimed). */
    boolean claim(String tenant, String eventId, Duration ttl);

    /** Forget a claim, so a client retrying after a failed publish is not treated as a duplicate. */
    void release(String tenant, String eventId);
}
