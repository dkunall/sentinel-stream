package com.sentinelstream.ingest.application;

import com.sentinelstream.ingest.domain.RawEnvelope;

import java.util.concurrent.CompletableFuture;

/** Port: hands a raw envelope to the pipeline; completes once the broker has acknowledged it. */
public interface RawEventPublisher {

    CompletableFuture<Void> publish(String key, RawEnvelope envelope);
}
