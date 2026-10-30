package com.sentinelstream.response.application;

/** Port: a fast, lossy "seen recently" check in front of the database's authoritative one. */
public interface SignalSeen {

    boolean seen(String signalId);

    void remember(String signalId);
}
