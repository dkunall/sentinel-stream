package com.sentinelstream.shared.audit;

import java.util.Map;

/**
 * Port for writing one audit entry. Implementations write in the caller's transaction, so an entry
 * exists exactly when the change it describes was committed.
 */
public interface AuditRecorder {

    void record(String tenant, String actor, String action, String target, Map<String, ?> detail);
}
