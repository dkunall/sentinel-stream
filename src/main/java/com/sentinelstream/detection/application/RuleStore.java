package com.sentinelstream.detection.application;

import com.sentinelstream.detection.domain.rule.Severity;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

/** Port: versioned rules and IOC lists. Rule versions are append-only. */
public interface RuleStore {

    /** A global counter bumped by every rule or IOC change; detectors poll it to know when to reload. */
    long changeVersion();

    void bumpChangeVersion();

    /** For every (tenant, rule), its newest version, enabled or not. */
    List<StoredRule> latestVersions();

    List<StoredRule> latestVersions(String tenant);

    Optional<StoredRule> latest(String tenant, String id);

    /** False if that version already exists (a concurrent edit won). */
    boolean insert(StoredRule rule);

    List<IocEntry> iocs();

    List<IocEntry> iocs(String tenant);

    int addIocs(String tenant, String list, String kind, Collection<String> values);

    int removeIoc(String tenant, String list, String kind, String value);

    record StoredRule(String tenant, String id, int version, String name, String dsl, String canonical, String hash,
                      Severity severity, boolean enabled, String createdBy, Instant createdAt) {
    }

    record IocEntry(String tenant, String list, String kind, String value) {
    }
}
