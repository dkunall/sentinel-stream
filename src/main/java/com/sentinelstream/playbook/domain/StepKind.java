package com.sentinelstream.playbook.domain;

/**
 * What a playbook step may do. Every action stays inside this system: a flag on a synthetic demo
 * account, an entry in the tenant's own IOC list, or a signed webhook to an allow-listed local URL.
 */
public enum StepKind {
    LOCK_ACCOUNT, ADD_TO_IOC_LIST, NOTIFY_WEBHOOK
}
