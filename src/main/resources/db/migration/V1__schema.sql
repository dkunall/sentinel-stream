-- Collectors authenticate with an API key; only its SHA-256 is stored.
create table collector (
    id          uuid primary key default gen_random_uuid(),
    tenant_id   text        not null,
    name        text        not null,
    key_hash    text        not null unique,
    created_by  text        not null,
    created_at  timestamptz not null default now(),
    revoked_at  timestamptz
);

-- Every edit of a rule is a new version; the highest version is the live one.
create table rule (
    tenant_id     text        not null,
    id            text        not null,
    version       int         not null,
    name          text        not null,
    dsl           text        not null,
    canonical     text        not null,
    compiled_hash text        not null,
    severity      text        not null check (severity in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    enabled       boolean     not null,
    created_by    text        not null,
    created_at    timestamptz not null default now(),
    primary key (tenant_id, id, version)
);

create table ioc_entry (
    tenant_id text not null,
    list_name text not null,
    kind      text not null check (kind in ('ip', 'user_agent')),
    value     text not null,
    primary key (tenant_id, list_name, kind, value)
);

-- Bumped in the same transaction as any rule or IOC change; detectors poll it.
create table ruleset_version (
    id      int primary key check (id = 1),
    version bigint not null
);
insert into ruleset_version values (1, 1);

-- Searchable copy of normalized events, one partition per UTC day; retention drops partitions.
create table event (
    tenant_id   text        not null,
    id          text        not null,
    ts          timestamptz not null,
    ingested_at timestamptz not null,
    user_name   text,
    ip          text,
    action      text        not null,
    outcome     text        not null,
    user_agent  text,
    device_fp   text,
    source      text        not null,
    country     text,
    city        text,
    asn         int,
    network     text        not null,
    primary key (tenant_id, id, ts)
) partition by range (ts);
create index event_user_idx on event (tenant_id, user_name, ts desc);
create index event_ip_idx on event (tenant_id, ip, ts desc);
create index event_ts_idx on event (tenant_id, ts desc, id desc);

-- One row per detector signal; the primary key makes redelivered signals no-ops.
create table alert_signal (
    signal_id   text primary key,
    tenant_id   text        not null,
    alert_id    uuid        not null,
    event_ts    timestamptz not null,
    ingested_at timestamptz not null,
    received_at timestamptz not null default now()
);
create index alert_signal_received_idx on alert_signal (tenant_id, received_at);

create table alert (
    id             uuid primary key,
    tenant_id      text        not null,
    fingerprint    text        not null unique,
    rule_id        text        not null,
    rule_version   int         not null,
    rule_name      text        not null,
    severity       text        not null,
    confidence     text        not null,
    entity_kind    text        not null,
    entity_key     text        not null,
    count          int         not null,
    first_seen     timestamptz not null,
    last_seen      timestamptz not null,
    status         text        not null check (status in ('OPEN', 'CLOSED')),
    summary        text        not null,
    event_ids      jsonb       not null,
    created_at     timestamptz not null default now()
);
create index alert_tenant_status_idx on alert (tenant_id, status, last_seen desc);

create table incident (
    id            uuid primary key,
    tenant_id     text        not null,
    entity_kind   text        not null,
    entity_key    text        not null,
    state         text        not null check (state in ('NEW', 'TRIAGED', 'FALSE_POSITIVE', 'INVESTIGATING', 'CONTAINED', 'RESOLVED')),
    severity      text        not null,
    title         text        not null,
    opened_at     timestamptz not null,
    last_alert_at timestamptz not null,
    updated_at    timestamptz not null,
    version       int         not null default 0
);
create index incident_entity_idx on incident (tenant_id, entity_kind, entity_key, last_alert_at desc);
create index incident_state_idx on incident (tenant_id, state, updated_at desc);

create table incident_alert (
    incident_id uuid not null references incident (id),
    alert_id    uuid not null references alert (id),
    primary key (incident_id, alert_id)
);
create unique index incident_alert_one_incident on incident_alert (alert_id);

create table incident_transition (
    id          bigserial primary key,
    incident_id uuid        not null references incident (id),
    from_state  text        not null,
    to_state    text        not null,
    actor       text        not null,
    note        text,
    at          timestamptz not null default now()
);

create table playbook (
    tenant_id      text    not null,
    id             text    not null,
    name           text    not null,
    trigger_rules  jsonb   not null,
    steps          jsonb   not null,
    needs_approval boolean not null,
    primary key (tenant_id, id)
);

create table playbook_run (
    id           uuid primary key,
    tenant_id    text        not null,
    playbook_id  text        not null,
    incident_id  uuid        not null references incident (id),
    status       text        not null check (status in ('PENDING_APPROVAL', 'APPROVED', 'RUNNING', 'SUCCEEDED', 'FAILED', 'REJECTED')),
    requested_by text        not null,
    approved_by  text,
    created_at   timestamptz not null default now(),
    started_at   timestamptz,
    finished_at  timestamptz,
    error        text
);
-- one live run of a playbook per incident; a failed or rejected run can be requested again
create unique index playbook_run_live on playbook_run (incident_id, playbook_id)
    where status in ('PENDING_APPROVAL', 'APPROVED', 'RUNNING', 'SUCCEEDED');

create table playbook_step_result (
    run_id  uuid        not null references playbook_run (id),
    idx     int         not null,
    kind    text        not null,
    status  text        not null,
    detail  text        not null,
    at      timestamptz not null default now(),
    primary key (run_id, idx)
);

-- Synthetic accounts the LOCK_ACCOUNT step acts on; nothing outside this table is touched.
create table demo_account (
    tenant_id     text        not null,
    user_name     text        not null,
    locked        boolean     not null default false,
    locked_at     timestamptz,
    locked_by_run uuid,
    primary key (tenant_id, user_name)
);

create table outbox (
    id              bigserial primary key,
    tenant_id       text        not null,
    run_id          uuid,
    dedup_key       text        not null unique,
    target_url      text        not null,
    payload         jsonb       not null,
    attempts        int         not null default 0,
    next_attempt_at timestamptz not null default now(),
    sent_at         timestamptz,
    last_error      text
);
create index outbox_pending_idx on outbox (next_attempt_at) where sent_at is null;

-- What the in-app demo webhook receiver got, so the demo can show the HMAC check.
create table webhook_delivery (
    id           bigserial primary key,
    received_at  timestamptz not null default now(),
    signature_ok boolean     not null,
    delivery_id  text,
    body         jsonb       not null
);

create table audit_log (
    seq       bigserial primary key,
    tenant_id text        not null,
    at        timestamptz not null default now(),
    actor     text        not null,
    action    text        not null,
    target    text        not null,
    detail    jsonb       not null,
    batch_id  uuid
);
create index audit_log_unsealed_idx on audit_log (tenant_id, seq) where batch_id is null;

create table audit_batch (
    id          uuid primary key,
    tenant_id   text        not null,
    from_seq    bigint      not null,
    to_seq      bigint      not null,
    entries     int         not null,
    prev_digest text        not null,
    digest      text        not null,
    signature   text        not null,
    object_key  text        not null,
    sealed_at   timestamptz not null default now(),
    retain_until timestamptz not null
);
create index audit_batch_tenant_idx on audit_batch (tenant_id, to_seq desc);
