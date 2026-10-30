# Sentinel Stream

Sentinel Stream is a small security-monitoring backend. It takes authentication events, normalises and enriches them, and runs per-user and per-IP detection rules over them in Kafka Streams. Detections become alerts and then incidents. Analysts can run approved response playbooks on an incident, and every change is written to an audit trail that is signed and stored under S3 object lock.

It is a portfolio project, written to work through the hard parts of a detection pipeline: ordering, idempotency, hot-reloaded rules, four-eyes response and tamper-evident audit. It is not a SIEM you should deploy.

**Only synthetic data.** The only logs this project analyses are the ones it generates itself (`scripts/gen.py`, plus test fixtures). Every address comes from the RFC 5737 documentation ranges and is mapped by a bundled fake geo table, and every user is `@example.test`. Nothing here scans, probes or contacts any external host. The only network action a playbook can take is a webhook, and webhooks are restricted to an allow-list that defaults to `localhost` and `127.0.0.1`.

## What it does

```
collectors ──HTTP (API key)──┐
syslog TCP (local) ──────────┤
                             ▼
                 sentinel.events.raw  (keyed by tenant|user)
                             │  Kafka Streams: normalise → enrich (geo, ASN, network type, device fp) → DLQ
              ┌──────────────┼───────────────┐
              ▼              ▼               ▼
         normalized       by-user          by-ip      → detection processors with RocksDB entity state
              │                 └──── signals ─┘
              ▼                        ▼
   Postgres event store          sentinel.alerts → correlator → alerts / incidents (Postgres, Redis dedup)
   (daily partitions, search,                                     │
    PII masking)                                   playbooks (four-eyes) → account lock, signed webhook (outbox)
                                                                  │
                                         audit entries → sealed batches (hash chain + Ed25519) → S3 object lock
```

- **Ingest.** `POST /v1/events:batch` takes up to 500 events with a per-collector API key (only the hash is stored). Event ids are deduplicated for 24 h in Redis. A bounded in-flight budget returns 429 instead of queueing without limit. An optional syslog TCP listener parses OpenSSH-style lines.
- **Rules.** Rules are written in a small DSL, compiled when they are saved, versioned, and hot-reloaded on every instance within one 2 s poll:
  ```
  sequence login.failure{8,} then login.success by user within 10m
  sequence *.success where network in (vpn, hosting) then password_change.* where ip changed by user within 1h
  threshold login.failure >= 20 by ip within 5m
  travel login.success by user faster than 900 kmh
  ioc ip in "blocked-ips"
  anomaly login.failure by user per 1h zscore > 3 after 24
  newdevice login.success by user after 3
  ```
  `POST /v1/rules/{id}:backtest` replays stored events through the same pure `DetectionEngine` the stream uses.
- **Detection.** Each entity (a user or an IP) has its state in a Streams state store. Sequences run as a small NFA. Thresholds use sliding windows. IOC lists are matched with Aho-Corasick. Anomaly baselines use Welford's algorithm. Impossible travel is computed with haversine and drops to LOW confidence when either end is a VPN or mobile network. The profile learns only from successful logins, and only after the rules have run.
- **Correlation.** All signals for the same rule, entity and UTC hour form one alert, whose id comes from that fingerprint. A redelivered signal is a no-op. HIGH-confidence alerts for one entity within 30 minutes share an incident. Incidents follow a state machine (`NEW → TRIAGED → INVESTIGATING → CONTAINED → RESOLVED`, or `FALSE_POSITIVE`) with optimistic versioning.
- **Response.** Playbooks are lists of steps: lock a demo account, add an indicator to an IOC list, or notify a webhook. A run that needs approval must be approved by a different admin than the one who requested it. The executor records every step it completes, so a crashed run resumes where it stopped. Webhooks go through an outbox, are signed with HMAC-SHA256 (`X-Sentinel-Signature`), and carry a stable delivery id (`X-Sentinel-Delivery`).
- **Search.** Search uses keyset pagination over a daily-partitioned Postgres table. Users and IPs are masked unless the caller has the `sentinel.pii` scope. Asking for cleartext without that scope returns 403 rather than silently masking.
- **Audit.** Every write appends an audit entry. A sealer groups unsealed entries into a hash-chained batch, signs it with Ed25519 and writes it to S3 under COMPLIANCE object lock. `GET /v1/audit/batches/{id}/verify` re-reads both copies and reports any modified, missing or extra entries, and whether the stored object still matches.
- **Tenancy and auth.** The app is an OAuth2 resource server. Analysts need `sentinel.analyst`, admins also need `sentinel.admin`, and cleartext search needs `sentinel.pii`. The tenant is the part of the token subject after `@`, and every query is scoped by it.

The code is hexagonal: each module has `domain`, `application` and `adapter` packages. ArchUnit enforces three rules: the domain has no Spring, Kafka, JPA or AWS imports; application code does not depend on adapters; and adapter slices do not depend on each other.

## Run it

You need Docker with Compose, plus `curl`, `jq`, `python3` and `openssl` for the scripts.

```bash
./scripts/up.sh --build   # first run writes random secrets to ~/.config/sentinel-stream/compose.env (mode 600)
./scripts/demo.sh         # end-to-end walk-through, prints ok/FAIL per check
./scripts/bench.sh        # small local benchmark (B=25 batches, R=5 bursts by default)
docker compose --env-file ~/.config/sentinel-stream/compose.env down -v
```

The stack is Postgres 16, Redis 7, Kafka 3.8 (KRaft), versitygw as an S3 gateway with object lock, mock-oauth2-server and the app. All ports bind to 127.0.0.1: the app on 7990, OAuth on 7991 and syslog on 7992. Compose refuses to start if a secret is missing, and no secrets are kept in the repo.

The demo:
1. Saves rules. An identical save is a no-op, an analyst gets 403, and a syntax error says where the problem is.
2. Sends 335 synthetic events. A resend comes back as 35 duplicates, and a wrong API key gets 401. It also sends two syslog lines.
3. Waits for the spray, takeover, travel and block-list alerts.
4. Walks an incident through the state machine.
5. Runs a lock-and-notify playbook. Self-approval is refused, a second admin approves it, the account is locked and one signed webhook is delivered.
6. Checks PII masking, then checks that another tenant sees nothing.
7. Seals the audit trail and verifies it.

## Tests

```bash
mvn verify   # needs Docker for Testcontainers
```

- **99 unit tests.** These cover the rule compiler, every detector, and property tests (jqwik) that check the NFA against a brute-force oracle, plus Aho-Corasick and Welford. They also cover the state machine, audit chain, PII masker, Streams topology (TopologyTestDriver) and the Streams thread-replacement budget, along with 3 ArchUnit rules.
- **18 integration tests.** These run against real Postgres, Kafka, Redis and versitygw in Testcontainers. Between them they cover:
  - the pipeline from start to finish, a resend that changes nothing, and a regression test for per-user ordering;
  - a redelivered signal raced 8 times, which produces exactly one alert;
  - 8 rules firing at once for one entity, which produce one incident;
  - a two-admin approval race, a run resumed after a crash, the webhook host allow-list, and an unsigned delivery being rejected;
  - 4 concurrent sealers with no entry sealed twice, and edits to a database row or to the stored object, both of which `verify` finds;
  - deleting a locked object, which S3 refuses;
  - 6 concurrent rule edits that never share a version.
  - tenant isolation, and auth checks on every endpoint.

CI (`.github/workflows/ci.yml`) runs the tests, builds the image, scans it with Trivy (CRITICAL/HIGH, fixed only) and runs the compose demo plus a short benchmark.

## Numbers

These are from `scripts/bench.sh`, three runs back to back on a shared 8-core, 16 GB dev box that was running other workloads (about 3 GB free), against the compose stack, with the app capped at a 512 MB heap.

| | run 1 | run 2 | run 3 |
|---|---|---|---|
| ingest, 5000 events in 25 sequential batches of 200 | 2885 events/s | 3996 events/s | 4940 events/s |
| per-batch POST latency p50 / p95 | 58 / 100 ms | 38 / 80 ms | 27 / 64 ms |
| post burst → alert visible in API, p50 of 5 | 269 ms | 264 ms | 268 ms |
| server-side ingest → signal at correlator, p50 of 5 | 226 ms | 224 ms | 221 ms |

How to read them:
- Ingest is one client posting sequentially, so it measures request latency, not capacity. The rise across runs is JVM warm-up.
- The alert-visible figure includes a 100 ms polling step.
- Five samples per run is very few.
- Most of the roughly 220 ms is probably Kafka Streams' exactly-once commit interval, not detection work. I have not profiled it.

## Bugs found along the way

Two bugs got past every unit and Testcontainers test and only showed up when the full stack ran:

1. **RocksDB on Alpine.** The runtime image had no `libstdc++`, so the RocksDB state store failed to load. Kafka Streams kept replacing the dead thread forever while `/actuator/health/readiness` still said UP. The fixes:
   - The image now installs `libstdc++`.
   - The uncaught-exception handler replaces a thread at most 5 times a minute and then shuts the client down.
   - Readiness now includes the Streams state.
2. **Out-of-order events per user.** The raw topic was keyed by event id, so one user's batch was spread across every partition. The by-user repartition then interleaved it, and "five failures then a success" sometimes saw the success first. TopologyTestDriver runs a single partition, so it could not catch this. The raw topic is now keyed by user. `PipelineIT.oneUsersBatchReachesTheSequenceDetectorInOrder` failed before the fix and passes after it.

A third bug showed up as a flaky test on a later local run:

3. **Shared rule compiler.** `RulesIT` races six rule edits and expects each to return 201 or 409. Now and then one returned 400 "expected 'by'" for a valid rule. The parser kept its token cursor on a single compiler instance that the rule service shared between request threads, so concurrent saves read each other's tokens. Each compile now gets its own cursor. `RuleCompilerTest.oneSharedCompilerParsesConcurrentRulesCorrectly` (8 threads × 2000 compiles) fails on the old code and passes now. The IT also prints every response body when it fails.

The first CI image scan also flagged `httpcore5` 5.3.6. It came in through the AWS SDK's `apache5-client`, which the app never uses because S3 goes through the URL-connection client, so that client is now excluded. Two spring-webmvc CVEs are ignored in `.trivyignore`, with the reason written there: the fix exists only in 7.x (Boot 4), and both CVEs need XSLT views or SSE fragments, which this app does not use.

## Limitations

These are known and not fixed:

- **Ordering is arrival order, not event time.** One user's events stay in the order they arrived. Late or reordered events are not re-sorted, and state keyed by IP can still see different users interleaved. That doesn't matter for thresholds or IOCs, but would for an IP-keyed sequence rule.
- **At-least-once side effects.** Webhooks can be delivered more than once (receivers should dedup on `X-Sentinel-Delivery`). The demo sink's own dedup is check-then-insert and can race. If the executor crashes between performing a step and recording it, that step runs again. Locking an account is idempotent; a notification is not.
- **Poison records are skipped.** After about 2 minutes of retries with backoff, a correlator record that still fails is logged, counted and skipped, not dead-lettered.
- **Syslog is unauthenticated.** Every syslog line goes to one configured tenant (`acme` by default). The listener binds to localhost unless you change it.
- **Audit.**
  - Sequence numbers are unique but not contiguous: they come from a shared sequence, so a rolled-back transaction leaves gaps.
  - If no signing key is configured, the app logs a warning and uses an ephemeral key, which cannot verify batches sealed before a restart.
  - If the database commit fails after the S3 put, the locked object is orphaned and only removed when its retention ends.
  - Retention is 1 day in the demo.
- **Grouping is coarse.** Alerts group by UTC hour, so a burst that crosses an hour boundary becomes two alerts.
- **Redis dedup is best-effort.** Signal dedup in Redis is only a shortcut: if Redis is down, the database check still decides. Ingest dedup does depend on Redis: if Redis is down, ingest fails rather than accepting events it cannot deduplicate, and the dedup window is 24 h.
- **Backtest is capped at 50,000 events.**
- **The geo/ASN table is a fake.** It covers only the documentation ranges, and the device fingerprint is a hash of the user agent.
- **Single node.** Each module was written to work with more than one instance (deterministic ids, row locks, idempotent upserts), but only one instance was ever run.
- **No UI.** Only the API and a JSON dashboard summary.

## Layout

```
src/main/java/com/sentinelstream/
  ingest/      collectors, batch + syslog intake, normaliser, enrichers
  pipeline/    Kafka Streams topology and runner
  detection/   rule DSL, compiler, detectors (pure), rule store, backtest
  response/    correlator, alerts, incidents
  playbook/    playbooks, four-eyes runs, executor, webhook outbox
  search/      event store and masked search
  audit/       audit entries, sealing, signing, S3 object lock, verify
  dashboard/   summary endpoint
  shared/      security, errors, Kafka config, JSON
scripts/       up.sh, demo.sh, bench.sh, gen.py (synthetic events)
```
