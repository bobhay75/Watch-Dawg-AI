# Signed Swarm snapshot ingestion

The optional `POST /v1/swarm/snapshot` route accepts observations from an
enrolled Watch-Dawg Android collector. It does not accept a caller-provided
public key or destination path. The service verifies a P-256 signature, rejects
altered or older replay attempts, stores the exact signed JSON bytes, preserves
each accepted device signature in immutable history, and writes a server-owned
verification sidecar for the Swarm evaluator. Timestamp freshness is an
evaluator policy, not an ingestion gate.

## Enrollment

Provision a unique bearer token containing 32 through 256 cryptographically
random URL-safe ASCII characters (`A-Z`, `a-z`, `0-9`, `_`, or `-`) to the
device over a separate trusted channel. Store only its lowercase SHA-256 digest
on the server. The Android public key is its DER-encoded
`SubjectPublicKeyInfo` value; `key_id` is the lowercase SHA-256 digest of those
DER bytes.

The server-owned enrollment JSON is an object keyed by device id:

```json
{
  "android-<first-24-hex-of-key-id>": {
    "token_sha256": "<64 lowercase hex characters>",
    "key_id": "<64 lowercase hex characters>",
    "public_key_der_base64": "<base64 DER P-256 public key>",
    "snapshot_path": "android/android-<first-24-hex-of-key-id>.json"
  }
}
```

Set either `SENTINEL_SWARM_ENROLLMENTS_FILE` or
`SENTINEL_SWARM_ENROLLMENTS_JSON`, never both. File-based configuration is
preferred so a secret manager can mount the enrollment record read-only.
Configure the storage locations separately:

```text
SENTINEL_SWARM_SNAPSHOT_ROOT=/state/swarm-snapshots
SENTINEL_SWARM_REPLAY_STATE_PATH=/state/swarm-replay.sqlite3
SENTINEL_SWARM_PROOF_HMAC_KEY_BASE64=<base64 of 32 random bytes>
```

The proof HMAC key is mandatory whenever enrollment is enabled. Generate and
store it independently from device bearer tokens (for example, with
`openssl rand -base64 32`) and inject it from a secret manager. It authenticates
the server's verification sidecar; it must never be provisioned to Android.

The Android `device_id` must equal `android-` plus the first 24 characters of
its verified `key_id`. The snapshot path is resolved beneath the server-owned
root and must end in `.json`. A request cannot override either value.

## Wire contract

The request has `Content-Type: application/json`, a device-specific
`Authorization: Bearer ...` header, a matching
`X-WatchDawg-Device-ID: android-0123456789abcdef01234567` header, and exactly
these fields:

```json
{
  "schema_version": 1,
  "device_id": "android-0123456789abcdef01234567",
  "key_id": "<enrolled key id>",
  "algorithm": "SHA256withECDSA",
  "signed_payload": "<base64 exact canonical snapshot JSON bytes>",
  "signature": "<base64 DER ECDSA signature over signed_payload bytes>"
}
```

Canonical snapshot JSON is UTF-8, has object keys sorted lexicographically, no
insignificant whitespace, no duplicate keys, no non-finite numbers, and uses
literal Unicode rather than ASCII escape substitution. Snapshot schema 1 uses
integer values rather than floating-point values. The signed object must contain
the same `device_id`, a timezone-aware `collected_at`, and a monotonically
increasing integer `sequence` from 1 through 2^63-1 for each new snapshot.

After authenticating the exact signed bytes, the server validates the complete
Android v1 privacy schema before touching replay state or persistent snapshot
storage. Objects use exact field allowlists and bounded types; event package
identities must be device-keyed `pkg-hmac256:` pseudonyms. Unknown fields,
unsupported event shapes, and raw package names are rejected with a generic
error that does not echo the rejected value.

The whole HTTP body is limited to 512,000 bytes. Ingestion deliberately accepts
an old or future-dated snapshot when its device, token, signature, strict schema,
and increasing sequence are valid. This allows the signed oldest-first Android
outbox to drain after offline periods or a bad device clock. Acceptance proves
authenticated storage, not current telemetry; the evaluator applies its own
past-age and future-time gate before drawing conclusions.

Ingest controls are tuned with:

```text
SENTINEL_SWARM_RATE_LIMIT_PER_MINUTE=120
SENTINEL_SWARM_DEVICE_COOLDOWN_SECONDS=1
SENTINEL_SWARM_HISTORY_MAX_ENTRIES_PER_DEVICE=2048
SENTINEL_REQUEST_TIMEOUT_SECONDS=15
```

The device header and bearer token are authenticated and rate-limited before
the server reads or parses the body. Exactly one of each identity header is
required; duplicated authorization or device-id headers fail authentication.
The envelope and signed payload device ids must still match the
preauthenticated header.

Successful ingestion returns HTTP 201 with the accepted sequence and payload
SHA-256. Retrying the exact already-accepted device, sequence, and payload hash
returns the same five-field HTTP 201 receipt without advancing replay state or
changing the original receipt time. Healthy materialized files are not
rewritten; missing files from an interrupted prior attempt are repaired, while
a conflicting immutable history artifact fails closed. This remains true after
a process restart regardless of payload age, so a client can recover if it
crashed after the first 201 but before acknowledging its durable outbox. A lower
sequence, or the same sequence with different signed bytes, returns HTTP 409.

For a new accepted sequence, the single service process holds a per-device lock,
commits the sequence, payload hash, and fixed `received_at` to SQLite first.
It then durably creates three immutable history artifacts beneath
`<snapshot>.history/`, followed by the atomic latest-snapshot compatibility
files:

```text
<sequence-19-digits>-<payload-sha256>.snapshot.json
<sequence-19-digits>-<payload-sha256>.snapshot.json.proof.json
<sequence-19-digits>-<payload-sha256>.signature.der
```

The first file is the exact signed payload. The second is its HMAC-authenticated
server proof. The third is the original DER ECDSA signature, so the archived
device signature can later be verified again over the exact snapshot with the
enrolled public key. Retain the corresponding public enrollment record with the
same evidence lifecycle; the history trio does not duplicate the public key.
Directory entries and files are fsynced, and HTTP 201 is
sent only after the history trio and current snapshot/proof pair are durable.

If the process stops between the replay commit and file publication, the
retained client outbox retries the exact envelope; the server uses the
write-ahead row's original `received_at` to verify and repair missing material.
The server will not advance to a higher sequence until the currently committed
history trio is valid; it repairs a damaged mutable latest pair from that
archive. This prevents a failed materialization from stranding the exact retry
after a later sequence advances.
The SQLite schema can add a missing `received_at` column in place; an
authenticated existing proof supplies that time when available, otherwise the
prior collected time is the conservative fallback. This does not invent a
missing archived device signature. An upgrade from a pre-history build must
retain and retry the exact last accepted envelope to populate its history trio,
or start a deliberately re-enrolled device with a fresh replay database and
history root. Without one of those operator-controlled paths, higher sequences
fail closed rather than silently grandfathering unverifiable history.

## Evaluator policy

After successful verification the service writes
`<snapshot>.proof.json`. Its canonical verification fields are authenticated
with server-side HMAC-SHA-256 as `proof_hmac_sha256`; a caller-created sidecar
containing only `signature_verified: true` is rejected. The evaluator performs
a stable double-read with bounded retries and accepts a generation only when its
valid proof HMAC binds the exact snapshot SHA-256, so it cannot combine a
snapshot and proof from different atomic replacements. To fail closed when a manually copied
or unsigned file appears, set `require_verified_ingestion` on the
`swarm_device` target and pin the expected key id:

```json
{
  "require_verified_ingestion": true,
  "trusted_key_ids": ["<64 lowercase hex characters>"],
  "max_snapshot_age_seconds": 3600
}
```

For verified object snapshots, both the signed `collected_at` value and the
HMAC-authenticated `received_at` value must be current. The maximum accepted age
defaults to one hour and can be set from 60 through 86,400 seconds. Missing,
stale, inconsistent, or future timestamps produce
`SWARM_TELEMETRY_STALE`; event and posture conclusions are suppressed while
last-known active stateful risks remain open. A periodic Android collection job
creates a snapshot on the device; it does not automatically upload unless HTTPS
sync has separately been configured and invoked.

The current Swarm evaluator reads only the configured latest snapshot path; it
does not automatically walk or acknowledge accepted history. Running the
evaluator after each successful upload before syncing the next outbox entry
makes each **fresh** batch eligible for alerting. Stale or future-dated batches
are archived, but their dynamic event and posture conclusions remain
suppressed. Historical-event alerting requires a separately reviewed ordered
history consumer with an explicit historical/freshness policy. The history
prevents evidence loss, but by itself does not promise automatic per-batch
alert delivery.

Legacy snapshots remain readable when `require_verified_ingestion` is absent, but
their provenance is explicitly not signature-verified.

Package HMACs prevent raw package names from leaving the collector, but they
remain stable within one app installation. Device/key ids, event times,
permission counts, patch/app versions, posture, and transports are also
linkable metadata. Store snapshots as sensitive telemetry, keep retention
bounded, and never expose them as public proof pages without a separate privacy
review and deliberate redaction policy.

## Production boundary

- Terminate modern TLS before this HTTP service. Never send a device token or
  snapshot over plaintext transport.
- Put a global rate limit, concurrent-connection cap, and absolute total
  header/body deadline at the reverse proxy. The built-in socket timeout is an
  idle-I/O timeout and the process-local limiter is only a defense-in-depth
  control; this service is not intended for direct Internet exposure.
- Keep the snapshot root and SQLite replay database on durable, access-controlled
  POSIX storage. Ephemeral container filesystems lose replay state on restart.
- Accepted history is capped at 2,048 entries per device by default and has no
  automatic pruning. Set
  `SENTINEL_SWARM_HISTORY_MAX_ENTRIES_PER_DEVICE` from 1 through 100,000, also
  apply a filesystem quota, and monitor capacity/write failures. At the cap a
  new sequence fails closed with HTTP 507, while an exact current retry still
  works, so the Android outbox retains evidence. To resume, quiesce the single
  ingest process, export and evaluate retained evidence under the approved
  retention procedure, delete only the oldest complete
  snapshot/proof/signature trios, and then restart ingest. Never delete the
  replay row's current sequence trio. The 2,048-entry default bounds maximum
  raw archive payload near 1 GiB per device before filesystem overhead. Set a
  lower limit when normal snapshots are smaller or storage is constrained.
- Run exactly one ingestion service process/instance per replay database. The
  per-device materialization lock is process-local; multi-process, multi-region,
  or horizontally scaled ingestion requires a transactional shared database
  and distributed generation/materialization coordination before rollout.
- Rotate the token and enroll a new key id if either credential may be exposed.
  A collector reset that loses its sequence state must be explicitly re-enrolled;
  the server never silently lowers the accepted sequence.
- Keep the proof-HMAC key stable. Rotation is fail-closed and requires an
  explicit offline migration that re-authenticates every retained proof (or a
  new enrollment, replay database, and history root); there is no online
  proof-key keyring in this pilot.
- Give every enrollment a unique token hash, public-key id, snapshot path, proof
  path, and history root. Startup rejects credential reuse, device/key derivation
  mismatch, duplicate paths, and nested or intersecting snapshot/proof/history
  paths. The configured replay database (including its SQLite journal/WAL
  sidecar names) must not intersect those paths either.
