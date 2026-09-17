# Watch-Dawg Android Sensor operator guide

The Android sensor is an owner-installed, opt-in collector for a real Android
device. It collects the signals Android makes available to an ordinary app,
creates a canonical JSON snapshot, signs that exact byte sequence with an
ECDSA P-256 key held by Android Keystore, and can send the signed envelope to
the authenticated Sentinel ingest route.

This is a real-device pilot, not an endpoint-detection certification or an OS
security boundary. It does not root the phone, exploit software, record media,
intercept credentials, patch applications, block processes, inspect packets,
or take a containment action.

## Evidence boundary

| Signal | What the sensor can support | What it does **not** prove |
| --- | --- | --- |
| Foreground-app transition | A `UsageStatsManager` event was available after the owner granted Usage Access. Package names are replaced with a device-local HMAC pseudonym before export. | That the app used the camera, microphone, network, or a particular document. |
| Camera/microphone permission posture | An installed package held a granted camera or microphone permission when sampled. | Actual camera or microphone use. Ordinary apps cannot use `AppOpsManager` to observe another app's active operations without a signature-only permission. |
| Package change | Package metadata or its sampled permission state changed between local collections. `package_has_signing_certificate` reports only sampled certificate-metadata presence. | That the package, certificate, or publisher is trusted, that the package is malicious, or that an update was compromised. |
| Device posture | Public Android APIs reported facts such as screen-lock, encryption, security-patch, or developer-setting posture. Unsupported controls remain explicit object-scoped `unsupported` evidence rather than a fabricated boolean result. | Secure Boot attestation, device integrity, or freedom from root/OS compromise. |
| Connectivity | The public connectivity APIs reported current transport/posture metadata. | Packet contents, destinations, exfiltration, or network enforcement. The pilot does not install a VPN. |
| Snapshot signature | The enrolled P-256 key signed the canonical payload, and the server verified it before acceptance. | That every underlying Android signal is complete or truthful on a compromised phone. |

Android's [`UsageStatsManager`](https://developer.android.com/reference/android/app/usage/UsageStatsManager)
requires special user-granted access, retains events for a limited period, and
may return no events while the user is locked. Android's
[`AppOpsManager`](https://developer.android.com/reference/android/app/AppOpsManager)
does not let an ordinary app reliably watch other apps' live camera or
microphone operations. Watch-Dawg therefore labels permission-plus-foreground
correlations as inference and never relabels them as observed sensor access.
With verified object-scoped evidence, package and permission inventory deltas
are verified observations of a change, while foreground-plus-permission events
remain `INFERENCE`; neither label is a malware verdict.

The snapshot deliberately reports unsupported camera, microphone, identity,
and packet-level network coverage as unavailable. Sentinel can alert on that
coverage gap; the gap must not be suppressed to make the dashboard look more
capable.

## Collection completeness and bounded retries

Every signed payload contains a `collection` object with these exact fields:

```json
{
  "event_limit": 500,
  "events_emitted": 17,
  "complete": true,
  "package_deltas_truncated": false,
  "permission_deltas_truncated": false,
  "usage_events_truncated": false,
  "usage_query_available": true,
  "usage_history_gap": false
}
```

`complete` becomes false if a granted UsageStats query is unavailable, any
event stream reaches the per-snapshot limit, or `usage_history_gap` is true.
Lack of an owner grant is instead
represented as `sensors.process.status: "not_granted"`; it is not disguised as
a successful UsageStats observation. An available query that reaches the event
limit reports process status `partial`, while an unavailable granted query
reports `error`.

Package and permission deltas that do not fit retain their prior durable
baseline, so a later scan retries them. A partial UsageStats query checkpoints
the last consumed event timestamp and source-row ordinal at that timestamp. A
retry skips exactly that persisted prefix, so more than 500 source events with
the same millisecond timestamp still make forward progress. Replay can create
duplicates, including a duplicate camera-capability event when the corresponding
microphone-capability event did not fit, but it does not intentionally advance
past unread rows. Consumers must therefore treat event delivery as at-least-once
across partial snapshots and use the signed `collection` metadata when making
coverage claims.

Android queries are bounded to the most recent 24 hours. If an existing cursor
is older than that horizon, or a clock rollback puts the cursor in the future,
the collector starts at the bounded horizon and signs
`usage_history_gap: true`. That snapshot reports process coverage `partial`
even when the query succeeds with no events; it never relabels the missing
interval as observed or complete. The marker is per-collection, so later
contiguous snapshots can regain current coverage while immutable history keeps
the signed gap evidence.

The `posture` object contains only the supported boolean checks
`disk_encrypted`, `screen_lock`, and `security_updates_current`. Secure Boot is
not exposed as a supported Android public-API boolean; it remains
`posture_evidence.secure_boot` with `status: "unsupported"`, source
`android_public_api`, and scope `verified_boot_state`.

## Build the review APK

The project is in `android-sensor/` and currently uses:

- Android API 35 for compile and target SDK;
- Android 8.0/API 26 as the minimum supported version;
- Java 17;
- Gradle 8.9 and Android Gradle Plugin 8.7.3.

Install a JDK 17 and an Android SDK containing Platform 35, then run:

```bash
cd android-sensor
gradle --no-daemon --stacktrace :app:testDebugUnitTest :app:assembleDebug
```

The review APK is written to:

```text
android-sensor/app/build/outputs/apk/debug/app-debug.apk
```

The `Build Watch-Dawg Android Sensor` GitHub Actions workflow runs the same
unit test and debug build and retains the review APK as a short-lived workflow
artifact. A debug APK is suitable only for an authorized pilot. It is not a
release artifact and should not be represented as production signed. The
hosted runner's debug signing key is ephemeral: treat each CI APK as a
first-install or throwaway artifact, not an update channel. A later CI APK may
require uninstalling the earlier build, which erases its app-private signing
identity, token, baselines, and pending outbox and therefore requires fresh
enrollment. An updateable pilot needs a protected, stable release signing key.

## Install on Android 15

Use a device you own or are explicitly authorized to manage. With Android
platform tools installed, enable Developer options and USB debugging on the
pilot device, confirm the computer's authorization prompt, and run:

```bash
adb devices
adb install -r android-sensor/app/build/outputs/apk/debug/app-debug.apk
adb shell am start -n com.bobsome1.watchdawg.sensor/.MainActivity
```

Then complete the in-app setup:

1. Review the disclosure before enabling collection.
2. Open **Usage Access** and explicitly allow Watch-Dawg Sensor. On Android 15,
   the equivalent manual path is normally **Settings > Apps > Special app
   access > Usage access**.
3. Run one manual collection and inspect the reported coverage before enabling
   periodic work or sync.
4. Copy the enrollment record and enroll the exact device key on the server.
5. Configure the HTTPS ingest endpoint and the per-device token, test one
   manual sync, and only then opt into periodic collection.

Usage Access is not a normal runtime permission: declaring
`PACKAGE_USAGE_STATS` in the manifest does not grant it. The owner must use the
system Settings screen, and revoking it must leave the app operational with
reduced coverage rather than fabricate results.

Clearing application data or uninstalling the sensor deletes its local keys,
sequence counter, consent state, and package pseudonym secret. Treat the next
installation as a new device identity and replace the server enrollment.

## Package visibility and Play distribution

The pilot declares `QUERY_ALL_PACKAGES` because an endpoint-security collector
must compare installed-package and permission posture. Android otherwise
filters package visibility; see the Android
[`package visibility`](https://developer.android.com/training/package-visibility)
documentation.

`QUERY_ALL_PACKAGES` has no runtime grant dialog. Its presence therefore makes
the app's own prominent disclosure and affirmative enablement important. Raw
package names must stay on the device; exported events use a keyed,
device-local pseudonym so different devices cannot be trivially correlated.

Google Play restricts `QUERY_ALL_PACKAGES`. A security-app use case may be
eligible, but publication requires an accurate Play Console declaration,
privacy policy, data-safety answers, and review. The repository and this guide
do not claim Play approval. Before a Play submission, confirm the current
[`broad package visibility policy`](https://support.google.com/googleplay/android-developer/answer/10158779)
and determine whether narrower `<queries>` declarations can meet the product
requirement.

## Enroll one device

The app exposes an enrollment record containing public, non-secret identity
material:

```json
{
  "device_id": "android-<24 hex characters>",
  "key_id": "<64 lowercase hex characters>",
  "public_key_der_base64": "<base64 SubjectPublicKeyInfo DER>"
}
```

Compare this record out of band with the physical device before enrolling it.
The server also verifies that `device_id` is exactly `android-` plus the first
24 characters of `key_id`; the two values cannot be mixed between records.
Generate a unique high-entropy bearer token for this device; do not reuse the
Sentinel operator/API token. Give the plaintext token only to the app and put
only its lowercase SHA-256 digest in the server enrollment:

```bash
DEVICE_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
printf '%s' "$DEVICE_TOKEN" | sha256sum
```

Transfer the token to the device through an approved secret channel and clear
the temporary shell variable after setup. A production enrollment flow should
avoid placing the plaintext in shell history or the clipboard.

Create an enrollment file readable only by the service account. Its top-level
key is the exact `device_id`; `snapshot_path` is a relative `.json` path under
`SENTINEL_SWARM_SNAPSHOT_ROOT`:

```json
{
  "android-0123456789abcdef01234567": {
    "token_sha256": "replace-with-the-64-character-lowercase-token-digest",
    "key_id": "replace-with-the-64-character-key-id",
    "public_key_der_base64": "replace-with-the-app-exported-public-key",
    "snapshot_path": "android-0123456789abcdef01234567.json"
  }
}
```

Configure the service with the file, durable paths, and the existing Sentinel
operator token:

```bash
python -m pip install --requirement sentinel/requirements.txt
export SENTINEL_API_TOKEN="replace-with-a-separate-random-operator-secret"
export SENTINEL_SWARM_ENROLLMENTS_FILE="/run/secrets/swarm-enrollments.json"
export SENTINEL_SWARM_SNAPSHOT_ROOT="/var/lib/watchdawg/swarm-snapshots"
export SENTINEL_SWARM_REPLAY_STATE_PATH="/var/lib/watchdawg/swarm-state/replay.sqlite3"
export SENTINEL_SWARM_PROOF_HMAC_KEY_BASE64="<base64 of exactly 32 secret random bytes>"
python -m sentinel.api
```

Keep the proof-HMAC key in the server's secret manager and stable across
restarts. It is never sent to Android. The ingestion service and every
Sentinel evaluator that reads verified Swarm snapshots must receive the same
`SENTINEL_SWARM_PROOF_HMAC_KEY_BASE64` value. This pilot has no online proof-key
keyring: rotation requires an explicit offline migration that re-authenticates
retained proofs, or a new enrollment, replay database, and history root.

For a local, single-device pilot, `SENTINEL_SWARM_ENROLLMENTS_JSON` may be used
instead of the file. Configure exactly one of the two variables. Environment
values are easy to expose through shell history and process/deployment
metadata, so use a mounted secret or a managed secret store outside throwaway
development.

The server rejects malformed enrollment records, key-ID/public-key mismatch,
keys other than ECDSA P-256, paths outside the configured snapshot root,
invalid token digests, and more than 1,000 enrolled devices. The app's supplied
plaintext bearer token must match `[A-Za-z0-9_-]{32,256}` exactly. Any other
character or length is rejected before signature verification.

## HTTPS sync and replay protection

Configure the app with the full HTTPS snapshot route:

```text
https://sentinel.example.com/v1/swarm/snapshot
```

and the matching per-device bearer token. The token is encrypted at rest by an
AES-GCM key held in Android Keystore. The sensor refuses a cleartext `http://`
endpoint and the manifest disables cleartext traffic. TLS still depends on the
device trust store; this pilot does not implement certificate pinning or mTLS.

Each request sends `Content-Type: application/json`, exactly one per-device
`Authorization: Bearer ...` credential, the matching
`X-WatchDawg-Device-ID: android-<24 lowercase hex characters>` header, and a
signed envelope no larger than 512 KB. The envelope contains the device ID,
key ID, algorithm, base64 canonical payload, and DER-encoded ECDSA signature.
The server authenticates the two identity headers before reading the body and
then verifies all of the following before replacing the accepted snapshot:

- exact enrollment and constant-time bearer-token match;
- enrolled key ID and ECDSA P-256 signature;
- canonical UTF-8 JSON with no duplicate keys or non-finite values;
- matching device IDs;
- a strictly increasing 64-bit sequence number for each new snapshot;
- body, payload, signature, and storage-path limits.

Ingest deliberately does not reject an otherwise valid snapshot because its
signed collection time is old or in the future. This lets the Android FIFO
drain after an offline period or a bad device clock instead of permanently
wedging behind its oldest item. Acceptance means the evidence was authenticated
and stored; it does **not** mean the telemetry is current. Sentinel's evaluator
independently applies `max_snapshot_age_seconds`, reports stale or future
telemetry, and suppresses dynamic conclusions that require current evidence.
Operators should still correct phone and server clocks promptly.

Ingest also defaults to 120 requests per minute per process and a one-second
per-device cooldown. `SENTINEL_SWARM_RATE_LIMIT_PER_MINUTE` and
`SENTINEL_SWARM_DEVICE_COOLDOWN_SECONDS` tune those defense-in-depth limits;
the production edge still needs a shared limiter. The exact wire contract is
also recorded in [`sentinel/SWARM_INGEST.md`](../sentinel/SWARM_INGEST.md).

A successful upload returns HTTP 201 and a receipt similar to:

```json
{
  "accepted": true,
  "device_id": "android-0123456789abcdef01234567",
  "key_id": "<64 lowercase hex characters>",
  "sequence": 7,
  "snapshot_sha256": "<64 lowercase hex characters>"
}
```

The Android client treats only status `201` with an
`application/json` response of at most 4,096 characters as success. It binds
the receipt back to the signed request: `accepted` must be true and the device
ID, key ID, sequence, and payload SHA-256 must match the locally decoded signed
envelope. Redirects, other status codes, oversized/non-JSON responses, or a
mismatched receipt fail closed.

The app keeps the signed upload queued until that bound receipt is validated.
If it restarts after the server committed the snapshot but before the local
acknowledgment, it may resend the exact envelope. The server returns the same
HTTP 201 receipt without advancing replay state or changing the original
receipt time. If an earlier server crash committed the replay row but
interrupted storage materialization, the exact retry repairs missing artifacts
before 201; already-correct files are not rewritten, and a conflicting
immutable history artifact fails closed. An older sequence or the same sequence
with different signed bytes remains a replay conflict and returns HTTP 409.

For every accepted sequence, the server durably retains three files under
`<snapshot-path>.history/` before returning 201:

```text
<sequence-19-digits>-<payload-sha256>.snapshot.json
<sequence-19-digits>-<payload-sha256>.snapshot.json.proof.json
<sequence-19-digits>-<payload-sha256>.signature.der
```

They contain the exact signed snapshot, its server-HMAC proof, and the original
DER device signature. The latter permits later ECDSA verification over the
snapshot with the enrolled public key after Android deletes its acknowledged
outbox entry. The compatibility snapshot and proof at the configured path still
point to only the latest accepted sequence.

The current evaluator reads that latest path only; it does not automatically
walk or acknowledge history. Running it after each successful upload before
syncing the next queued entry makes each **fresh** batch eligible for alerting.
Stale or future-dated batches are archived, but their dynamic event and posture
conclusions remain suppressed. Historical-event alerting requires a separately
reviewed ordered history consumer with an explicit historical/freshness policy.
History preserves evidence but does not itself provide automatic per-batch
alert delivery.

History is capped at 2,048 entries per device by default and is never
automatically pruned. `SENTINEL_SWARM_HISTORY_MAX_ENTRIES_PER_DEVICE` accepts 1
through 100,000; also enforce a filesystem quota and monitor capacity/write
failures. At the cap, a new sequence returns HTTP 507 while an exact current
retry remains valid, so the Android outbox keeps the entry. To resume, quiesce
the single ingest process, export and evaluate retained evidence under the
approved retention procedure, delete only the oldest complete
snapshot/proof/signature trios, and then restart ingest. Never delete the replay
row's current sequence trio. Storage failures likewise return no 201.

When upgrading a server that previously accepted snapshots without this
history trio, retain and retry the exact last accepted Android envelope before
sending a higher sequence. If that envelope no longer exists, explicitly
re-enroll the device with a fresh replay database and history root. The server
does not fabricate or grandfather a missing device signature.

Do not put either Sentinel token in browser JavaScript, public logs, crash
reports, analytics, source control, or screenshots.

## Periodic collection is opt-in

Periodic work must remain off until the device owner enables it. The Android
job scheduler is battery-aware and may defer work under Doze, low battery,
vendor power management, or background restrictions; it is periodic evidence,
not a real-time service-level guarantee. A reboot receiver may restore only a
previously enabled schedule. Disabling periodic collection must cancel the
scheduled job without affecting manual collection.

The 15-minute job appends to a 32-entry, sequence-ordered, app-private signed
outbox. It does **not** upload. If all 32 entries remain unacknowledged, further
manual or periodic collection fails closed before assigning a sequence or
advancing package, permission, or usage checkpoints; no pending evidence is
evicted. Sync remains a separate visible owner action and always sends the
oldest pending entry. Only an exact HTTP 201 receipt bound to its device, key,
sequence, and payload hash permits that entry to be removed. Export Latest
still selects the newest verified pending or last-acknowledged snapshot.

The app shows Usage Access, periodic collection, sync configuration, and the
pending outbox count. A configured endpoint is not consent by itself.
Collection and sync must not silently enable after installation or an app
update.

## Verify an accepted snapshot and proof sidecar

For an enrolled `snapshot_path` named `device.json`, successful ingest writes:

- `device.json`: the canonical payload whose signature was verified;
- `device.json.proof.json`: a small server-generated verification sidecar;
- the last accepted sequence in the replay-state SQLite database.

The sidecar binds `device_id`, `key_id`, `sequence`, algorithm, receipt time,
and `payload_sha256` to the stored payload. Its `proof_hmac_sha256` is an
HMAC-SHA-256 over canonical proof fields using the server-only 32-byte key.
Compare the stored bytes to the sidecar:

```bash
sha256sum /var/lib/watchdawg/swarm-snapshots/device.json
jq . /var/lib/watchdawg/swarm-snapshots/device.json.proof.json
```

The SHA-256 output must exactly equal `payload_sha256`, and the device,
sequence, and key ID must match the upload receipt. Sentinel repeats these
binding checks and verifies the sidecar HMAC with the same
`SENTINEL_SWARM_PROOF_HMAC_KEY_BASE64` secret when loading the snapshot. For a
fail-closed evidence profile, set the target's
`require_verified_ingestion` to `true` and include the expected key ID in
`trusted_key_ids`; then a missing, unauthenticated, mismatched, or untrusted
sidecar fails closed. A verified target also fails closed when that server key
is absent or invalid.

The proof sidecar is a server-authenticated ingest record, not a separately
signed or publicly verifiable receipt.
For independent cryptographic verification, preserve the original signed
envelope and enrolled public key, then verify the exact decoded payload:

```bash
jq -r .signed_payload signed-envelope.json | base64 --decode > payload.json
jq -r .signature signed-envelope.json | base64 --decode > signature.der
printf '%s' "$PUBLIC_KEY_DER_BASE64" | base64 --decode > public-key.der
openssl pkey -pubin -inform DER -in public-key.der -out public-key.pem
openssl dgst -sha256 -verify public-key.pem -signature signature.der payload.json
```

The final command must print `Verified OK`. Also hash `payload.json` and compare
it with both the HTTP receipt and proof sidecar. Never parse and reserialize the
payload before signature verification; the signature covers its original
canonical bytes.

To make the watch pack fail closed on verified ingest, point an authorized
profile at the same relative snapshot path and pin the enrolled key:

```json
{
  "swarm_snapshot_root": "/var/lib/watchdawg/swarm-snapshots",
  "targets": [
    {
      "id": "owned-android-shadow",
      "kind": "swarm_device",
      "enabled": true,
      "mode": "shadow",
      "device_id": "android-0123456789abcdef01234567",
      "snapshot_path": "android-0123456789abcdef01234567.json",
      "require_verified_ingestion": true,
      "trusted_key_ids": ["replace-with-the-64-character-key-id"],
      "required_sensor_scopes": {
        "camera": "direct_cross_app_access",
        "microphone": "direct_cross_app_access",
        "identity": "device_authentication_events",
        "process": "foreground_transitions",
        "network": "active_transport_only"
      },
      "authorization": {
        "mode": "owner",
        "id": "AUTH-ANDROID-001",
        "approved_methods": ["read-device-snapshot"],
        "scope": {
          "device_id": "android-0123456789abcdef01234567",
          "snapshot_path": "android-0123456789abcdef01234567.json"
        },
        "expires_at": "2030-01-01T00:00:00Z"
      }
    }
  ]
}
```

Use a real authorization record and future expiry. Register the file as an
approved server-owned profile, then invoke it through `POST /v1/run` with the
separate Sentinel operator token. Ingestion stores evidence; it does not
automatically run a profile or take an action.

The Android collector uses structured sensor status/source/scope claims. The
watch pack accepts that schema only with verified ingestion and a non-empty
trusted-key allowlist. Required scopes are compared exactly: an aggregate or
unattributed Android signal is never promoted to per-app visibility. In the
example, camera, microphone, and identity limitations remain visible instead
of being converted into false coverage.

## Threat model

The pilot is designed to detect in-transit payload changes, reject unknown
devices and keys, limit oversized requests, preserve authenticated monotonic
backlogs, and reject altered or older replay attempts while allowing exact
receipt-recovery retries. The evaluator, rather than ingest, marks stale or
future telemetry and withholds current-state conclusions. Private signing and
token-encryption keys are
non-exportable through the Android Keystore API. The app reports the local key
security level where Android exposes it; see
[`Android Keystore`](https://developer.android.com/privacy-and-security/keystore).
That label is informational until independently attested.

The pilot does not protect against all of the following:

- a rooted or OS-compromised phone falsifying source signals or app memory;
- a malicious build, code running inside the sensor's UID, physical device
  compromise, or bearer-token theft;
- server compromise or an operator with the proof-HMAC key replacing both a
  payload and its server-authenticated proof sidecar;
- denial of service, clock manipulation, job deferral, or permanent loss of
  app-private state;
- live cross-app camera/microphone observation, packet inspection, VPN
  enforcement, exploit prevention, auto-patching, or autonomous response;
- a distributed ingest deployment sharing file state safely across instances.

Pseudonymization is not anonymity. A package pseudonym is stable for the life
of one app installation, and the device/key identifiers are also stable. Even
without raw package names, foreground timestamps, permission counts, Android
and patch versions, developer/ADB posture, transports, and event sequences can
be linkable or identifying when combined. Use TLS, least-privilege access,
short retention, deletion/export procedures, and an explicit owner disclosure;
do not publish raw snapshots as public receipts.

## Production gates still open

Before external production or regulated deployment, complete at least these
gates:

1. Create and protect a dedicated Android release-signing key; define rotation,
   rollback, build provenance, and reproducible-release procedures.
   Pin the container base by digest, lock Python transitive dependencies with
   hashes, enable Gradle dependency verification, and use fixed CI runner images
   before treating CI output as a release supply-chain attestation.
2. Add Play Integrity and hardware-backed key attestation with server-side
   certificate-chain, challenge, app-identity, patch-level, revocation, and
   replay validation. Hardware-backed local storage alone is not attestation.
3. Put ingest behind a managed HTTPS proxy/WAF with a concurrent-connection
   cap, absolute total header/body deadlines, request/rate limits, secret
   rotation, audit logging, and alerting. The built-in server timeout is only
   an idle-I/O defense. Evaluate mTLS for managed fleets.
4. Replace per-instance files and SQLite with durable shared storage,
   transactional cross-instance replay locks, ordered history evaluation with a
   processed watermark, backup/restore tests, quotas, retention, and tenant
   isolation before horizontal scaling.
5. Add a separately signed, append-only receipt if receipts must survive server
   administrator compromise or support third-party verification.
6. Complete privacy review, data-flow inventory, deletion/export behavior,
   Play declarations, and device-owner consent testing.
7. Treat any future VPN visibility or enforcement as a separate, explicit
   feature. Android's [`VpnService`](https://developer.android.com/reference/android/net/VpnService)
   requires user approval, presents persistent system UI, conflicts with another
   active VPN, and creates substantial routing, privacy, and availability risk.
   Any Play-distributed implementation must also meet the current
   [`VpnService` policy](https://support.google.com/googleplay/android-developer/answer/16558241).

This work does not claim military-grade status, FIPS validation, FedRAMP or
agency authorization, Play approval, compromise prevention, or complete device
visibility. Those are externally testable outcomes, not product adjectives.
