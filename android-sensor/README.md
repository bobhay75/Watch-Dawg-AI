# Watch-Dawg Android Sensor

This directory contains an installable, non-root Android collector. It gathers
real evidence exposed by supported Android APIs, signs each snapshot with a
device-held ECDSA P-256 key, and can manually deliver the signed envelope to a
Watch-Dawg ingestion endpoint over HTTPS.

It is not a simulation, an exploit tool, or a device-control agent. Collection
is visible and owner-directed. The app never blocks, patches, deletes, or
changes another app.

## What it actually observes

- Foreground app transitions after the owner explicitly grants **Usage
  Access**.
- Installed-package, version, and selected sensitive-permission deltas. Raw
  package names are replaced on-device with an HMAC-SHA-256 pseudonym before
  export.
- Screen-lock, storage-encryption, Android security-patch, Developer Options,
  and ADB posture available through public APIs.
- Active connectivity transport (for example Wi-Fi, cellular, Ethernet, or
  VPN), validation, captive-portal, and metering state. It does not inspect
  destinations, packet content, DNS, or traffic.
- The hardware/security level reported for the Android Keystore signing key.

The collector retains a bounded, ordered outbox of up to 32 signed snapshots in
app-private storage. Manual sync always sends the oldest pending snapshot and
deletes only that exact entry after a type-checked HTTP 201 receipt binds its
device, key, sequence, and payload hash. The UI reports the pending count. If
the outbox is full, collection fails closed before assigning a sequence or
advancing any evidence baseline; it never evicts unacknowledged evidence.
Periodic collection is disabled by default and can be explicitly enabled or
disabled in the UI. Android may defer the 15-minute `JobScheduler` interval for
battery and Doze policies.

Collection checkpoints are transactional with respect to a durable outbox
entry: Watch-Dawg first signs, fsyncs, and atomically renames the entry, then
advances the sequence and package, permission, and usage baselines. A failure
before publication leaves every baseline unchanged. A checkpoint failure after
publication can repeat evidence with a higher sequence on retry; that
duplicate-safe behavior is intentional because losing an unrecorded delta is
the more dangerous failure mode. Export Latest selects the newest verified
snapshot across the pending queue and last-acknowledged cache.

Each signed payload includes an explicit collection summary:

```json
{
  "collection": {
    "event_limit": 500,
    "events_emitted": 17,
    "complete": true,
    "package_deltas_truncated": false,
    "permission_deltas_truncated": false,
    "usage_events_truncated": false,
    "usage_query_available": true,
    "usage_history_gap": false
  }
}
```

When the event limit is reached, `complete` is false and the affected
truncation flag is true. Package and permission baselines retain unreported
state so later scans retry those deltas. A partial UsageStats cursor is
checkpointed as the last consumed timestamp plus the consumed source-row
ordinal at that timestamp. A retry skips only that persisted prefix, so even
more than 500 source events sharing one millisecond make forward progress
without intentionally advancing past unread events. If Usage Access was
granted but Android returned no query cursor, `usage_query_available` is false
and process coverage is `error`, not `observed`. A cursor truncated by the
event limit reports process coverage as `partial`. If an existing cursor is
older than Android's bounded 24-hour query horizon, or a clock rollback puts it
in the future, `usage_history_gap` is true; that snapshot is incomplete and its
process coverage is `partial` even when the bounded query succeeds with no
events. The marker is per-collection: later contiguous snapshots can establish
current coverage, while the signed historical snapshot preserves the gap.

Event objects use `package_has_signing_certificate` to report whether signing
certificate metadata was present in the sampled `PackageInfo`. Android
packages are signed as part of installation; this field is not a publisher
reputation, certificate-chain validation, or trust verdict.

## Camera and microphone truth boundary

The app requests neither `CAMERA` nor `RECORD_AUDIO`. A normal Android app
cannot reliably attribute another app's live camera or microphone use through
public APIs.

When Usage Access is granted, Watch-Dawg can report that a package moved to the
foreground while it held a camera or microphone permission. Such an event is
exported as `camera_capable_foreground` or
`microphone_capable_foreground` with:

```json
{
  "claim": "foreground_transition_plus_granted_permission_not_sensor_use",
  "evidence_kind": "capability_inference"
}
```

That is a capability inference, not proof that the sensor was used. The
snapshot's camera and microphone sensor entries remain
`status: "unsupported"`. Android's own Privacy Dashboard remains the source of
truth available to the device owner.

A future, separately reviewed live-watch service could collect coarse
`CameraManager.AvailabilityCallback` and anonymized
`AudioRecordingCallback` state while a persistent notification is shown. Those
signals still could not identify an app and are intentionally not represented
as implemented here.

## Enrollment and signed transport

On first use the app creates a non-exportable Android Keystore ECDSA P-256 key.
StrongBox is requested when available on Android 9+; generation falls back to
the provider Android selects when StrongBox is unavailable. The private key
never appears in an export.

The enrollment export is a separate public record:

```json
{
  "device_id": "android-<first-24-key-fingerprint-hex>",
  "key_id": "<full-sha256-public-key-fingerprint-hex>",
  "public_key_der_base64": "<subject-public-key-info>"
}
```

An operator must pin that public key to the device during an authenticated
enrollment step. A public key supplied later by an untrusted snapshot must
never silently replace the enrolled key.

Each sync request contains exactly this envelope shape:

```json
{
  "algorithm": "SHA256withECDSA",
  "device_id": "android-…",
  "key_id": "…",
  "schema_version": 1,
  "signature": "<base64 DER ECDSA signature>",
  "signed_payload": "<base64 exact UTF-8 canonical snapshot bytes>"
}
```

The payload contains the same `device_id`, a monotonically increasing
`sequence`, and `collected_at`. The signature covers the exact decoded bytes in
`signed_payload`. The canonical JSON v1 profile sorts object keys and permits
only strings, booleans, null, arrays, objects, and integers; floating-point
numbers are rejected.

The sync bearer credential must match `[A-Za-z0-9_-]{32,256}` exactly. It is
encrypted using AES-GCM with a
non-exportable Android Keystore key. Sync is manual, permits only `https://`
endpoints with a host, refuses redirects, and uses the platform trust store.
The token is never logged or exported.

## Build and install

Prerequisites:

- JDK 17
- Android SDK Platform 35 and Build Tools
- Gradle 8.9 (the repository CI should pin the exact toolchain)

From this directory:

```sh
gradle :app:testDebugUnitTest :app:assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

For production, use a protected release signing key and a reproducible CI
build; do not distribute the debug APK. GitHub-hosted CI debug keys are
ephemeral, so artifacts from separate runs are first-install/throwaway builds,
not an updateable channel. Installing a later artifact may require uninstalling
the prior app, which erases its device identity and pending outbox and requires
fresh server enrollment.

After installation:

1. Open Watch-Dawg Sensor and review its disclosure.
2. Tap **Grant or review Usage Access** and explicitly enable it if foreground
   transition evidence is desired.
3. Tap **Run real scan now**.
4. Export the public enrollment record and enroll it in the Watch-Dawg server.
5. Configure the server-provided HTTPS endpoint and per-device bearer
   credential, then manually sync the oldest pending signed snapshot.
6. Optionally enable periodic local collection. It does not auto-sync.

## Distribution and policy note

`QUERY_ALL_PACKAGES` is declared because installed-package and permission
posture is a core security function. Google Play treats this as restricted; a
store release needs the applicable declaration, prominent disclosure, privacy
policy, and policy review. If that use is not approved, remove the permission
and degrade inventory coverage honestly rather than bypass package visibility
controls.

No Accessibility Service, VPN, root access, hidden service, camera permission,
microphone permission, credential capture, counterattack, exploit generation,
or automatic remediation is present.
