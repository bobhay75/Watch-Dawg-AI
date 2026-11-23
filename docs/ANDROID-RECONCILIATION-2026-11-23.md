# Android sensor and Survival OS reconciliation

This isolated integration branch combines the Android sensor baseline from
PR #14 (`094ee1034add2befb768bbc3011e9a128f3b5bcc`) and the native Survival OS
activity from PR #24 (`e8db3874ecbfe5a52a4d3504054684041907bdf1`) with current
main. Their source branches and draft pull requests remain intact.

## Resolved integration boundaries

- Preserve main's secret, private evidence and operations ignore rules while
  adding Android local build exclusions.
- Preserve pinned container bases, the patched zlib check, non-root execution,
  removed runtime pip, dependency audits and full-image scans. The newly needed
  Sentinel cryptography dependency must be installed *before* removing pip.
- Regenerate the Sentinel lock with Python 3.12 and pip-tools 7.7.0, pin
  cryptography 50.0.2 and hash all transitive dependencies. Install that lock in
  the combined backend test job because it now includes signed Android ingest
  tests. Include Python package inventory in the final Sentinel image scan.
- Identify the corrected combined app as version code 5, `0.3.1-survival-preview`, and
  retain APK metadata, SHA-256 and unit/lint reports from the same CI build.
- Reuse the existing shield/check vector in a dark, adaptive launcher icon.
  Correct the sensor README to disclose Survival OS's optional GPS permission.

## Survival lifecycle review fixes

The reconciliation review found that the inherited Survival activity could
close a native conversation/engine while a background load or inference still
used it, leak an initialized engine when conversation creation failed, or
delete the prior model before a replacement rename succeeded. The corrected
activity routes load, inference, cleanup and model file changes through one
serialized owner. Unpublished resources are released in a `finally` block on
failure or cancellation. Destruction rejects further work immediately and
performs cleanup off the UI thread, after native work returns.

LiteRT-LM 0.18.1's Flow adapter has an empty `awaitClose` handler: cancelling
collection does not itself establish that native inference has stopped. This
preview therefore uses a synchronous native request on the IO worker while
holding resource ownership, with a 512-token output limit. An answer appears
when generation finishes. Clear/remove can be requested immediately but wait
for that native request before closing; this avoids treating coroutine
cancellation as proof that native resources are safe to free.

Imports write and sync a unique temporary file beside the installed model.
Replacement requests an atomic move and has no delete-first or non-atomic
fallback. Import/read/size/cancellation/move failures retain the old model.
This is atomic replacement, not a claim about recovery from every filesystem
or hardware fault. GPS keeps one active listener and timeout, ignores stale
callbacks, and cancels both on replacement/destruction. Questions are bounded
to 4,000 characters in the UI and again before inference.

The extracted Java regressions exercise concurrent native work versus close
and removal, initialization/conversation failures, shutdown/cancellation before
publication, cleanup ordering, actual atomic replacement and injected move
failure, import failures and provider-close failure, repeated GPS request
cleanup, stale callbacks, and the prompt boundary. These tests use controlled
resources/files; real LiteRT inference and physical GPS remain device checks.

Source behavior checked:

- [LiteRT-LM v0.18.1 Conversation](https://github.com/google-ai-edge/LiteRT-LM/blob/v0.18.1/kotlin/java/com/google/ai/edge/litertlm/Conversation.kt)
- [Android Files.move contract](https://developer.android.com/reference/java/nio/file/Files)

## Validation and release boundary

The reconciled Sentinel unit suite passes 148 tests locally. Hosted CI must
also pass Android unit tests, Android lint, APK assembly, combined backend and
recovery tests, dependency audits and packaged-image gates before integration
can be accepted. CI results on the final head take precedence over old PR runs.

The review APK uses an ephemeral debug signing key. It is a test build and is
not a production signing channel or store release. Do not uninstall a previous
installation with unsynced evidence merely to replace its signing identity;
export/acknowledge pending evidence and enroll the new identity deliberately.

Survival OS is an activity within the sensor app, not a replacement operating
system. A compatible local model is not bundled. Real phone installation,
GPS reception, model inference speed, thermal behavior, battery behavior and
owner workflow acceptance remain device checks. No cloud-provider credential
or live private server is required for the build.

## Target SDK review on November 23, 2026

This sideloaded preview retains compile/target SDK 35 and minimum SDK 26.
Google Play requires new ordinary phone apps and updates to target Android 16
(API 36) or higher from August 31, 2026. Target 35 therefore does not qualify
this APK for a new Play submission. The review UI is English-only.

A target upgrade is a separate compatibility change. The present AGP 8.7.3
toolchain predates Android's documented API 36 setup requirement. Target 36 also
changes edge-to-edge handling, predictive back and large-screen behavior, all
of which need runtime verification with these native activities and local
model lifecycle. Changing only the target number would not establish that
compatibility. No target/lint warning is suppressed and no store claim is made.

Official sources checked for this decision:

- [Current Play target requirements](https://developer.android.com/google/play/requirements/target-sdk)
- [Android 16 SDK setup](https://developer.android.com/about/versions/16/setup-sdk)
- [Android 16 target behavior changes](https://developer.android.com/about/versions/16/behavior-changes-16)
