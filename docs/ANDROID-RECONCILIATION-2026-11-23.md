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
- Identify this combined app as version code 4, `0.3.0-survival-preview`, and
  retain APK metadata, SHA-256 and unit/lint reports from the same CI build.

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
