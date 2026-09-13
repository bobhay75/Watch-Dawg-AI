#!/usr/bin/env bash
set -euo pipefail

: "${GOOGLE_CLOUD_PROJECT:?Set GOOGLE_CLOUD_PROJECT}"
: "${SENTINEL_SECRET_VERSION:?Set SENTINEL_SECRET_VERSION to the pinned version}"

SENTINEL_REGION="${GOOGLE_CLOUD_RUN_REGION:-us-central1}"
SENTINEL_SERVICE="${SENTINEL_CLOUD_RUN_SERVICE:-watch-dawg-sentinel-staging}"
SENTINEL_SECRET_NAME="${SENTINEL_SECRET_NAME:-sentinel-api-token-staging}"
SENTINEL_PROFILE_NAME="${SENTINEL_PROFILE_NAME:-black-oak-staging}"
SENTINEL_SERVICE_URL="$(gcloud run services describe "${SENTINEL_SERVICE}" \
  --project "${GOOGLE_CLOUD_PROJECT}" \
  --region "${SENTINEL_REGION}" \
  --format='value(status.url)')"
SENTINEL_ID_TOKEN="$(gcloud auth print-identity-token)"
SENTINEL_API_TOKEN="$(gcloud secrets versions access "${SENTINEL_SECRET_VERSION}" \
  --secret "${SENTINEL_SECRET_NAME}" \
  --project "${GOOGLE_CLOUD_PROJECT}")"
SENTINEL_HEALTH_RESPONSE="$(mktemp)"
SENTINEL_RUN_RESPONSE="$(mktemp)"
trap 'rm -f "${SENTINEL_HEALTH_RESPONSE}" "${SENTINEL_RUN_RESPONSE}"' EXIT

SENTINEL_ANONYMOUS_STATUS="$(curl --silent --output /dev/null --write-out '%{http_code}' \
  "${SENTINEL_SERVICE_URL}/healthz")"
if [[ "${SENTINEL_ANONYMOUS_STATUS}" != "403" ]]; then
  echo "Expected anonymous Cloud Run access to return 403; got ${SENTINEL_ANONYMOUS_STATUS}." >&2
  exit 1
fi

curl --fail-with-body --silent --show-error \
  --config - \
  "${SENTINEL_SERVICE_URL}/healthz" \
  --output "${SENTINEL_HEALTH_RESPONSE}" <<EOF
header = "X-Serverless-Authorization: Bearer ${SENTINEL_ID_TOKEN}"
EOF

SENTINEL_APPLICATION_STATUS="$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --config - \
  --data "{\"profile\":\"${SENTINEL_PROFILE_NAME}\"}" \
  "${SENTINEL_SERVICE_URL}/v1/run" <<EOF
header = "X-Serverless-Authorization: Bearer ${SENTINEL_ID_TOKEN}"
header = "Content-Type: application/json"
EOF
)"
if [[ "${SENTINEL_APPLICATION_STATUS}" != "401" ]]; then
  echo "Expected missing Sentinel authentication to return 401; got ${SENTINEL_APPLICATION_STATUS}." >&2
  exit 1
fi

curl --fail-with-body --silent --show-error \
  --config - \
  --data "{\"profile\":\"${SENTINEL_PROFILE_NAME}\"}" \
  "${SENTINEL_SERVICE_URL}/v1/run" \
  --output "${SENTINEL_RUN_RESPONSE}" <<EOF
header = "X-Serverless-Authorization: Bearer ${SENTINEL_ID_TOKEN}"
header = "Authorization: Bearer ${SENTINEL_API_TOKEN}"
header = "Content-Type: application/json"
EOF
unset SENTINEL_ID_TOKEN SENTINEL_API_TOKEN

python - "${SENTINEL_HEALTH_RESPONSE}" "${SENTINEL_RUN_RESPONSE}" \
  "${SENTINEL_PROFILE_NAME}" <<'PY'
import json
import sys
from pathlib import Path

health = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
run = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
expected_profile = sys.argv[3]

assert health == {
    "status": "ok",
    "service": "watch-dawg-sentinel-api",
    "profiles_configured": 1,
}
assert run["profile"] == expected_profile
assert run["result"]["targets_checked"] == 5
assert isinstance(run["result"]["discernment"], dict)
print("Private staging smoke test passed for", expected_profile)
PY
