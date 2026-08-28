#!/usr/bin/env bash
set -euo pipefail

: "${KEY9_AGENT_URL:?Set KEY9_AGENT_URL to the Cloud Run service URL}"

KEY9_BASE_URL="${KEY9_AGENT_URL%/}"

curl --fail --silent --show-error "${KEY9_BASE_URL}/healthz"
curl --fail --silent --show-error "${KEY9_BASE_URL}/list-apps"
