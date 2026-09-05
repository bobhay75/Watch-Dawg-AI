#!/usr/bin/env bash
set -euo pipefail

: "${KEY9_AGENT_URL:?Set KEY9_AGENT_URL to the Cloud Run service URL}"
: "${KEY9_AGENT_TOKEN:?Set KEY9_AGENT_TOKEN to the private bridge token}"

KEY9_BASE_URL="${KEY9_AGENT_URL%/}"

curl --fail --silent --show-error "${KEY9_BASE_URL}/v1/health"
curl --fail --silent --show-error \
  -H "x-key9-bridge-token: ${KEY9_AGENT_TOKEN}" \
  "${KEY9_BASE_URL}/list-apps"
