#!/usr/bin/env bash
set -euo pipefail

: "${GOOGLE_CLOUD_PROJECT:?Set GOOGLE_CLOUD_PROJECT to the contest project ID}"
: "${KEY9_BRIDGE_SECRET:?Set KEY9_BRIDGE_SECRET to the Secret Manager secret name holding the bridge token}"

KEY9_RUN_REGION="${GOOGLE_CLOUD_RUN_REGION:-us-central1}"
KEY9_VERTEX_LOCATION="${GOOGLE_CLOUD_LOCATION:-global}"
KEY9_SERVICE="${KEY9_CLOUD_RUN_SERVICE:-watch-dawg-key9-agent}"
KEY9_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEY9_AGENT_DIR="${KEY9_SCRIPT_DIR}/../agent-service"

if [[ ! "${GOOGLE_CLOUD_PROJECT}" =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]]; then
  echo "GOOGLE_CLOUD_PROJECT is not a valid project ID" >&2
  exit 2
fi

KEY9_PROJECT_NUMBER="$(gcloud projects describe "${GOOGLE_CLOUD_PROJECT}" --format='value(projectNumber)')"
KEY9_RUNTIME_SERVICE_ACCOUNT="${KEY9_RUNTIME_SERVICE_ACCOUNT:-${KEY9_PROJECT_NUMBER}-compute@developer.gserviceaccount.com}"

gcloud services enable \
  run.googleapis.com \
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com \
  aiplatform.googleapis.com \
  secretmanager.googleapis.com \
  --project "${GOOGLE_CLOUD_PROJECT}"

gcloud run deploy "${KEY9_SERVICE}" \
  --source "${KEY9_AGENT_DIR}" \
  --project "${GOOGLE_CLOUD_PROJECT}" \
  --region "${KEY9_RUN_REGION}" \
  --service-account "${KEY9_RUNTIME_SERVICE_ACCOUNT}" \
  --allow-unauthenticated \
  --min-instances 0 \
  --max-instances 2 \
  --concurrency 20 \
  --cpu 1 \
  --memory 512Mi \
  --timeout 120 \
  --set-env-vars "GOOGLE_CLOUD_PROJECT=${GOOGLE_CLOUD_PROJECT},GOOGLE_CLOUD_LOCATION=${KEY9_VERTEX_LOCATION},GOOGLE_GENAI_USE_VERTEXAI=True,KEY9_MODEL=${KEY9_GEMINI_MODEL:-gemini-3.5-flash},KEY9_SANDBOX=true" \
  --set-secrets "KEY9_BRIDGE_TOKEN=${KEY9_BRIDGE_SECRET}:latest"

gcloud run services describe "${KEY9_SERVICE}" \
  --project "${GOOGLE_CLOUD_PROJECT}" \
  --region "${KEY9_RUN_REGION}" \
  --format "value(status.url)"
