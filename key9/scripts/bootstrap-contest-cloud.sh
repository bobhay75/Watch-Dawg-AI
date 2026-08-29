#!/usr/bin/env bash
set -euo pipefail

KEY9_PROJECT="${GOOGLE_CLOUD_PROJECT:-bobsome1}"
KEY9_RUN_REGION="${GOOGLE_CLOUD_RUN_REGION:-us-central1}"
KEY9_VERTEX_LOCATION="${GOOGLE_CLOUD_LOCATION:-global}"
KEY9_SERVICE="${KEY9_CLOUD_RUN_SERVICE:-watch-dawg-key9-agent}"
KEY9_SECRET_NAME="${KEY9_BRIDGE_SECRET:-key9-bridge-token}"
KEY9_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEY9_ENV_FILE="${KEY9_SCRIPT_DIR}/../key9-sites-env.txt"

if [[ ! "${KEY9_PROJECT}" =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]]; then
  echo "GOOGLE_CLOUD_PROJECT is not a valid project ID" >&2
  exit 2
fi

command -v gcloud >/dev/null || {
  echo "gcloud is required; run this script in Google Cloud Shell" >&2
  exit 2
}
command -v openssl >/dev/null || {
  echo "openssl is required to generate the private bridge token" >&2
  exit 2
}

gcloud projects describe "${KEY9_PROJECT}" --format='value(projectId)' >/dev/null
KEY9_PROJECT_NUMBER="$(gcloud projects describe "${KEY9_PROJECT}" --format='value(projectNumber)')"
KEY9_RUNTIME_SERVICE_ACCOUNT="${KEY9_RUNTIME_SERVICE_ACCOUNT:-${KEY9_PROJECT_NUMBER}-compute@developer.gserviceaccount.com}"
KEY9_BRIDGE_TOKEN="$(openssl rand -hex 32)"

gcloud config set project "${KEY9_PROJECT}"
gcloud services enable \
  aiplatform.googleapis.com \
  artifactregistry.googleapis.com \
  cloudbuild.googleapis.com \
  run.googleapis.com \
  secretmanager.googleapis.com \
  --project "${KEY9_PROJECT}"

if gcloud secrets describe "${KEY9_SECRET_NAME}" --project "${KEY9_PROJECT}" >/dev/null 2>&1; then
  printf '%s' "${KEY9_BRIDGE_TOKEN}" | gcloud secrets versions add "${KEY9_SECRET_NAME}" \
    --data-file=- \
    --project "${KEY9_PROJECT}"
else
  printf '%s' "${KEY9_BRIDGE_TOKEN}" | gcloud secrets create "${KEY9_SECRET_NAME}" \
    --data-file=- \
    --replication-policy=automatic \
    --project "${KEY9_PROJECT}"
fi

gcloud secrets add-iam-policy-binding "${KEY9_SECRET_NAME}" \
  --member "serviceAccount:${KEY9_RUNTIME_SERVICE_ACCOUNT}" \
  --role roles/secretmanager.secretAccessor \
  --project "${KEY9_PROJECT}" >/dev/null

gcloud projects add-iam-policy-binding "${KEY9_PROJECT}" \
  --member "serviceAccount:${KEY9_RUNTIME_SERVICE_ACCOUNT}" \
  --role roles/aiplatform.user \
  --condition=None >/dev/null

GOOGLE_CLOUD_PROJECT="${KEY9_PROJECT}" \
GOOGLE_CLOUD_RUN_REGION="${KEY9_RUN_REGION}" \
GOOGLE_CLOUD_LOCATION="${KEY9_VERTEX_LOCATION}" \
KEY9_CLOUD_RUN_SERVICE="${KEY9_SERVICE}" \
KEY9_BRIDGE_SECRET="${KEY9_SECRET_NAME}" \
KEY9_RUNTIME_SERVICE_ACCOUNT="${KEY9_RUNTIME_SERVICE_ACCOUNT}" \
  "${KEY9_SCRIPT_DIR}/deploy-cloud-run.sh"

KEY9_AGENT_URL="$(gcloud run services describe "${KEY9_SERVICE}" \
  --project "${KEY9_PROJECT}" \
  --region "${KEY9_RUN_REGION}" \
  --format='value(status.url)')"

umask 077
{
  printf 'KEY9_AGENT_URL=%s\n' "${KEY9_AGENT_URL}"
  printf 'KEY9_AGENT_TOKEN=%s\n' "${KEY9_BRIDGE_TOKEN}"
} >"${KEY9_ENV_FILE}"

printf '\nWatch-Dawg KEY-9 is live at %s\n' "${KEY9_AGENT_URL}"
printf 'Sites production variables were written to %s\n' "${KEY9_ENV_FILE}"
printf 'Do not commit, share, or paste that file into chat. Add both values directly to the Site production environment.\n'
