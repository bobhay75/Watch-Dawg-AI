#!/usr/bin/env bash
set -euo pipefail

if [[ "${SENTINEL_STAGING_DEPLOY:-false}" != "true" ]]; then
  echo "Set SENTINEL_STAGING_DEPLOY=true to create or update private staging." >&2
  exit 2
fi

for command_name in gcloud git openssl curl grep python; do
  command -v "${command_name}" >/dev/null || {
    echo "${command_name} is required; use Google Cloud Shell." >&2
    exit 2
  }
done

SENTINEL_PROJECT="${GOOGLE_CLOUD_PROJECT:-bobsome1}"
SENTINEL_REGION="${GOOGLE_CLOUD_RUN_REGION:-us-central1}"
SENTINEL_SERVICE="${SENTINEL_CLOUD_RUN_SERVICE:-watch-dawg-sentinel-staging}"
SENTINEL_ARTIFACT_REPOSITORY="${SENTINEL_ARTIFACT_REPOSITORY:-watch-dawg}"
SENTINEL_RUNTIME_ACCOUNT_NAME="${SENTINEL_RUNTIME_ACCOUNT_NAME:-watch-dawg-sentinel-stg}"
SENTINEL_SECRET_NAME="${SENTINEL_SECRET_NAME:-sentinel-api-token-staging}"
SENTINEL_PROFILE_NAME="${SENTINEL_PROFILE_NAME:-black-oak-staging}"
SENTINEL_PROFILE_FILE="${SENTINEL_PROFILE_FILE:-black-oak-staging.json}"
SENTINEL_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SENTINEL_ROOT="$(cd "${SENTINEL_SCRIPT_DIR}/.." && pwd)"
SENTINEL_REPOSITORY_ROOT="$(cd "${SENTINEL_ROOT}/.." && pwd)"
SENTINEL_IMAGE_TAG="${SENTINEL_IMAGE_TAG:-$(git -C "${SENTINEL_REPOSITORY_ROOT}" rev-parse --short=12 HEAD)}"

if [[ ! "${SENTINEL_PROJECT}" =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]]; then
  echo "GOOGLE_CLOUD_PROJECT is not a valid project ID." >&2
  exit 2
fi
if [[ ! "${SENTINEL_REGION}" =~ ^[a-z]+-[a-z]+[0-9]$ ]]; then
  echo "GOOGLE_CLOUD_RUN_REGION is not a valid region." >&2
  exit 2
fi
if [[ ! "${SENTINEL_SERVICE}" =~ ^[a-z][a-z0-9-]{0,61}[a-z0-9]$ ]]; then
  echo "SENTINEL_CLOUD_RUN_SERVICE is not a valid service name." >&2
  exit 2
fi
if [[ ! "${SENTINEL_ARTIFACT_REPOSITORY}" =~ ^[a-z][a-z0-9._-]{0,62}$ ]]; then
  echo "SENTINEL_ARTIFACT_REPOSITORY is not a valid repository name." >&2
  exit 2
fi
if [[ ! "${SENTINEL_RUNTIME_ACCOUNT_NAME}" =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]]; then
  echo "SENTINEL_RUNTIME_ACCOUNT_NAME is not a valid service-account name." >&2
  exit 2
fi
if [[ ! "${SENTINEL_SECRET_NAME}" =~ ^[a-zA-Z0-9_-]{1,255}$ ]]; then
  echo "SENTINEL_SECRET_NAME is not a valid Secret Manager name." >&2
  exit 2
fi
if [[ ! "${SENTINEL_PROFILE_NAME}" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]]; then
  echo "SENTINEL_PROFILE_NAME is not a valid profile name." >&2
  exit 2
fi
if [[ ! "${SENTINEL_PROFILE_FILE}" =~ ^[a-zA-Z0-9._-]+\.json$ ]]; then
  echo "SENTINEL_PROFILE_FILE must be one JSON filename." >&2
  exit 2
fi
if [[ ! -f "${SENTINEL_ROOT}/examples/${SENTINEL_PROFILE_FILE}" ]]; then
  echo "The selected staging profile file does not exist." >&2
  exit 2
fi
if [[ ! "${SENTINEL_IMAGE_TAG}" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$ ]]; then
  echo "SENTINEL_IMAGE_TAG is not a valid container tag." >&2
  exit 2
fi

gcloud projects describe "${SENTINEL_PROJECT}" --format='value(projectId)' >/dev/null
SENTINEL_DEPLOYER_ACCOUNT="$(gcloud config get-value account 2>/dev/null)"
if [[ -z "${SENTINEL_DEPLOYER_ACCOUNT}" ]]; then
  echo "No active gcloud account is configured." >&2
  exit 2
fi
if [[ "${SENTINEL_DEPLOYER_ACCOUNT}" == *".gserviceaccount.com" ]]; then
  SENTINEL_DEPLOYER_MEMBER="serviceAccount:${SENTINEL_DEPLOYER_ACCOUNT}"
else
  SENTINEL_DEPLOYER_MEMBER="user:${SENTINEL_DEPLOYER_ACCOUNT}"
fi
gcloud services enable \
  artifactregistry.googleapis.com \
  cloudbuild.googleapis.com \
  run.googleapis.com \
  secretmanager.googleapis.com \
  --project "${SENTINEL_PROJECT}"

if ! gcloud artifacts repositories describe "${SENTINEL_ARTIFACT_REPOSITORY}" \
  --location "${SENTINEL_REGION}" \
  --project "${SENTINEL_PROJECT}" >/dev/null 2>&1; then
  gcloud artifacts repositories create "${SENTINEL_ARTIFACT_REPOSITORY}" \
    --location "${SENTINEL_REGION}" \
    --project "${SENTINEL_PROJECT}" \
    --repository-format docker \
    --description "Private Watch-Dawg staging images"
fi

SENTINEL_RUNTIME_ACCOUNT="${SENTINEL_RUNTIME_ACCOUNT_NAME}@${SENTINEL_PROJECT}.iam.gserviceaccount.com"
if ! gcloud iam service-accounts describe "${SENTINEL_RUNTIME_ACCOUNT}" \
  --project "${SENTINEL_PROJECT}" >/dev/null 2>&1; then
  gcloud iam service-accounts create "${SENTINEL_RUNTIME_ACCOUNT_NAME}" \
    --project "${SENTINEL_PROJECT}" \
    --display-name "Watch-Dawg Sentinel staging runtime"
fi

SENTINEL_IMAGE="${SENTINEL_REGION}-docker.pkg.dev/${SENTINEL_PROJECT}/${SENTINEL_ARTIFACT_REPOSITORY}/sentinel-staging:${SENTINEL_IMAGE_TAG}"
gcloud builds submit "${SENTINEL_REPOSITORY_ROOT}" \
  --project "${SENTINEL_PROJECT}" \
  --config "${SENTINEL_ROOT}/cloudbuild.staging.yaml" \
  --substitutions "_IMAGE=${SENTINEL_IMAGE}"

if ! gcloud secrets describe "${SENTINEL_SECRET_NAME}" \
  --project "${SENTINEL_PROJECT}" >/dev/null 2>&1; then
  gcloud secrets create "${SENTINEL_SECRET_NAME}" \
    --project "${SENTINEL_PROJECT}" \
    --replication-policy automatic
fi

SENTINEL_GENERATED_TOKEN="$(openssl rand -hex 32)"
SENTINEL_SECRET_VERSION_RESOURCE="$(
  printf '%s' "${SENTINEL_GENERATED_TOKEN}" | gcloud secrets versions add \
    "${SENTINEL_SECRET_NAME}" \
    --project "${SENTINEL_PROJECT}" \
    --data-file=- \
    --format='value(name)'
)"
unset SENTINEL_GENERATED_TOKEN
SENTINEL_SECRET_VERSION="${SENTINEL_SECRET_VERSION_RESOURCE##*/}"
if [[ ! "${SENTINEL_SECRET_VERSION}" =~ ^[0-9]+$ ]]; then
  echo "Secret Manager did not return a version number." >&2
  exit 2
fi

gcloud secrets add-iam-policy-binding "${SENTINEL_SECRET_NAME}" \
  --project "${SENTINEL_PROJECT}" \
  --member "serviceAccount:${SENTINEL_RUNTIME_ACCOUNT}" \
  --role roles/secretmanager.secretAccessor \
  --condition=None >/dev/null
gcloud secrets add-iam-policy-binding "${SENTINEL_SECRET_NAME}" \
  --project "${SENTINEL_PROJECT}" \
  --member "${SENTINEL_DEPLOYER_MEMBER}" \
  --role roles/secretmanager.secretAccessor \
  --condition=None >/dev/null

remove_public_invokers() {
  local service_name="$1"
  local public_members
  public_members="$(gcloud run services get-iam-policy "${service_name}" \
    --project "${SENTINEL_PROJECT}" \
    --region "${SENTINEL_REGION}" \
    --flatten='bindings[].members' \
    --filter='bindings.role:roles/run.invoker' \
    --format='value(bindings.members)')"
  for public_member in allUsers allAuthenticatedUsers; do
    if grep -Fxq "${public_member}" <<<"${public_members}"; then
      gcloud run services remove-iam-policy-binding "${service_name}" \
        --project "${SENTINEL_PROJECT}" \
        --region "${SENTINEL_REGION}" \
        --member "${public_member}" \
        --role roles/run.invoker \
        --quiet >/dev/null
    fi
  done
}

if gcloud run services describe "${SENTINEL_SERVICE}" \
  --project "${SENTINEL_PROJECT}" \
  --region "${SENTINEL_REGION}" >/dev/null 2>&1; then
  remove_public_invokers "${SENTINEL_SERVICE}"
fi

SENTINEL_PROFILE_MAP="$(printf '{\"%s\":\"%s\"}' "${SENTINEL_PROFILE_NAME}" "${SENTINEL_PROFILE_FILE}")"
SENTINEL_ENV_VARS="^|^SENTINEL_CONFIG_ROOT=/app/sentinel/examples|SENTINEL_PROFILES_JSON=${SENTINEL_PROFILE_MAP}|SENTINEL_STATE_ROOT=/state|SENTINEL_RATE_LIMIT_PER_MINUTE=2|SENTINEL_PROFILE_COOLDOWN_SECONDS=300"

gcloud run deploy "${SENTINEL_SERVICE}" \
  --image "${SENTINEL_IMAGE}" \
  --project "${SENTINEL_PROJECT}" \
  --region "${SENTINEL_REGION}" \
  --service-account "${SENTINEL_RUNTIME_ACCOUNT}" \
  --ingress all \
  --invoker-iam-check \
  --default-url \
  --min-instances 0 \
  --max-instances 1 \
  --concurrency 1 \
  --cpu 1 \
  --memory 512Mi \
  --timeout 120 \
  --set-env-vars "${SENTINEL_ENV_VARS}" \
  --set-secrets "SENTINEL_API_TOKEN=${SENTINEL_SECRET_NAME}:${SENTINEL_SECRET_VERSION}" \
  --labels "application=watch-dawg,component=sentinel,environment=staging"

remove_public_invokers "${SENTINEL_SERVICE}"
gcloud run services add-iam-policy-binding "${SENTINEL_SERVICE}" \
  --project "${SENTINEL_PROJECT}" \
  --region "${SENTINEL_REGION}" \
  --member "${SENTINEL_DEPLOYER_MEMBER}" \
  --role roles/run.invoker \
  --condition=None >/dev/null

GOOGLE_CLOUD_PROJECT="${SENTINEL_PROJECT}" \
GOOGLE_CLOUD_RUN_REGION="${SENTINEL_REGION}" \
SENTINEL_CLOUD_RUN_SERVICE="${SENTINEL_SERVICE}" \
SENTINEL_SECRET_NAME="${SENTINEL_SECRET_NAME}" \
SENTINEL_SECRET_VERSION="${SENTINEL_SECRET_VERSION}" \
SENTINEL_PROFILE_NAME="${SENTINEL_PROFILE_NAME}" \
  "${SENTINEL_SCRIPT_DIR}/smoke-cloud-run-staging.sh"

gcloud run services describe "${SENTINEL_SERVICE}" \
  --project "${SENTINEL_PROJECT}" \
  --region "${SENTINEL_REGION}" \
  --format='value(status.url)'
