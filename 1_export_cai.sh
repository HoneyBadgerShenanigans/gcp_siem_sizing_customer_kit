#!/bin/bash
# ==============================================================================
# 1_export_cai.sh
# Exports Google Cloud Asset Inventory (resource, iam-policy, org-policy) at the
# Organization level to a GCS bucket, waits for completion, and downloads the
# resulting files locally for AI/LLM SIEM log ingestion sizing.
# ==============================================================================
set -euo pipefail

# Restrict local file creation permissions to owner-only (0600 / 0700)
umask 077

usage() {
  cat <<EOF
Usage:
  $0 --org <ORGANIZATION_ID> --project <BILLING_PROJECT_ID> --bucket <GCS_BUCKET_NAME> [--create-bucket] [--location <US|EU|...>] [--cleanup-gcs]

Examples:
  $0 --org 123456789012 --project my-admin-project --bucket my-cai-export-bucket --create-bucket --cleanup-gcs
  $0 --org 123456789012 --project my-admin-project --bucket gs://existing-bucket/cai-snapshot
EOF
  exit 1
}

ORGANIZATION_ID=""
BILLING_PROJECT=""
BUCKET_INPUT=""
CREATE_BUCKET="false"
CLEANUP_GCS="false"
BUCKET_LOCATION="US"
POLL_INTERVAL_SECONDS=10

require_arg() {
  if [ "$#" -lt 2 ] || [ -z "${2:-}" ] || [[ "${2:-}" == --* ]]; then
    echo "ERROR: Option $1 requires a non-empty value." >&2
    usage
  fi
}

while [ $# -gt 0 ]; do
  case "$1" in
    --org)
      require_arg "$1" "${2:-}"
      ORGANIZATION_ID="$2"
      shift 2
      ;;
    --project)
      require_arg "$1" "${2:-}"
      BILLING_PROJECT="$2"
      shift 2
      ;;
    --bucket)
      require_arg "$1" "${2:-}"
      BUCKET_INPUT="$2"
      shift 2
      ;;
    --create-bucket)
      CREATE_BUCKET="true"
      shift 1
      ;;
    --cleanup-gcs)
      CLEANUP_GCS="true"
      shift 1
      ;;
    --location)
      require_arg "$1" "${2:-}"
      BUCKET_LOCATION="$2"
      shift 2
      ;;
    -h|--help)
      usage
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      ;;
  esac
done

if [ -z "${ORGANIZATION_ID}" ] || [ -z "${BILLING_PROJECT}" ] || [ -z "${BUCKET_INPUT}" ]; then
  echo "ERROR: --org, --project, and --bucket are required." >&2
  usage
fi

# Strip any accidental "organizations/" prefix and validate numeric Organization ID
ORGANIZATION_ID="${ORGANIZATION_ID#organizations/}"
if ! [[ "${ORGANIZATION_ID}" =~ ^[0-9]+$ ]]; then
  echo "ERROR: Invalid --org '${ORGANIZATION_ID}'. Must be a numeric GCP Organization ID." >&2
  exit 1
fi

# Validate Billing Project ID format
if ! [[ "${BILLING_PROJECT}" =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]]; then
  echo "ERROR: Invalid --project '${BILLING_PROJECT}'. Must be a valid GCP Project ID." >&2
  exit 1
fi

# Validate Bucket Location format
if ! [[ "${BUCKET_LOCATION}" =~ ^[a-zA-Z0-9-]+$ ]]; then
  echo "ERROR: Invalid --location '${BUCKET_LOCATION}'." >&2
  exit 1
fi

# Normalize bucket URI (ensure gs:// prefix and no trailing slash)
if [[ "${BUCKET_INPUT}" != gs://* ]]; then
  BUCKET="gs://${BUCKET_INPUT}"
else
  BUCKET="${BUCKET_INPUT}"
fi
BUCKET="${BUCKET%/}"

if ! [[ "${BUCKET}" =~ ^gs://[a-z0-9._-]+(/[a-zA-Z0-9._/-]+)?$ ]]; then
  echo "ERROR: Invalid --bucket '${BUCKET_INPUT}'." >&2
  exit 1
fi

# Extract bare bucket root (gs://bucket-name) in case a subpath was provided
BUCKET_ROOT="gs://$(echo "${BUCKET#gs://}" | cut -d'/' -f1)"

# Override any stale local quota_project in gcloud config so API calls use BILLING_PROJECT
export CLOUDSDK_BILLING_QUOTA_PROJECT="${BILLING_PROJECT}"

echo "=================================================================="
echo "GCP Cloud Asset Inventory Export"
echo "  Organization ID : ${ORGANIZATION_ID}"
echo "  Billing Project : ${BILLING_PROJECT}"
echo "  Target GCS Path : ${BUCKET}"
echo "=================================================================="

echo "[1/4] Enabling Cloud Asset & Storage APIs on ${BILLING_PROJECT}..."
gcloud services enable cloudasset.googleapis.com storage.googleapis.com \
  --project="${BILLING_PROJECT}"

if [ "${CREATE_BUCKET}" = "true" ]; then
  echo "[2/4] Ensuring GCS bucket ${BUCKET_ROOT} exists (location=${BUCKET_LOCATION})..."
  if ! gcloud storage buckets describe "${BUCKET_ROOT}" --project="${BILLING_PROJECT}" >/dev/null 2>&1; then
    gcloud storage buckets create "${BUCKET_ROOT}" \
      --project="${BILLING_PROJECT}" \
      --location="${BUCKET_LOCATION}" \
      --uniform-bucket-level-access \
      --public-access-prevention
  else
    echo "  Bucket ${BUCKET_ROOT} already exists."
  fi
else
  echo "[2/4] Using existing GCS bucket ${BUCKET_ROOT}..."
fi

CONTENT_TYPES=(resource iam-policy org-policy)
OP_NAMES=()
FAILED=()

echo "[3/4] Submitting asynchronous Cloud Asset Inventory exports..."
for ct in "${CONTENT_TYPES[@]}"; do
  echo "  -> Submitting content-type=${ct}..."
  # gcloud asset export prints the operation name to stderr inside brackets:
  # "Use [gcloud asset operations describe <OP_NAME>] to check the status..."
  if stderr_out=$(gcloud asset export \
                    --organization="${ORGANIZATION_ID}" \
                    --billing-project="${BILLING_PROJECT}" \
                    --content-type="${ct}" \
                    --output-path="${BUCKET}/cai_${ct}.json" 2>&1); then
    op=$(echo "${stderr_out}" | sed -n 's/.*gcloud asset operations describe \([^]]*\)\].*/\1/p')
    if [ -n "${op}" ] && [[ "${op}" =~ ^organizations/[0-9]+/operations/[a-zA-Z0-9/_-]+$ ]]; then
      OP_NAMES+=("${op}")
      echo "     Operation: ${op}"
    else
      FAILED+=("${ct}")
      echo "     ERROR: Could not parse valid operation name from output:" >&2
      echo "     ${stderr_out}" >&2
    fi
  else
    FAILED+=("${ct}")
    echo "     FAILED to submit content-type=${ct}:" >&2
    echo "     ${stderr_out}" >&2
  fi
done

if [ "${#FAILED[@]}" -gt 0 ]; then
  echo "ERROR: Failed to submit exports for: ${FAILED[*]}" >&2
  exit 1
fi

echo
echo "Waiting for ${#OP_NAMES[@]} export operation(s) to finish..."
OP_FAILED=()
if [ "${#OP_NAMES[@]}" -gt 0 ]; then
  for op in "${OP_NAMES[@]}"; do
    while true; do
      status=$(gcloud asset operations describe "${op}" \
                 --billing-project="${BILLING_PROJECT}" \
                 --format="value(done)" 2>/dev/null || echo "")
      if [ "${status}" = "True" ] || [ "${status}" = "true" ]; then
        op_error=$(gcloud asset operations describe "${op}" \
                     --billing-project="${BILLING_PROJECT}" \
                     --format="value(error)" 2>/dev/null || echo "")
        if [ -n "${op_error}" ]; then
          echo "  [FAILED] ${op}" >&2
          echo "           Error: ${op_error}" >&2
          OP_FAILED+=("${op}")
        else
          echo "  [DONE] ${op}"
        fi
        break
      fi
      echo "  [RUNNING] ${op} (checking again in ${POLL_INTERVAL_SECONDS}s...)"
      sleep "${POLL_INTERVAL_SECONDS}"
    done
  done
fi

if [ "${#OP_FAILED[@]}" -gt 0 ]; then
  echo >&2
  echo "ERROR: ${#OP_FAILED[@]} Cloud Asset export operation(s) failed." >&2
  echo "Common causes: GCS bucket has CMEK/retention policy enabled, or the Cloud Asset service agent lacks write access to ${BUCKET_ROOT}." >&2
  exit 1
fi

echo
echo "[4/4] Downloading exported files to current directory ($(pwd))..."
for ct in "${CONTENT_TYPES[@]}"; do
  gcloud storage cp "${BUCKET}/cai_${ct}.json" "./cai_${ct}.json" \
    --billing-project="${BILLING_PROJECT}"
  chmod 600 "./cai_${ct}.json"
done

if [ "${CLEANUP_GCS}" = "true" ]; then
  echo "Cleaning up temporary export objects in ${BUCKET}..."
  for ct in "${CONTENT_TYPES[@]}"; do
    gcloud storage rm "${BUCKET}/cai_${ct}.json" --billing-project="${BILLING_PROJECT}" || true
  done
fi

echo
echo "Export complete! Downloaded files (permissions restricted to 0600):"
ls -lh cai_resource.json cai_iam-policy.json cai_org-policy.json
echo
echo "Next step: Run the AI preprocessor script to generate the SIEM sizing report:"
echo "  python3 2_prepare_siem_sizing_report.py --with-metrics --billing-project ${BILLING_PROJECT}"
