#!/usr/bin/env bash
# Bootstrap-project sets a project up so that ansible-test integration
# can be run.
#
# dependencies:
#  - google-cloud-sdk (gcloud)
#
#
PROJECT_ID="${1}"
SERVICE_ACCOUNT_NAME="${2}"
SERVICE_LIST=(
    "appengine"
    "bigtableadmin.googleapis.com"
    "cloudbuild.googleapis.com"
    "cloudfunctions"
    "cloudkms.googleapis.com"
    "cloudresourcemanager.googleapis.com"
    "cloudscheduler.googleapis.com"
    "cloudtasks.googleapis.com"
    "container"
    "dns"
    "file.googleapis.com"
    "ml.googleapis.com"
    "redis.googleapis.com"
    "runtimeconfig.googleapis.com"
    "sourcerepo.googleapis.com"
    "spanner.googleapis.com"
    "sqladmin.googleapis.com"
    "storage.googleapis.com"
    "tpu.googleapis.com"
)

REQUIRED_ROLE_LIST=(
    "roles/storage.objectAdmin"
    "roles/storage.legacyBucketReader"
    "roles/storage.objectCreator"
    "roles/source.admin"
)

for SERVICE in "${SERVICE_LIST[@]}"; do
    echo "enabling service $SERVICE..."
    gcloud services enable "$SERVICE" --project="$PROJECT_ID"
done

if [ -n "$SERVICE_ACCOUNT_NAME" ]
then
    for ROLE in "${REQUIRED_ROLE_LIST[@]}"; do
        echo "enabling role $ROLE..."
        gcloud projects add-iam-policy-binding "$PROJECT_ID" \
            --member="serviceAccount:$SERVICE_ACCOUNT_NAME" \
            --role="$ROLE"
    done
fi

if ! gcloud app describe --project="$PROJECT_ID" > /dev/null; then
    echo "creating appengine project..."
    gcloud app create --project="$PROJECT_ID" --region=us-central
fi

# create and upload cloud function for testing

BUCKET_NAME="gs://${PROJECT_ID}-ansible-testing"

if ! gcloud storage buckets describe "${BUCKET_NAME}" > /dev/null; then
    gcloud storage buckets create "${BUCKET_NAME}" --project="${PROJECT_ID}"
fi

gsutil cp ./test-fixtures/cloud-function.zip "${BUCKET_NAME}"


# The following is hard to automate, so echo
echo "Done! It may take up to 10 minutes for some of the changes to fully propagate."