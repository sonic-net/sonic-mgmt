#!/usr/bin/env bash
# cleanup-project cleans up an ansible testing project
#
# WARNING: do not run tests against a project while
# this is running, or else your tests will fail.
#
# dependencies:
#  - google-cloud-sdk (gcloudgcloud )
set -e
PROJECT_ID="${1}"
FOLDER_ID="${2}"
# service account is unused today
# SERVICE_ACCOUNT_NAME="${2}"
ZONE="us-central1-a"

main() {
    # note: the ordering here is deliberate, to start with
    # leaf resources and work upwards to parent resources.
    cleanup_resource "container" "clusters" "" "--zone=$ZONE"
    cleanup_resource_per_region "compute" "vpn-tunnels"
    cleanup_resource "compute" "instances" "" "--zone=$ZONE"
    cleanup_resource_per_region "compute" "addresses"
    cleanup_resource "compute" "target-http-proxies" "" "--global"
    cleanup_resource "compute" "forwarding-rules" "--global" "--global"
    cleanup_resource "compute" "forwarding-rules" \
        "--regions=us-central1" "--region=us-central1"
    cleanup_resource "compute" "url-maps" "--global" "--global"
    cleanup_resource "compute" "url-maps" \
        "--regions=us-central1" "--region=us-central1"
    cleanup_resource "compute" "backend-services" "--global" "--global"
    cleanup_resource "compute" "backend-services" \
        "--regions=us-central1" "--region=us-central1"
    for resource in $(gcloud projects list --filter="parent.id:$FOLDER_ID" --format="csv[no-heading](PROJECT_ID)"); do
        gcloud projects delete "${resource}" -q
    done
}

cleanup_resource() {
    resource_group="$1"
    resource="$2"
    extra_list_arg="$3"
    extra_delete_arg="$4"

    if [ -z "$extra_list_arg" ]
    then
        mapfile -t resources < <(gcloud "${resource_group}" "${resource}" list --project="${PROJECT_ID}" --format="csv[no-heading](name)")
    else
        mapfile -t resources < <(gcloud "${resource_group}" "${resource}" list --project="${PROJECT_ID}" --format="csv[no-heading](name)" "${extra_list_arg}")
    fi

    for resource_id in "${resources[@]}"
    do
        if [ -z "$extra_delete_arg" ]
        then
            gcloud "${resource_group}" "${resource}" delete "${resource_id}" --project="${PROJECT_ID}" -q
        else
            gcloud "${resource_group}" "${resource}" delete "${resource_id}" --project="${PROJECT_ID}" -q "${extra_delete_arg}"
        fi
    done
}

cleanup_resource_per_region() {
    resource_group="$1"
    resource="$2"
    for resource_and_region in $(gcloud "${resource_group}" "${resource}" list --project="${PROJECT_ID}" --format="csv[no-heading](name,region)"); do
        read -r resource_id region < <(echo "$resource_and_region" | tr "," " ")
        gcloud "${resource_group}" "${resource}" delete "${resource_id}" --project="${PROJECT_ID}" -q --region="${region}"
    done
}

main