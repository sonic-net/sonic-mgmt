#!/usr/bin/env bash
# Run the tests listed in ci/kne/tests.txt (or the paths given) against the slot's testbed.
# usage: run_test.sh <SLOT> [test path ...]
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
slot_vars "$1"
shift

if [[ $# -gt 0 ]]; then
  TESTS=("$@")
else
  mapfile -t TESTS < <(sed -e 's/#.*//' -e 's/[[:space:]]*$//' -e '/^[[:space:]]*$/d' "${KNE_CI_DIR}/tests.txt")
fi
[[ ${#TESTS[@]} -gt 0 ]] || die "no tests listed in ci/kne/tests.txt"

mkdir -p "${REPO_ROOT}/tests/logs"
log "pytest on ${TESTBED}: ${TESTS[*]}"
# Stay root. The runner uid is not in this image's passwd, and Ansible 2.20's
# ssh_askpass then fails the DUT login. restore_checkout_owner returns the tree.
trap restore_checkout_owner EXIT
docker exec -w /data/sonic-mgmt/tests \
  -e ANSIBLE_LIBRARY=/data/sonic-mgmt/ansible/library \
  -e ANSIBLE_MODULE_UTILS=/data/sonic-mgmt/ansible/module_utils \
  -e SONIC_MGMT_SONIC_PASSWORD -e SONIC_MGMT_PTF_PASSWORD \
  "$CI_CONTAINER" python3 -m pytest "${TESTS[@]}" -v \
    --inventory "/data/sonic-mgmt/ansible/${INV}" --host-pattern "$DUT_NAME" \
    --testbed "$TESTBED" --testbed_file /data/sonic-mgmt/ansible/kne_testbed.yaml \
    --disable_loganalyzer --skip_sanity --skip_post_check --allow_recover \
    --disable_memory_utilization --skip_yang --ignore-conditional-mark \
    -p no:test_completeness \
    --junitxml="logs/junit-${SLOT}.xml"
