#!/bin/bash -eu
set -o pipefail
source "$(git rev-parse --show-toplevel)/dev/util.sh"

function run_test_cases {
  for test_case in test_cases/*; do
    teardown_and_setup_inventory
    run_test_case "$(basename -- "$test_case")"
  done
}

function run_test_case {
  local test_case="$1"
  echo "---- testing ${test_case} ----"

  if [ -z "$test_case" ]; then
    echo ERROR: run_test_case called with no argument 1>&2
    exit 1
  fi

  docker exec -e HFTOKEN="$(hf_token)" \
    "$(ansible_cid)" bash -ec "
      cd /cyberark/tests/conjur_host_identity

      # You can add -vvvvv here for debugging
      ansible-playbook test_cases/$test_case/playbook.yml
    "

  if [ -d "test_cases/${test_case}/tests/" ]; then
    docker exec "$(ansible_cid)" bash -ec "
      cd /cyberark/tests/conjur_host_identity
      py.test --junitxml=./junit/${test_case} --connection docker -v test_cases/${test_case}/tests/test_default.py
    "
  fi
}

run_test_cases
