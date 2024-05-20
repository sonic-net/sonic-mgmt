#!/bin/bash

test_name=''
push_config_after_test='false'
push_config_before_test='false'
push_config_success='true'

print_usage() {
  printf "Use:\n\t'-t tests/ondatra:test_name' to run the test.\n\t'-b' to push the switch config before the test.\n\t'-a' to push the config after the test.\n"
}

while getopts 'abt:' arg; do
  case "${arg}" in
    t) test_name="${OPTARG}" ;;
    a) push_config_after_test='true' ;;
    b) push_config_before_test='true' ;;
    *) print_usage
       exit 1 ;;
  esac
done

function push_config() {
  bazel test --test_output=streamed tests/ondatra:installation_test --test_strategy=exclusive --cache_test_results=no
  if [ $? -ne 0 ]; then
      push_config_success='false'
  fi
}

# Pushes the config before/after test.
function run_test() {
  if [ -z "$test_name" ]; then
    print_usage
    exit 1
  fi

  if [ $push_config_before_test = 'true' ]; then
    push_config
  fi

  if [ $push_config_success = 'true' ]; then
    bazel test --test_output=streamed "$test_name" --test_strategy=exclusive --cache_test_results=no --test_timeout=10000000
  fi

  if [ $push_config_after_test = 'true' ]; then
    push_config
  fi
}

run_test
