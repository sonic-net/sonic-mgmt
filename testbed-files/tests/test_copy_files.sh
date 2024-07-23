#!/bin/bash

# Usage: execute as "./tests/test_copy_files.sh"

verify_rc() {
    # Expects first parameter is expected return code.
    # Requires this to be the first command after the command being tested.
    actual_rc=$?
    if test "$actual_rc" != "$1"; then
        echo "ERROR: Unexpected return code $?"
        exit 1
    fi
    echo # New line separator after test run
}

ok() {
    verify_rc 0
}

bad() {
    verify_rc 1
}

run_test(){
    echo "TEST CMD: $@"
    $@ # Must be last command for RC verification
}

# Run a sequence of basic commands that should have clean output and correct return codes
run_test ./copy_files.sh -h
ok

run_test ./copy_files.sh -l
ok

run_test ./copy_files.sh -l -v
ok

run_test ./copy_files.sh does_not_exist
bad

run_test ./copy_files.sh
bad

# TODO: Add more commands that verify copying features once a cleanability option is added
# to the main script. Otherwise execution may impact current git status negatively.
