#!/bin/bash

set -x

VER=`date +%Y-%m-%d-%H-%M-%S`

pushd /data/work

ARGS="$ARGS --logs-level debug"
ARGS="$ARGS --results-prefix=results"
ARGS="$ARGS --get-tech-support none"
ARGS="$ARGS --fetch-core-files none"
ARGS="$ARGS --syslog-check none"
ARGS="$ARGS --save config-db module"
ARGS="$ARGS --topology-check module"
ARGS="$ARGS --logs-path logs/$VER"
ARGS="$ARGS --continue-on-collection-errors"
ARGS="$ARGS --max-time session 0 --max-time module 0 --max-time function 0"
ARGS="$ARGS --noop"
ARGS="$ARGS --tryssh=0"
ARGS="$ARGS --testbed-file testbed.yaml"
ARGS="$ARGS --env SPYTEST_RPS_DEBUG 0"

ARGS="$ARGS --tclist-bucket 1,2,4"

if [ -f /scripts/run.args ]; then
  MORE_ARGS=$(cat /scripts/run.args)
  ARGS="$ARGS $MORE_ARGS"
fi

if [[ $ARGS != *--test-suite* ]]; then
  ARGS="$ARGS --test-suite community-vs"
fi

/repo/bin/spytest $ARGS $@

