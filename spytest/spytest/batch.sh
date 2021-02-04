#!/bin/bash

dir=$(dirname $0)
spytest=$dir/../bin/spytest
TYPE=$1;shift

export SPYTEST_BATCH_RUN_NEW=2
if [ "$TYPE" == "slave" ]; then
    export PYTEST_XDIST_WORKER=1
    export SPYTEST_NO_CONSOLE_LOG=1
elif [ "$TYPE" != "master" ]; then
    echo "USAGE: $0 [master|slave] <spytest arguments> ..."
    exit 0
fi

exec $spytest $*

