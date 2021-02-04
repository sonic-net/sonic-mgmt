#!/bin/bash

ROOT=/tmp/scapy-tgen
mkdir -p $ROOT

set -x

cd $(dirname $0)

if [ -f $ROOT/service.pid ]; then
  pkill -F $ROOT/service.pid
  rm -f $ROOT/service.pid
fi

export TMPDIR=$ROOT/tmp/
rm -rf $TMPDIR;mkdir $TMPDIR

mkdir -p $ROOT/logs
VER=$(date +%Y_%d_%m-%H_%M_%S)
if [ -d $ROOT/logs/current ]; then
  find $ROOT/logs/current -name "*.pid" | xargs -r -L 1 pkill -F
  mv -f $ROOT/logs/current $ROOT/logs/$VER
fi
mkdir $ROOT/logs/current

export HOME=$ROOT/logs/current
export SCAPY_TGEN_LOGS_PATH=$HOME

ulimit -n 50000

# remove problematic files
rm -f cgi.py*

cleanup()
{
  find $ROOT/logs/current -name "*.pid" | xargs -r -L 1 pkill -F
}
trap cleanup SIGINT SIGTERM EXIT

python pyro-service.py 2>&1 | tee $HOME/service.log

