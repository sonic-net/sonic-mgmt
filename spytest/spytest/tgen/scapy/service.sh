#!/bin/bash

set -x

cd $(dirname $0)

export HOME=$PWD/logs/current
if [ -f $HOME/service.pid ]; then
  pkill -F $HOME/service.pid
  rm -f $HOME/service.pid
fi

mkdir -p logs
VER=$(date +%Y_%d_%m-%H_%M_%S)
mv -f logs/current logs/$VER
mkdir -p logs/current
export HOME=$PWD/logs/current

export SCAPY_TGEN_LOGS_PATH=$HOME

ulimit -n 50000

# remove problematic files
rm -f cgi.py*

python pyro-service.py 2>&1 | tee $HOME/service.log

