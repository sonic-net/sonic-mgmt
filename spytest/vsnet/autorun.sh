#!/bin/bash

RUN=${SPYTEST_RUN:=bash}

if [ "$RUN" == "test" ]; then
  #bash topo.sh
  ./helper.sh topo
  bash test.sh
elif [ "$RUN" == "topo" ]; then
  #bash topo.sh
  ./helper.sh topo
  bash
elif [ "$RUN" == "bash" ]; then
  bash
fi
