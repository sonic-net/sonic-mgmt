#!/bin/bash

set -e

for i in $(seq 0 31); do
  last_el=$((1+i*2))
  ip address add 10.0.0.$last_el/31 dev eth$i
done
