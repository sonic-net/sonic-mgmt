#!/bin/bash

set -e

for i in `cat /proc/net/dev | grep eth | awk -F'eth|:' '{print $2}'`; do
  last_el=$((1+i*2))
  ip address add 10.0.0.$last_el/31 dev eth$i
done
