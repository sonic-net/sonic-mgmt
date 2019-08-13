#!/bin/bash

set -e

for i in `cat /proc/net/dev | grep eth | awk -F'eth|:' '{print $2}'`; do
  ip address flush dev eth$i
done
