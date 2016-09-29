#!/bin/bash

set -e

for i in $(seq 0 31); do
  ip address flush dev eth$i
done
