#!/bin/bash

for i in $(seq 0 33);
do
  echo "set_rdq_rl 50 $i 0 0 0" > /proc/mlx_sx/sx_core
done
