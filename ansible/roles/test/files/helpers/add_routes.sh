#!/bin/bash

set -e

for j in `seq 0 15`; do
    if ! (route | grep "172.16.$j.0"); then
        cmd="ip route add 172.16.$j.0/24 nexthop via 10.0.0.33 "
        for i in `seq 1 15`; do
            cmd+="nexthop via 10.0.0.$((32+2*$i+1)) "
        done
        $cmd
    fi
done
