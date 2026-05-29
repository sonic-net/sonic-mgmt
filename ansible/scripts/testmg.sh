#!/bin/bash

testbed="\
vms-sn2700-t1
vms-sn2700-t1-lag
vms-sn2700-t0
vms-s6000-t0
vms-a7260-t0
vms-s6100-t0
vms-s6100-t1
vms-s6100-t1-lag"

for tb in ${testbed}; do
    echo $tb
    ./testbed-cli.sh test-mg $tb lab password.txt | grep -E 'changed=[1-9]+'
    if [ $? == 0 ]; then
        echo "generated minigraph for testbed $tb mismatch"
        exit 1
    fi
done
