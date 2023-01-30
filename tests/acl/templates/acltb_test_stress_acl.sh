#!/bin/bash
loop_times=100
finished_times=0
while [[ ${loop_times} > 0 ]]; do
        echo "Load acl rules"
        sonic-cfggen -j /tmp/acltb_test_stress_acl_rules.json -w
        sleep(1)
        echo "Delete acl rules"
        acl-loader delete STRESS_ACL
        let finished_times+=1
        let loop_times-=1
        echo "Finished ${finished_times} times, ${loop_times} times remaining"
done
show acl rule
show acl table
echo "End"
