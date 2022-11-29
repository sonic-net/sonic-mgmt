#!/bin/bash
loop_times=1000
finished_times=0
while [[ ${loop_times} > 0 ]]; do
        acl-loader update full /tmp/ip_stress_acl.json
        acl-loader delete
        let finished_times+=1
        let loop_times-=1
        echo "Finished ${finished_times} times, ${loop_times} times remaining"
done
show acl rule
show acl table
echo "End"
