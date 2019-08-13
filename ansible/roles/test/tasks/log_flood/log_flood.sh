#!/bin/bash
log_qty=${1:-1000}
for i in $(seq 1 $log_qty) 
do
    logger "Log flood test message $i of $log_qty"
done

