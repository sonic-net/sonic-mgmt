#!/bin/bash

LOG="/tmp/agent_worker.log"
while true
do
    pgrep -af Agent.Worker
    if [ $? -eq 0 ]
    then
        echo "Busy will try after 300 seconds..." >> $LOG
        sleep 300
    else
        echo "Starting Agent.Worker..." >> $LOG
        /bin/Agent.Worker
    fi
done