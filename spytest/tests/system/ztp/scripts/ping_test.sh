#!/bin/sh

# -q quiet
# -c nb of pings to perform

ping -q -c5 192.168.1.1 > /dev/null

if [ $? -eq 0 ]
then
    echo "Ping successful"
    exit 0
else
   echo "Ping failed"
   exit 1
fi
