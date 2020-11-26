#! /bin/bash

# Script to bounce interfaces from the commandline repeatedly
# $1 is the number of seconds to run the test
# $2 is the interface to use

end=$((SECONDS+$1))

while [ $SECONDS -lt $end ]
  do
    sudo config interface shutdown $2
    sudo config interface startup $2 
done
