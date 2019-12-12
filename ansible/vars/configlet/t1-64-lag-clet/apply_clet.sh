#! /bin/bash

# Sleep to let all BGP sessions go up & running before adding a T0
sleep 1m
/usr/bin/configlet -j /etc/sonic/clet-to_clear.json -d
/usr/bin/configlet -j /etc/sonic/clet-add.json -u
