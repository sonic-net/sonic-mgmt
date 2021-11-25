#!/bin/bash

set -e

# only seek for sub-interface and add ip for them
for sub_intf in `ls /sys/class/net | grep -E "^eth[0-9]+(\.[0-9]+)$"`; do
  # for example, sub_intf be like: eth4.10, then corresponding properties be like:
  # port: 4, vlan_id: 10, last_ed: 33, ip: 10.0.0.33/31
  port=`echo $sub_intf|awk  -F'eth|\.' '{print $2}'`
  vlan_id=`echo $sub_intf|awk  -F'eth|\.' '{print $3}'`
  last_el=$((25+port*2))
  ip address add 10.0.0.$last_el/31 dev "eth$port.$vlan_id"
done
