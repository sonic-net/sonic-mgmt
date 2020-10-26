#!/bin/bash

if [[ $(id -u) -ne 0 ]]; then
    echo "Root privelege required"
    exit
fi

echo "Checking for libvirt package..."
if ! command -v virsh; then
    echo "libvirt not found, installing libvirt"
    apt-get install -y libvirt-bin
fi
echo

echo "Checking for bridge-utils package..."
if ! command -v brctl; then
    echo "brctl not found, installing bridge-utils"
    apt-get install -y bridge-utils
fi
echo

echo "Checking for net-tools package..."
if ! command -v ifconfig; then
    echo "ifconfig no t found, install net-tools"
    apt-get install -y net-tools
fi
echo

echo "Checking if br1 already exists..."
if ifconfig br1; then
    echo "br1 already exists, delete and then rerun this script"
    exit
fi
echo

echo "Creating management bridge br1..."
virsh net-define files/br1.xml
virsh net-start br1
virsh net-autostart br1
echo

echo "Enabling br1 forwarding..."
l=$(iptables -v -L | grep -n 'Chain FORWARD')
lowerbound="${l%%:*}"
sync=0
iptables -v -L | grep -n 'REJECT.*br1' | while read -r line; do
  upperbound=${line%%:*}
  let index=$upperbound-$lowerbound-$sync-1
  iptables -D FORWARD $index
  ((sync=sync+1))
done

echo "COMPLETE. Bridge info:"
echo
brctl show br1
echo
ifconfig br1
