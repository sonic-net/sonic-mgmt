#!/bin/bash

if [[ $(id -u) -ne 0 ]]; then
    echo "Root privelege required"
    exit
fi

if [ $# -eq 0 ]; then
    echo "Please specify server's external facing port name"
    exit
fi

echo "Setting up NAT..."
iptables -t nat -A POSTROUTING -s 10.250.0.0/24 -o $1 -j MASQUERADE
iptables -A FORWARD -i $1 -j ACCEPT
iptables -A FORWARD -i br1 -j ACCEPT
echo "Updated IP tables rules: "
iptables -v -L
