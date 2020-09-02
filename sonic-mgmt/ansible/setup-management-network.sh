#!/bin/bash

if [[ $(id -u) -ne 0 ]]; then
    echo "Root privilege required"
    exit
fi

echo "STEP 1: Checking for bridge-utils package..."
if ! command -v brctl; then
    echo "brctl not found, installing bridge-utils"
    apt-get install -y bridge-utils
fi
echo

echo "STEP 2: Checking for net-tools package..."
if ! command -v ifconfig; then
    echo "ifconfig not found, install net-tools"
    apt-get install -y net-tools
fi
echo

echo "STEP 3: Checking if bridge br1 already exists..."
if brctl show br1; then
    echo "br1 already exists, deleting first"
    ifconfig br1 down
    brctl delbr br1
fi
echo

echo "STEP 4: Creating management bridge br1..."
brctl addbr br1
ifconfig br1 10.250.0.1/24
ifconfig br1 up
echo

echo "COMPLETE. Bridge info:"
echo
brctl show br1
echo
ifconfig br1
