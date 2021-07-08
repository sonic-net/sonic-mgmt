#!/bin/bash
if [[ $(id -u) -ne 0 ]]; then
    echo "Root privilege required"
    exit
fi

echo "Refreshing apt package lists..."
apt-get update
echo

echo "STEP 1: Checking for j2cli package..."
if ! command -v j2; then
    echo "j2cli not found, installing j2cli"
    cmd="install j2cli==0.3.10"
    if ! command -v pip &> /dev/null; then
        pip3 $cmd
    else
        pip $cmd
    fi
fi
echo

echo "STEP 2: Checking for bridge-utils package..."
if ! command -v brctl; then
    echo "brctl not found, installing bridge-utils"
    apt-get install -y bridge-utils
fi
echo

echo "STEP 3: Checking for net-tools package..."
if ! command -v ifconfig; then
    echo "ifconfig not found, install net-tools"
    apt-get install -y net-tools
fi
echo

echo "STEP 4: Checking for ethtool package..."
if ! command -v ethtool; then
    echo "ethtool not found, install ethtool"
    apt-get install -y ethtool
fi
echo

echo "STEP 5: Checking if bridge br1 already exists..."
if ! ifconfig br1; then
    echo "br1 not found, creating bridge network"
    brctl addbr br1
    brctl show br1
fi
echo

echo "STEP 6: Configuring br1 interface..."
echo "Assigning 10.250.0.1/24 to br1"
ifconfig br1 10.250.0.1/24
ifconfig br1 inet6 add fec0::1/64
echo "Bringing up br1"
ifconfig br1 up
echo

echo "COMPLETE. Bridge info:"
echo
brctl show br1
echo
ifconfig br1
