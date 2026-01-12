#!/bin/bash
set -e  # Exit on any error
echo "=== Setting proxy environment variables ==="
export http_proxy="http://jusherma-dev.cisco.com:3128/"
export https_proxy="http://jusherma-dev.cisco.com:3128/"
echo "Proxy variables set successfully"

echo "=== Updating package manager ==="
sudo -E apt update
echo "Package manager updated successfully"

echo "=== Installing policykit-1 ==="
sudo DEBIAN_FRONTEND=noninteractive apt install --reinstall policykit-1 -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"
echo "policykit-1 installed successfully"

echo "=== Installing ISC DHCP server ==="
sudo systemctl mask isc-dhcp-server.service
sudo -E apt install isc-dhcp-server -y
echo "ISC DHCP server installed successfully"
