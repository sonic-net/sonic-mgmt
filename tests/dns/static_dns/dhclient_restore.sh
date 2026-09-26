#!/bin/bash

set -euo pipefail

mgmt_port="$1"
pid_file="$2"
done_file="$3"

ip_addrs=$(mktemp)
routes=$(mktemp)
current_ip_addrs=$(mktemp)
current_routes=$(mktemp)

cleanup() {
    rm -f "$ip_addrs" "$routes" "$current_ip_addrs" "$current_routes"
}
trap cleanup EXIT

# Save the full pre-test IPv4 state before dhclient can modify eth0.
sudo ip -4 -o addr show dev "$mgmt_port" scope global | awk '{print $4}' | sort > "$ip_addrs"
sudo ip -4 route show default dev "$mgmt_port" | sort > "$routes"

# Run DHCP and stop the client started by this test.
sudo dhclient -pf "$pid_file" "$mgmt_port"
if [ -f "$pid_file" ]; then
    sudo kill "$(cat "$pid_file")" || true
fi
sudo rm -f "$pid_file"

# Clear current global IPv4 addresses because dhclient may have added a lease address.
sudo ip -4 addr flush dev "$mgmt_port" scope global

# Add back exactly the IPv4 addresses captured before DHCP.
while read -r addr; do
    [ -n "$addr" ] || continue
    sudo ip -4 addr add "$addr" dev "$mgmt_port"
done < "$ip_addrs"

# Remove current default routes because dhclient may have installed or changed one.
while sudo ip -4 route del default dev "$mgmt_port" 2>/dev/null; do
    true
done

# Restore the exact default routes captured before DHCP.
while read -r route; do
    [ -n "$route" ] || continue
    # Keep $route unquoted so ip receives the saved route fields as separate arguments.
    # shellcheck disable=SC2086
    sudo ip -4 route add $route 2>/dev/null || sudo ip -4 route replace $route
done < "$routes"

sudo ip -4 -o addr show dev "$mgmt_port" scope global | awk '{print $4}' | sort > "$current_ip_addrs"
sudo ip -4 route show default dev "$mgmt_port" | sort > "$current_routes"

diff -u "$ip_addrs" "$current_ip_addrs"
diff -u "$routes" "$current_routes"

touch "$done_file"
