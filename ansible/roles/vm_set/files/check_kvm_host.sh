#!/bin/bash

set -u

if (( $# > 0 )); then
    echo "Usage: $0" >&2
    exit 2
fi

failures=0

check()
{
    local label="$1"
    local output
    shift
    if output=$(timeout 30 "$@" 2>&1); then
        printf '[PASS] %s\n' "$label"
    else
        printf '[FAIL] %s\n%s\n' "$label" "${output:-Command failed.}"
        failures=$((failures + 1))
    fi
}

for service in docker containerd ovsdb-server ovs-vswitchd; do
    check "Service: $service" systemctl is-active --quiet "$service"
done

check "Docker API" docker info --format '{{.ServerVersion}}'
# Libvirt can use monolithic or modular, socket-activated daemons.
check "Libvirt API" virsh --readonly --connect qemu:///system list --all --name
check "Open vSwitch database" ovs-vsctl --timeout=30 --retry show

if (( failures > 0 )); then
    printf '\nHost diagnostics:\n'
    cat /etc/os-release
    uname -r
    timeout 10 systemctl --no-pager show \
        -p Id -p ActiveState -p SubState -p Result -p ExecMainStatus \
        docker containerd libvirtd virtqemud ovsdb-server ovs-vswitchd 2>&1 || true
    timeout 10 journalctl --no-pager -b -n 50 -u ovsdb-server -u ovs-vswitchd 2>&1 || true
    printf '\nKVM host service health check failed: %s check(s).\n' "$failures"
    exit 42
fi

echo "KVM host service health check passed."
