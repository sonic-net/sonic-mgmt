#!/usr/bin/env python3
"""Configure an exclusively owned Switch-Host USB link without changing other interfaces."""

import argparse
import ipaddress
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys


def run(command):
    return subprocess.check_output(command, text=True, stderr=subprocess.PIPE, timeout=10).strip()


def validate_settings(interface, address):
    if not re.fullmatch(r"usb[0-9]{1,12}", interface):
        raise ValueError("Interface must be named usbN (at most 15 characters)")
    host = ipaddress.IPv4Interface(address)
    if (str(host) != address or not host.network.subnet_of(ipaddress.IPv4Network("169.254.0.0/16"))
            or host.network.prefixlen > 30
            or host.ip in (host.network.network_address, host.network.broadcast_address)):
        raise ValueError("Address must be a canonical IPv4 link-local host CIDR with prefix /16 through /30")
    return host


def check_platform(host):
    from sonic_py_common import device_info

    if not device_info.is_switch_host() or device_info.is_switch_bmc():
        raise ValueError("Provisioning is only supported on a platform identified as Switch-Host, not a BMC")
    peer = ipaddress.IPv4Address(device_info.get_bmc_address())
    if peer not in host.network or peer in (host.ip, host.network.network_address, host.network.broadcast_address):
        raise ValueError("The platform's configured bmc_addr must be a different host in the USB link subnet")


def check_ownership(interface, host, ip):
    links = json.loads(run([ip, "-j", "address", "show"]))
    matches = [link for link in links if link["ifname"] == interface]
    if len(matches) != 1:
        raise ValueError("USB interface is missing or ambiguous: {}".format(interface))
    link = matches[0]
    if link.get("master"):
        raise ValueError("USB interface is enslaved to another interface")
    for other in links:
        for address in other.get("addr_info", []):
            if address["family"] != "inet":
                continue
            existing = ipaddress.IPv4Interface("{}/{}".format(address["local"], address["prefixlen"]))
            if other["ifname"] == interface:
                if existing != host:
                    raise ValueError("USB interface already has a different IPv4 address; remove it explicitly first")
            elif existing.network.overlaps(host.network):
                raise ValueError("USB subnet overlaps another interface: {}".format(other["ifname"]))

    ifquery = shutil.which("ifquery")
    if ifquery and interface in run([ifquery, "--list"]).splitlines():
        raise ValueError("USB interface is configured by ifupdown")

    networkd = Path("/run/systemd/netif/links") / str(link["ifindex"])
    if networkd.exists() and any(
            line.startswith("NETWORK_FILE=") and line.split("=", 1)[1].strip()
            for line in networkd.read_text().splitlines()):
        raise ValueError("USB interface is configured by systemd-networkd")

    nmcli = shutil.which("nmcli")
    if nmcli:
        managed = run([nmcli, "-g", "GENERAL.MANAGED", "device", "show", interface])
        if managed != "no":
            raise ValueError("USB interface is managed by NetworkManager or ownership could not be determined")

    cfggen = shutil.which("sonic-cfggen")
    if not cfggen:
        raise ValueError("sonic-cfggen is required to check live CONFIG_DB ownership")
    config = json.loads(run([cfggen, "-d", "--print-data"]))
    for table in ("PORT", "INTERFACE", "MGMT_PORT", "MGMT_INTERFACE",
                  "PORTCHANNEL_INTERFACE", "VLAN_INTERFACE"):
        if any(key.split("|", 1)[0] == interface for key in config.get(table, {})):
            raise ValueError("USB interface is configured in CONFIG_DB table {}".format(table))


def configure(interface, address, check=False):
    host = validate_settings(interface, address)
    check_platform(host)
    ip = shutil.which("ip")
    if not ip:
        raise ValueError("iproute2 is required")
    check_ownership(interface, host, ip)
    if not check:
        run([ip, "link", "set", "dev", interface, "up"])
        run([ip, "address", "replace", address, "dev", interface])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Validate without modifying the link")
    parser.add_argument("interface")
    parser.add_argument("address")
    args = parser.parse_args()
    try:
        configure(args.interface, args.address, args.check)
    except (ValueError, OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired,
            ImportError, AttributeError) as error:
        detail = str(error)
        if isinstance(error, subprocess.CalledProcessError) and error.stderr:
            detail += ": " + error.stderr.strip()
        print("BMC USB link provisioning failed: {}".format(detail), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
