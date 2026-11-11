#!/usr/bin/env python3
"""Run inside the owned PTF namespace; check every endpoint and frozen routed traffic path."""

import ipaddress
import json
from pathlib import Path
import select
import socket
import subprocess
import sys
import time


def forwarding_probe(ingress, egress, router_mac, case_id):
    from scapy.all import Ether, IP, Raw, UDP

    payload = ("generic-smoke:" + case_id).encode()
    source, destination = (str(ipaddress.ip_interface(row["ptf_address"]).ip) for row in (ingress, egress))
    packet = bytes(Ether(src=ingress["mac"], dst=router_mac) / IP(src=source, dst=destination, ttl=64)
                   / UDP(sport=31337, dport=32567) / Raw(load=payload))
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as receive:
        receive.bind(("eth" + str(egress["ptf_index"]), 0))
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as send:
            send.bind(("eth" + str(ingress["ptf_index"]), 0))
            send.send(packet)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if not select.select([receive], [], [], max(0, deadline - time.monotonic()))[0]:
                break
            observed = Ether(receive.recv(65535))
            if (IP in observed and UDP in observed and observed[IP].src == source and observed[IP].dst == destination
                    and observed[UDP].sport == 31337 and observed[UDP].dport == 32567
                    and bytes(observed[UDP].payload) == payload):
                if observed[IP].ttl != 63 or observed.dst.lower() != egress["mac"]:
                    raise ValueError(case_id + ": packet did not follow the expected routed DUT path")
                return
    raise ValueError(case_id + ": no matching forwarded packet on the independent egress endpoint")


def run(request):
    by_port = {row["dut_port"]: row for row in request["endpoints"]}
    if not request["traffic_cases"]:
        raise ValueError("The frozen manifest has no independent traffic cases")
    for row in request["endpoints"]:
        name = "eth" + str(row["ptf_index"])
        if Path("/sys/class/net", name, "address").read_text().strip().lower() != row["mac"]:
            raise ValueError("Actual PTF MAC differs from the frozen endpoint")
        gateway = str(ipaddress.ip_interface(row["dut_address"]).ip)
        completed = subprocess.run(["ping", "-n", "-I", name, "-c", "3", "-W", "2", gateway],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=12, check=False)
        if completed.returncode:
            raise ValueError("Gateway/ARP smoke failed on " + name)
        neighbors = json.loads(subprocess.check_output(["ip", "-j", "neighbor", "show", "to", gateway, "dev", name]))
        if not any(item.get("lladdr", "").lower() == request["router_mac"] for item in neighbors):
            raise ValueError("Gateway neighbor is not the actual reserved DUT router MAC")
    for case in request["traffic_cases"]:
        ingress, egress = by_port[case["ingress"]], by_port[case["egress"]]
        if ingress["ptf_index"] == egress["ptf_index"]:
            raise ValueError("Ingress and egress must be independent")
        forwarding_probe(ingress, egress, request["router_mac"], case["id"])
    return {"ready": True, "gateway_endpoints_passed": len(by_port),
            "forwarding_cases_passed": len(request["traffic_cases"]),
            "meaning": "Initial Generic deployment smoke, not full HLD or MMU qualification"}


def main():
    try:
        print(json.dumps(run(json.load(sys.stdin)), sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError, ImportError, subprocess.SubprocessError) as error:
        print("Generic packet smoke failed: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
