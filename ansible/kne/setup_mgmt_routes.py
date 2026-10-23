#!/usr/bin/env python3
"""Set up management routes for KNE SONiC topology nodes (DHCP mode).

This script configures only the network routes needed to reach SONiC management
IPs from the bare metal host.  It does NOT configure IPs inside the VMs — that
is handled by dnsmasq (DHCP) running in each pod via startup.sh.

Routes configured:
  1. Bare metal  → kne-control-plane  (172.31.<topo>.0/24 via kind gateway)
  2. kne-control-plane → pod           (<mgmt_ip>/32 via <pod_ip> dev <veth> onlink)
  3. Pod bridge fixup                  (gateway IP + NAT on br<topo>)

Only SONiC nodes are processed. Other pods, such as PTF, have no management
bridge; PTF's management IP is set up by setup_ptf_mgmt.sh.

Usage:
    python3 setup_mgmt_routes.py <rendered-topology-file>


The topology file must be the rendered file passed to `kne create`, not the
template, because the namespace and management subnet are read from it.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Management addressing — must match startup.sh:
#   subnet  172.31.<TOPO_ID>.0/24
#   gateway 172.31.<TOPO_ID>.1
#   VM IP   172.31.<TOPO_ID>.<SWITCH_ID>
# TOPO_ID is capped at 234 because startup.sh derives telnet ports from it
# (5321 + TOPO_ID * 256 + SWITCH_ID must stay below 65536).
# ---------------------------------------------------------------------------
TOPO_ID_MIN = 1
TOPO_ID_MAX = 234
SWITCH_ID_MIN = 2
SWITCH_ID_MAX = 254


def derive_mgmt(topo_id: int, switch_id: int) -> dict[str, str]:
    if not TOPO_ID_MIN <= topo_id <= TOPO_ID_MAX:
        raise ValueError(f"TOPO_ID {topo_id} out of range {TOPO_ID_MIN}-{TOPO_ID_MAX}")
    if not SWITCH_ID_MIN <= switch_id <= SWITCH_ID_MAX:
        raise ValueError(f"SWITCH_ID {switch_id} out of range {SWITCH_ID_MIN}-{SWITCH_ID_MAX}")
    subnet = ipaddress.ip_network(f"172.31.{topo_id}.0/24")
    return {
        "mgmt_subnet": str(subnet),
        "mgmt_gw": f"172.31.{topo_id}.1",
        "mgmt_ip": f"172.31.{topo_id}.{switch_id}",
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _user_home() -> str:
    sudo_user = os.environ.get("SUDO_USER", os.environ.get("USER", ""))
    if sudo_user:
        return os.path.expanduser(f"~{sudo_user}")
    return os.path.expanduser("~")


def _kubectl_env() -> dict[str, str]:
    home = _user_home()
    kubeconfig = os.environ.get("KUBECONFIG", f"{home}/.kube/config")
    return {**os.environ, "KUBECONFIG": kubeconfig, "HOME": home}


def _privileged_cmd(*args: str) -> list[str]:
    if os.geteuid() == 0:
        return list(args)
    return ["sudo", *args]


def _run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


def log(msg: str) -> None:
    print(msg, flush=True)


# ---------------------------------------------------------------------------
# Topology parsing
# ---------------------------------------------------------------------------

def parse_topology(pb_txt_path: Path) -> tuple[str, list[dict]]:
    content = pb_txt_path.read_text(encoding="utf-8")

    topo_name_match = re.search(r'^name:\s+"([^"]+)"', content, re.MULTILINE)
    topo_name = topo_name_match.group(1) if topo_name_match else "unknown"

    fallback_topo_id: int | None = None
    try:
        candidate = int(topo_name)
        if TOPO_ID_MIN <= candidate <= TOPO_ID_MAX:
            fallback_topo_id = candidate
    except ValueError:
        pass

    nodes: list[dict] = []
    for match in re.finditer(r"nodes:\s*\{", content):
        start = match.end() - 1
        depth = 0
        for i in range(start, len(content)):
            if content[i] == "{":
                depth += 1
            elif content[i] == "}":
                depth -= 1
                if depth == 0:
                    block = content[start + 1:i]
                    break

        name = re.search(r'name:\s+"([^"]+)"', block)
        switch_id = re.search(r'SWITCH_ID"\s*value:\s*"(\d+)"', block, re.DOTALL)
        topo_id = re.search(r'TOPO_ID"\s*value:\s*"(\d+)"', block, re.DOTALL)
        image = re.search(r'image:\s+"([^"]+)"', block)

        if not name or not switch_id:
            continue

        resolved_topo_id = int(topo_id.group(1)) if topo_id else fallback_topo_id
        if resolved_topo_id is None:
            continue

        nodes.append({
            "name": name.group(1),
            "switch_id": int(switch_id.group(1)),
            "topo_id": resolved_topo_id,
            "image": image.group(1) if image else "",
        })

    return topo_name, nodes


def is_sonic_node(node: dict) -> bool:
    return "sonic" in node.get("image", "").lower()


# ---------------------------------------------------------------------------
# Route operations
# ---------------------------------------------------------------------------

def get_kind_gateway() -> str:
    result = _run([
        "docker", "inspect", "kne-control-plane",
        "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
    ])
    if result.returncode != 0 or not result.stdout.strip():
        raise RuntimeError(f"Cannot determine kne-control-plane IP: {result.stderr}")
    return result.stdout.strip()


def get_kind_bridge() -> str:
    result = _run([
        "docker", "inspect", "kne-control-plane",
        "--format", "{{range .NetworkSettings.Networks}}{{.NetworkID}}{{end}}",
    ])
    if result.returncode != 0 or not result.stdout.strip():
        raise RuntimeError(f"Cannot determine kind network ID: {result.stderr}")
    net_id = result.stdout.strip()[:12]
    return f"br-{net_id}"


def get_pod_ip(namespace: str, pod_name: str) -> str:
    result = _run(
        ["kubectl", "get", "pod", "-n", namespace, pod_name,
         "-o", "jsonpath={.status.podIP}"],
        env=_kubectl_env(),
    )
    if result.returncode != 0 or not result.stdout.strip():
        raise RuntimeError(f"Cannot get pod IP for {pod_name}: {result.stderr}")
    return result.stdout.strip()


def get_pod_veth(pod_ip: str) -> str | None:
    """Discover the veth device for a pod IP inside kne-control-plane."""
    # "ip route get" works whether the CNI gives each pod its own route or one
    # subnet route via a bridge (as KNE's kind-bridge setup does).
    result = _run([
        "docker", "exec", "kne-control-plane",
        "ip", "route", "get", pod_ip,
    ])
    if result.returncode == 0 and result.stdout.strip():
        match = re.search(r"dev\s+(\S+)", result.stdout)
        if match:
            return match.group(1)
    return None


def add_host_route(subnet: str, kind_gw: str, kind_bridge: str) -> None:
    """Add route on bare metal: subnet via kind gateway."""
    _run(_privileged_cmd("ip", "route", "del", subnet))
    result = _run(_privileged_cmd(
        "ip", "route", "add", subnet, "via", kind_gw, "dev", kind_bridge
    ))
    if result.returncode != 0:
        raise RuntimeError(
            f"Failed to add host route {subnet} via {kind_gw}: {result.stderr}"
        )


def add_kind_route(mgmt_ip: str, pod_ip: str) -> None:
    """Add route in kne-control-plane: mgmt_ip/32 via pod_ip dev veth onlink."""
    host_route = f"{mgmt_ip}/32"
    _run(["docker", "exec", "kne-control-plane", "ip", "route", "del", host_route])

    veth = get_pod_veth(pod_ip)
    cmd = [
        "docker", "exec", "kne-control-plane",
        "ip", "route", "add", host_route, "via", pod_ip,
    ]
    if veth:
        cmd.extend(["dev", veth, "onlink"])

    result = _run(cmd)
    if result.returncode != 0:
        raise RuntimeError(
            f"Failed to add kind route {host_route} via {pod_ip}: {result.stderr}"
        )


def update_pod_bridge(namespace: str, pod_name: str, topo_id: int, mgmt_subnet: str, mgmt_gw: str) -> None:
    """Ensure pod management bridge has correct gateway and NAT."""
    bridge = f"br{topo_id}"
    script = (
        f"ip addr add {mgmt_gw}/24 dev {bridge} 2>/dev/null || true; "
        f"ip route replace {mgmt_subnet} dev {bridge} 2>/dev/null || "
        f"ip route add {mgmt_subnet} dev {bridge} 2>/dev/null || true; "
        f"iptables -t nat -C POSTROUTING -s {mgmt_subnet} -o eth0 -j MASQUERADE "
        f"2>/dev/null || iptables -t nat -A POSTROUTING -s {mgmt_subnet} -o eth0 "
        f"-j MASQUERADE 2>/dev/null || true"
    )
    result = _run(
        ["kubectl", "exec", "-n", namespace, pod_name, "--", "sh", "-c", script],
        env=_kubectl_env(),
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        log(f"  WARNING: pod bridge update failed for {pod_name}: {detail}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Set up management routes for KNE SONiC topology (DHCP mode)."
    )
    parser.add_argument("topology", type=Path,
                        help="Rendered topology file (the same file passed to kne create)")
    args = parser.parse_args()

    topology = args.topology.resolve()
    if not topology.is_file():
        print(f"ERROR: {topology} not found", file=sys.stderr)
        return 1

    log(f"Parsing topology: {topology}")
    namespace, nodes = parse_topology(topology)
    if not nodes:
        print("ERROR: No nodes found in topology", file=sys.stderr)
        return 1

    nodes = [n for n in nodes if is_sonic_node(n)]
    if not nodes:
        print("ERROR: No SONiC nodes found in topology", file=sys.stderr)
        return 1

    log(f"Topology: {namespace}, Nodes: {len(nodes)}")

    # Detect kind network
    log("Detecting kind network...")
    kind_gw = get_kind_gateway()
    kind_bridge = get_kind_bridge()
    log(f"  kne-control-plane IP : {kind_gw}")
    log(f"  kind bridge          : {kind_bridge}")

    # Add host routes (one per unique subnet)
    subnets_done: set[str] = set()
    for node in nodes:
        mgmt = derive_mgmt(int(node["topo_id"]), int(node["switch_id"]))
        subnet = str(mgmt["mgmt_subnet"])
        if subnet not in subnets_done:
            log(f"  Host route: {subnet} via {kind_gw} dev {kind_bridge}")
            add_host_route(subnet, kind_gw, kind_bridge)
            subnets_done.add(subnet)

    # Process each node
    log(f"\nConfiguring routes for {len(nodes)} nodes...\n")
    errors: list[str] = []

    for node in sorted(nodes, key=lambda n: (int(n["switch_id"]), str(n["name"]))):
        name = str(node["name"])
        topo_id = int(node["topo_id"])
        switch_id = int(node["switch_id"])
        mgmt = derive_mgmt(topo_id, switch_id)
        mgmt_ip = str(mgmt["mgmt_ip"])
        mgmt_gw = str(mgmt["mgmt_gw"])
        mgmt_subnet = str(mgmt["mgmt_subnet"])

        try:
            pod_ip = get_pod_ip(namespace, name)
            log(f"  [{name}] pod={pod_ip}  mgmt={mgmt_ip}")

            add_kind_route(mgmt_ip, pod_ip)
            update_pod_bridge(namespace, name, topo_id, mgmt_subnet, mgmt_gw)

        except Exception as exc:
            log(f"  [{name}] ERROR: {exc}")
            errors.append(name)

    # Summary
    log("")
    log("=== Summary ===")
    ok_count = len(nodes) - len(errors)
    log(f"  Routes configured: {ok_count}/{len(nodes)}")
    if errors:
        log(f"  Failed: {', '.join(errors)}")

    log("")
    log("=== Management IPs ===")
    log(f"  {'Node':<18} {'Mgmt IP':<18} {'SSH'}")
    log(f"  {'----':<18} {'-------':<18} {'---'}")
    for node in sorted(nodes, key=lambda n: (int(n["switch_id"]), str(n["name"]))):
        name = str(node["name"])
        if name in errors:
            continue
        mgmt = derive_mgmt(int(node["topo_id"]), int(node["switch_id"]))
        mgmt_ip = str(mgmt["mgmt_ip"])
        log(f"  {name:<18} {mgmt_ip:<18} ssh admin@{mgmt_ip}")
    log("")

    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
