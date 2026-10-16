#!/usr/bin/env python3
"""Configure IP addresses and BGP on the T1 neighbor SONiC VMs.

Usage:
    python3 configure_neighbors.py <rendered-topology-file>

The topology file must be the rendered file passed to `kne create`. Each
neighbor's management IP is derived from it (172.31.<TOPO_ID>.<SWITCH_ID>,
using the pod named in neighbors.json), so the script works with any TOPO_ID.
Interface, loopback, and BGP data come from neighbors.json next to this script.
"""
import argparse
import importlib.util
import json
import subprocess
import sys
import textwrap
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
ROUTES_SCRIPT = SCRIPT_DIR.parents[1] / "setup_mgmt_routes.py"


def load_routes_helpers():
    """Reuse the topology parser and address rule from setup_mgmt_routes.py."""
    if not ROUTES_SCRIPT.is_file():
        sys.exit(f"ERROR: {ROUTES_SCRIPT} not found")
    spec = importlib.util.spec_from_file_location("setup_mgmt_routes", ROUTES_SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


parser = argparse.ArgumentParser(description="Configure IP addresses and BGP on the T1 neighbors.")
parser.add_argument("topology", type=Path,
                    help="Rendered topology file (the same file passed to kne create)")
args = parser.parse_args()
if not args.topology.is_file():
    sys.exit(f"ERROR: {args.topology} not found")

routes = load_routes_helpers()
_, nodes = routes.parse_topology(args.topology)
mgmt_by_pod = {
    n["name"]: routes.derive_mgmt(n["topo_id"], n["switch_id"])["mgmt_ip"] for n in nodes
}

neigh = json.loads((SCRIPT_DIR / "neighbors.json").read_text())

missing = [n["pod"] for n in neigh if n["pod"] not in mgmt_by_pod]
if missing:
    sys.exit(f"ERROR: neighbor pods not found in {args.topology}: {', '.join(missing)}")


def ssh(ip, script):
    cmd = [
        "docker", "exec", "-i", "sonic-mgmt",
        "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=30",
        f"admin@{ip}", "bash", "-s",
    ]
    return subprocess.run(cmd, input=script, text=True, capture_output=True)


ok = fail = 0
for n in neigh:
    ip = mgmt_by_pod[n["pod"]]
    name = n["name"]
    asn = n["asn"]
    eth_v4, eth_v6 = n["eth_v4"], n["eth_v6"]
    lo_v4, lo_v6 = n["lo_v4"], n["lo_v6"]
    peer_v4, peer_v6 = n["peer_v4"], n["peer_v6"]
    rid = lo_v4.split("/")[0]

    script = textwrap.dedent(f"""
    set +e
    # wipe common default IPs on all Ethernet ports
    for i in $(seq 0 4 124); do
      sudo config interface ip remove Ethernet$i 10.0.0.$((i/2))/31 2>/dev/null
      sudo config interface ip remove Ethernet$i 10.0.0.$((i/2+1))/31 2>/dev/null
    done
    # remove whatever is on Ethernet0 / Loopback0 now
    show ip interfaces 2>/dev/null | awk '/^Ethernet0 /{{print $2}}' | while read a; do
      [ -n "$a" ] && sudo config interface ip remove Ethernet0 "$a"
    done
    show ip interfaces 2>/dev/null | awk '/^Loopback0 /{{print $2}}' | while read a; do
      [ -n "$a" ] && sudo config interface ip remove Loopback0 "$a"
    done
    sudo config interface ip remove Loopback0 10.1.0.1/32 2>/dev/null

    sudo config interface ip add Ethernet0 {eth_v4}
    sudo config interface ip add Ethernet0 {eth_v6}
    sudo config interface ip add Loopback0 {lo_v4}
    sudo config interface ip add Loopback0 {lo_v6}

    sudo vtysh <<'EOF'
configure terminal
router bgp {asn}
 bgp router-id {rid}
 no bgp ebgp-requires-policy
 no bgp network import-check
 neighbor {peer_v4} remote-as 65100
 neighbor {peer_v6} remote-as 65100
 address-family ipv4 unicast
  neighbor {peer_v4} activate
  network {lo_v4}
 exit-address-family
 address-family ipv6 unicast
  neighbor {peer_v6} activate
  network {lo_v6}
 exit-address-family
end
write memory
EOF
    sudo config save -y
    echo CONFIGURED_{name}
    """)

    r = ssh(ip, script)
    out = r.stdout + r.stderr
    if r.returncode == 0 and f"CONFIGURED_{name}" in out:
        print(f"OK {name} {ip}", flush=True)
        ok += 1
    else:
        print(f"FAIL {name} {ip} rc={r.returncode}", flush=True)
        print(out[-800:], flush=True)
        fail += 1

print(f"DONE ok={ok} fail={fail}", flush=True)
