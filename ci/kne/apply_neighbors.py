#!/usr/bin/env python3
"""Push neighbor config_db rewrites for a t1 or t1-lag slot. Runs on the Kind host."""
import json
import os
import subprocess
import sys
import tempfile

topo = os.environ["TOPO"]
slot = os.environ["SLOT"]
base = os.environ["BASE_PREFIX"]          # 172.31.101.
new = f"172.31.{slot}."
container = os.environ["CI_CONTAINER"]
dut_name = os.environ["DUT_NAME"]
dut_ip = os.environ["DUT_IP"]
password = os.environ["SONIC_PASS"]
here = os.path.dirname(os.path.abspath(__file__))

rows = json.load(open(os.path.join(here, "topos", f"{topo}.neighbors.json")))


def spec_for(n):
    mgmt = n["mgmt"].replace(base, new)
    if topo == "t1":
        return mgmt, {
            "hostname": n["name"], "asn": n["asn"],
            "lo4": n["lo_v4"], "lo6": n["lo_v6"],
            "iface": "Ethernet0", "members": [],
            "addr4": n["eth_v4"], "addr6": n["eth_v6"],
            "peer4": n["peer_v4"], "peer6": n["peer_v6"],
            "dut_name": dut_name, "dut_ip": dut_ip,
        }
    members = n.get("lacp_members") or []
    peer6 = n.get("peer_v6") or ""
    return mgmt, {
        "hostname": n["name"], "asn": n["asn"],
        "lo4": n["loopback"]["ipv4"], "lo6": n["loopback"].get("ipv6", ""),
        "iface": "PortChannel1" if members else "Ethernet0",
        "members": members,
        "addr4": f"{n['peer_v4']}/31",
        "addr6": f"{peer6}/126" if peer6 else "",
        "peer4": n["dut_peer_v4"], "peer6": n.get("dut_peer_v6", ""),
        "dut_name": dut_name, "dut_ip": dut_ip,
    }


def run(cmd, **kw):
    r = subprocess.run(cmd, text=True, capture_output=True, **kw)
    if r.returncode != 0:
        sys.stderr.write(r.stdout[-500:] + r.stderr[-500:])
        raise SystemExit(f"failed: {' '.join(cmd[:6])}")
    return r.stdout


ssh_opts = ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR"]
script = os.path.join(here, "config_neighbor.py")
run(["docker", "cp", script, f"{container}:/tmp/config_neighbor.py"])

for n in rows:
    mgmt, spec = spec_for(n)
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(spec, fh)
        local = fh.name
    run(["docker", "cp", local, f"{container}:/tmp/kne-neigh.json"])
    os.unlink(local)
    run(["docker", "exec", container, "sshpass", "-p", password, "scp", *ssh_opts,
         "/tmp/config_neighbor.py", "/tmp/kne-neigh.json", f"admin@{mgmt}:/tmp/"])
    out = run(["docker", "exec", container, "sshpass", "-p", password, "ssh", *ssh_opts,
               f"admin@{mgmt}",
               "sudo python3 /tmp/config_neighbor.py /tmp/kne-neigh.json "
               "&& (sudo config reload -y -f >/dev/null 2>&1 &) && echo RELOAD_KICKED"])
    if "RELOAD_KICKED" not in out and "WROTE" not in out:
        raise SystemExit(f"{n['name']} did not accept config")
    print(f"configured {n['name']} {mgmt}", flush=True)

print(f"NEIGHBORS_CONFIGURED {len(rows)}", flush=True)
