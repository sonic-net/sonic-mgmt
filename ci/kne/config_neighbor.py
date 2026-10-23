#!/usr/bin/env python3
"""Rewrite /etc/sonic/config_db.json on a KNE neighbor. Runs on the switch as root.

  sudo python3 config_neighbor.py /tmp/kne-neigh.json
"""
import json
import sys

spec = json.load(open(sys.argv[1]))
path = "/etc/sonic/config_db.json"
cfg = json.load(open(path))

for table in ("INTERFACE", "BGP_NEIGHBOR", "DEVICE_NEIGHBOR", "DEVICE_NEIGHBOR_METADATA",
              "PORTCHANNEL", "PORTCHANNEL_MEMBER", "PORTCHANNEL_INTERFACE",
              "LOOPBACK_INTERFACE", "BGP_PEER_RANGE", "BGP_MONITORS"):
    cfg.pop(table, None)

meta = cfg.setdefault("DEVICE_METADATA", {}).setdefault("localhost", {})
meta["hostname"] = spec["hostname"]
meta["bgp_asn"] = str(spec["asn"])
meta["type"] = "LeafRouter"
meta["default_bgp_status"] = "up"

cfg["LOOPBACK_INTERFACE"] = {"Loopback0": {}, f"Loopback0|{spec['lo4']}": {}}
if spec.get("lo6"):
    cfg["LOOPBACK_INTERFACE"][f"Loopback0|{spec['lo6']}"] = {}

iface = spec["iface"]
addrs = [a for a in (spec.get("addr4"), spec.get("addr6")) if a]
members = spec.get("members") or []
if members:
    cfg["PORTCHANNEL"] = {iface: {"admin_status": "up", "min_links": "1", "mtu": "9100", "lacp_key": "auto"}}
    cfg["PORTCHANNEL_MEMBER"] = {f"{iface}|{m}": {} for m in members}
    cfg["PORTCHANNEL_INTERFACE"] = {iface: {}}
    for addr in addrs:
        cfg["PORTCHANNEL_INTERFACE"][f"{iface}|{addr}"] = {}
    for m in members:
        cfg.setdefault("PORT", {}).setdefault(m, {})["admin_status"] = "up"
else:
    cfg["INTERFACE"] = {iface: {}}
    for addr in addrs:
        cfg["INTERFACE"][f"{iface}|{addr}"] = {}
    cfg.setdefault("PORT", {}).setdefault(iface, {})["admin_status"] = "up"

local4 = spec["addr4"].split("/")[0]
peer = {"admin_status": "up", "asn": "65100", "holdtime": "10", "keepalive": "3",
        "name": spec["dut_name"], "nhopself": "0", "rrclient": "0"}
cfg["BGP_NEIGHBOR"] = {spec["peer4"]: dict(peer, local_addr=local4)}
if spec.get("addr6") and spec.get("peer6"):
    cfg["BGP_NEIGHBOR"][spec["peer6"]] = dict(peer, local_addr=spec["addr6"].split("/")[0])

cfg["DEVICE_NEIGHBOR"] = {members[0] if members else iface: {"name": spec["dut_name"], "port": iface}}
cfg["DEVICE_NEIGHBOR_METADATA"] = {
    spec["dut_name"]: {"hwsku": "Force10-S6000", "mgmt_addr": spec["dut_ip"], "type": "ToRRouter"},
}

json.dump(cfg, open(path, "w"), indent=2)
print(f"WROTE {path} for {spec['hostname']}")
