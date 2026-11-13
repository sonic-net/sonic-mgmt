#!/usr/bin/env python3
"""Rewrite a SONiC VS neighbor's config_db.json so it acts as a T1 for the KNE T0 topology.

Runs ON the T1 (as root). Called by ci/kne/config_t1.sh.
  sudo python3 t1_configdb.py <hostname> <lo4> <lo6> <pc4> <pc6> <peer4> <peer6> <dut_name> <dut_mgmt_ip>
"""
import json
import sys

hostname, lo4, lo6, pc4, pc6, peer4, peer6, dut_name, dut_mgmt = sys.argv[1:10]
path = "/etc/sonic/config_db.json"
cfg = json.load(open(path))

# Drop the community default fabric: 32 point-to-point interfaces + 32 BGP peers.
for table in ("INTERFACE", "BGP_NEIGHBOR", "DEVICE_NEIGHBOR", "DEVICE_NEIGHBOR_METADATA",
              "PORTCHANNEL", "PORTCHANNEL_MEMBER", "PORTCHANNEL_INTERFACE",
              "LOOPBACK_INTERFACE", "BGP_PEER_RANGE", "BGP_MONITORS"):
    cfg.pop(table, None)

meta = cfg.setdefault("DEVICE_METADATA", {}).setdefault("localhost", {})
meta["hostname"] = hostname
meta["bgp_asn"] = "64600"
meta["type"] = "LeafRouter"
meta["default_bgp_status"] = "up"

cfg["LOOPBACK_INTERFACE"] = {
    "Loopback0": {},
    f"Loopback0|{lo4}": {},
    f"Loopback0|{lo6}": {},
}
cfg["PORTCHANNEL"] = {
    "PortChannel1": {"admin_status": "up", "min_links": "1", "mtu": "9100", "lacp_key": "auto"},
}
cfg["PORTCHANNEL_MEMBER"] = {"PortChannel1|Ethernet0": {}}
cfg["PORTCHANNEL_INTERFACE"] = {
    "PortChannel1": {},
    f"PortChannel1|{pc4}": {},
    f"PortChannel1|{pc6}": {},
}
peer_common = {"admin_status": "up", "asn": "65100", "holdtime": "10", "keepalive": "3",
               "name": dut_name, "nhopself": "0", "rrclient": "0"}
cfg["BGP_NEIGHBOR"] = {
    peer4: dict(peer_common, local_addr=pc4.split("/")[0]),
    peer6: dict(peer_common, local_addr=pc6.split("/")[0]),
}
cfg["DEVICE_NEIGHBOR"] = {"Ethernet0": {"name": dut_name, "port": "PortChannel1"}}
cfg["DEVICE_NEIGHBOR_METADATA"] = {
    dut_name: {"hwsku": "Force10-S6000", "lo_addr": "10.1.0.32/32", "mgmt_addr": dut_mgmt, "type": "ToRRouter"},
}
cfg.setdefault("PORT", {}).setdefault("Ethernet0", {})["admin_status"] = "up"

json.dump(cfg, open(path, "w"), indent=2)
print(f"WROTE {path} for {hostname}")
