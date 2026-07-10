"""Unit tests for the T0-leaf CONFIG_DB Jinja2 template (configdb-t0-leaf.j2).

These render the template with a synthetic T0-leaf neighbor configuration and
assert on the produced CONFIG_DB JSON. They lock in the fix that keeps the
exabgp route-injector out of the shared PEER_V4/V6 peer-group:

  * the output is always valid JSON (comma/joiner handling),
  * the exabgp injector (props.nhipv4 / props.nhipv6) is emitted in
    BGP_INTERNAL_NEIGHBOR (iBGP, own ASN) and NOT in BGP_NEIGHBOR, so bgpcfgd
    renders it into the separate INTERNAL_PEER_V4/V6 group and PEER_V4/V6 stay
    uniformly eBGP (avoids FRR "Peer-group members must be all internal or all
    external" -> 0 routes advertised),
  * the real DUT peers remain in BGP_NEIGHBOR,
  * a synthetic Loopback4096 (required by bgpcfgd's internal peer manager) is
    added to LOOPBACK_INTERFACE, reusing Loopback0 addresses.

Runs standalone (jinja2 only):

    python3 ansible/roles/sonic/templates/tests/test_configdb_t0_leaf.py

or under pytest.
"""
import json
import os

from jinja2 import Environment, FileSystemLoader

TEMPLATES_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE_NAME = "configdb-t0-leaf.j2"


def _host():
    return {
        "bgp": {"asn": "64600", "peers": {"65100": ["10.0.0.58", "FC00::75"]}},
        "interfaces": {
            "Loopback0": {"ipv4": "100.1.0.29/32", "ipv6": "2064:100::1d/128"},
            "Ethernet1": {"ipv4": "10.0.0.59/31"},
        },
        "bp_interface": {"ipv4": "10.1.0.32/24", "ipv6": "fc00::1/64"},
    }


def _render(host=None, props=None):
    host = host or _host()
    props = props or {"swrole": "leaf", "nhipv4": "10.10.246.254", "nhipv6": "fc0a::ff"}
    env = Environment(loader=FileSystemLoader(TEMPLATES_DIR))
    ctx = {
        "configuration": {"n": host},
        "hostname": "n",
        "props": props,
        "topo": "t0",
        "snmp_rocommunity": "public",
        "configuration_properties": {"common": {}},
    }
    return env.get_template(TEMPLATE_NAME).render(**ctx)


def test_output_is_valid_json():
    json.loads(_render())


def test_injector_in_internal_neighbor_not_bgp_neighbor():
    d = json.loads(_render())
    internal = d.get("BGP_INTERNAL_NEIGHBOR", {})
    neighbor = d.get("BGP_NEIGHBOR", {})
    # injector v4/v6 live in BGP_INTERNAL_NEIGHBOR ...
    assert "10.10.246.254" in internal, internal
    assert "fc0a::ff" in internal, internal
    # ... and NOT in BGP_NEIGHBOR
    assert "10.10.246.254" not in neighbor, neighbor
    assert "fc0a::ff" not in neighbor, neighbor
    # injector is iBGP (own ASN)
    assert internal["10.10.246.254"]["asn"] == "64600"


def test_dut_peers_remain_in_bgp_neighbor():
    d = json.loads(_render())
    neighbor = d.get("BGP_NEIGHBOR", {})
    assert "10.0.0.58" in neighbor, neighbor
    assert "FC00::75" in neighbor, neighbor


def test_loopback4096_present():
    d = json.loads(_render())
    lo = d.get("LOOPBACK_INTERFACE", {})
    assert "Loopback4096" in lo, lo
    assert "Loopback4096|100.1.0.29/32" in lo, lo


def test_injector_absent_when_undefined():
    # when no exabgp next-hop is provided, BGP_INTERNAL_NEIGHBOR is empty and JSON stays valid
    d = json.loads(_render(props={"swrole": "leaf"}))
    assert d.get("BGP_INTERNAL_NEIGHBOR", {}) == {}


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok:", name)
    print("ALL PASSED")
