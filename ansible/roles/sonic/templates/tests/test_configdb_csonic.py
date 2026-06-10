"""Unit tests for the cSONiC CONFIG_DB Jinja2 template (configdb-csonic.j2).

These tests render the template with synthetic neighbor configurations and
assert on the produced CONFIG_DB JSON. They exercise the logic the template
gets wrong most easily and that has no other coverage:

  * the output is always valid JSON (comma/joiner handling),
  * exabgp next-hop (props.nhipv4 / props.nhipv6) entries are emitted only when
    defined and non-empty, and never leave a dangling comma when absent,
  * the backplane port is placed at Ethernet{K+1} past the front-panel links
    (so multi-link LAG neighbors do not collide with a second front-panel port),
  * routed Ethernet interfaces land in INTERFACE while LAG members land in
    PORTCHANNEL_MEMBER, and
  * the synthetic VS lane numbering matches the SONiC-VM lanemap.

The test depends only on jinja2 so it runs standalone:

    python3 ansible/roles/sonic/templates/tests/test_configdb_csonic.py

or under pytest:

    pytest ansible/roles/sonic/templates/tests/test_configdb_csonic.py
"""
import json
import os

from jinja2 import Environment, FileSystemLoader

TEMPLATES_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE_NAME = "configdb-csonic.j2"


def _base_host():
    """A neighbor with two front-panel links: Ethernet1 is a LAG member of
    Port-Channel1, Ethernet2 is a routed interface. A backplane is present."""
    return {
        "interfaces": {
            "Loopback0": {"ipv4": "100.1.0.29/32", "ipv6": "2064:100::1d/128"},
            "Ethernet1": {"lacp": 1},
            "Ethernet2": {"ipv4": "10.0.0.5/31", "ipv6": "fc00::5/126"},
            "Port-Channel1": {"ipv4": "10.0.0.1/31", "ipv6": "fc00::1/126"},
        },
        "bgp": {
            "asn": 64001,
            "peers": {64600: ["10.0.0.0", "fc00::0"]},
        },
        "bp_interface": {"ipv4": "10.10.246.29/24", "ipv6": "fc0a::1d/64"},
    }


def _render(host, props):
    env = Environment(
        loader=FileSystemLoader(TEMPLATES_DIR),
        trim_blocks=False,
        lstrip_blocks=False,
    )
    template = env.get_template(TEMPLATE_NAME)
    hostname = "ARISTA01T1"
    return template.render(
        configuration={hostname: host},
        hostname=hostname,
        props=props,
    )


def _render_json(host, props):
    rendered = _render(host, props)
    # A malformed template (e.g. trailing comma) makes this raise.
    return json.loads(rendered)


def test_renders_valid_json_with_nexthops():
    cfg = _render_json(_base_host(), {"swrole": "leaf",
                                      "nhipv4": "10.10.246.254",
                                      "nhipv6": "fc0a::ff"})
    assert "BGP_NEIGHBOR" in cfg
    # bgp peers + both exabgp next hops are present.
    assert "10.0.0.0" in cfg["BGP_NEIGHBOR"]
    assert "10.10.246.254" in cfg["BGP_NEIGHBOR"]
    assert "fc0a::ff" in cfg["BGP_NEIGHBOR"]


def test_valid_json_without_nexthops():
    """Topologies that do not define nhipv4/nhipv6 must still render valid JSON
    (no undefined-variable blow-up, no dangling comma)."""
    cfg = _render_json(_base_host(), {"swrole": "leaf"})
    nbrs = cfg["BGP_NEIGHBOR"]
    # Only the real bgp peers remain; no empty/None next-hop key sneaks in.
    assert set(nbrs.keys()) == {"10.0.0.0", "fc00::0"}
    assert "" not in nbrs
    assert "None" not in nbrs


def test_empty_nexthop_is_skipped():
    """An empty-string next hop must be treated like an absent one."""
    cfg = _render_json(_base_host(), {"swrole": "leaf",
                                      "nhipv4": "",
                                      "nhipv6": None})
    assert set(cfg["BGP_NEIGHBOR"].keys()) == {"10.0.0.0", "fc00::0"}


def test_only_v4_nexthop():
    cfg = _render_json(_base_host(), {"swrole": "leaf",
                                      "nhipv4": "10.10.246.254"})
    nbrs = cfg["BGP_NEIGHBOR"]
    assert "10.10.246.254" in nbrs
    assert all(":" not in k or k in ("fc00::0",) for k in nbrs)
    assert set(nbrs.keys()) == {"10.0.0.0", "fc00::0", "10.10.246.254"}


def test_no_bgp_peers_only_nexthops():
    """No real peers, only exabgp next hops: still valid JSON, no leading comma."""
    host = _base_host()
    host["bgp"]["peers"] = {}
    cfg = _render_json(host, {"swrole": "leaf",
                              "nhipv4": "10.10.246.254",
                              "nhipv6": "fc0a::ff"})
    assert set(cfg["BGP_NEIGHBOR"].keys()) == {"10.10.246.254", "fc0a::ff"}


def test_backplane_placed_after_front_panel_links():
    """With K=2 front-panel Ethernet ports, the backplane is Ethernet3."""
    cfg = _render_json(_base_host(), {"swrole": "leaf",
                                      "nhipv4": "10.10.246.254",
                                      "nhipv6": "fc0a::ff"})
    assert "Ethernet3" in cfg["PORT"]
    assert "Ethernet3" in cfg["INTERFACE"]
    assert "Ethernet3|10.10.246.29/24" in cfg["INTERFACE"]
    # Single-link neighbor keeps the backplane at Ethernet2.
    single = _base_host()
    del single["interfaces"]["Ethernet2"]
    del single["interfaces"]["Port-Channel1"]
    single["interfaces"]["Ethernet1"] = {"ipv4": "10.0.0.5/31"}
    cfg1 = _render_json(single, {"swrole": "leaf"})
    assert "Ethernet2" in cfg1["PORT"]


def test_routed_vs_lag_member_split():
    cfg = _render_json(_base_host(), {"swrole": "leaf"})
    # Routed Ethernet2 gets an INTERFACE entry with its IPs.
    assert "Ethernet2" in cfg["INTERFACE"]
    assert "Ethernet2|10.0.0.5/31" in cfg["INTERFACE"]
    # LAG member Ethernet1 is a PORTCHANNEL_MEMBER, not a routed INTERFACE.
    assert "PortChannel1|Ethernet1" in cfg["PORTCHANNEL_MEMBER"]
    assert "Ethernet1" not in cfg["INTERFACE"]


def test_port_lane_numbering():
    cfg = _render_json(_base_host(), {"swrole": "leaf"})
    # Ethernet2 -> (2-1)*4 + 25 = 29 -> "29,30,31,32".
    assert cfg["PORT"]["Ethernet2"]["lanes"] == "29,30,31,32"
    # Ethernet1 -> (1-1)*4 + 25 = 25 -> "25,26,27,28".
    assert cfg["PORT"]["Ethernet1"]["lanes"] == "25,26,27,28"


def test_no_backplane_when_absent():
    host = _base_host()
    del host["bp_interface"]
    cfg = _render_json(host, {"swrole": "leaf"})
    assert "Ethernet3" not in cfg["PORT"]


def _run_standalone():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    failures = 0
    for t in tests:
        try:
            t()
            print("PASS", t.__name__)
        except Exception as exc:  # noqa: BLE001
            failures += 1
            print("FAIL", t.__name__, "->", repr(exc))
    print("\n{} passed, {} failed".format(len(tests) - failures, failures))
    return failures


if __name__ == "__main__":
    import sys
    sys.exit(1 if _run_standalone() else 0)
