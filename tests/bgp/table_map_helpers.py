"""
Shared helpers for BGP table-map (SELECTIVE_ROUTE_DOWNLOAD) tests.

Used by:
  - tests/bgp/test_urh_anchor_prefix.py
"""

import json
import logging

import pytest
import yaml

from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.utilities import wait_until
from tests.bgp.bgp_helpers import get_exabgp_port

logger = logging.getLogger(__name__)

EXABGP_BASE_PORT = 5000
EXABGP_BASE_PORT_V6 = 6000
CONSTANTS_FILE = "/etc/sonic/constants.yml"


def get_anchor_community(duthost):
    """Read local_anchor_route_community from constants.yml on the DUT."""
    pytest_require(
        duthost.stat(path=CONSTANTS_FILE)["stat"]["exists"],
        "constants.yml not found on DUT, skipping test"
    )
    constants = yaml.safe_load(duthost.shell("cat {}".format(CONSTANTS_FILE))["stdout"])
    bgp_constants = constants.get("constants", {}).get("bgp", {})
    if "local_anchor_route_community" not in bgp_constants:
        pytest.skip("local_anchor_route_community not defined in constants.yml")
    return bgp_constants["local_anchor_route_community"]


def set_device_type(duthost, device_type, subtype=None):
    """Set DEVICE_METADATA type and subtype in CONFIG_DB."""
    duthost.shell("redis-cli -n 4 HSET 'DEVICE_METADATA|localhost' type {}".format(device_type))
    if subtype:
        duthost.shell("redis-cli -n 4 HSET 'DEVICE_METADATA|localhost' subtype {}".format(subtype))
    else:
        duthost.shell("redis-cli -n 4 HDEL 'DEVICE_METADATA|localhost' subtype",
                      module_ignore_errors=True)


def restart_bgp_and_wait(duthost):
    """Restart the BGP docker(s) so FRR templates are regenerated, then wait for sessions.

    'docker restart' bypasses systemd, so bgp.service's Restart=always drop-in
    fires its own follow-up restart on top of ours, silently consuming a slot
    in systemd's StartLimitBurst counter (default 3 per 20 min) on every call.
    A test module that calls this helper more than a few times per run can
    trip bgp.service into a spurious 'start-limit-hit' failure even though the
    container itself is healthy. Clearing the counter immediately beforehand
    keeps repeated calls from accumulating against that limit.
    """
    if duthost.is_multi_asic:
        for asic_index in duthost.get_frontend_asic_ids():
            duthost.shell("sudo systemctl reset-failed bgp{}".format(asic_index), module_ignore_errors=True)
            duthost.shell("docker restart bgp{}".format(asic_index))
    else:
        duthost.shell("sudo systemctl reset-failed bgp", module_ignore_errors=True)
        duthost.shell("docker restart bgp")
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
    bgp_neighbors = config_facts.get("BGP_NEIGHBOR", {})
    # 180s was cutting it close in practice: full-table T1 neighbors (thousands
    # of routes each) can take upward of 3-4 minutes to reach Established on
    # this KVM environment. On the native URH topology (6 confederation
    # neighbors carrying a real ~100k-entry full table each, observed with
    # load average ~4 on the KVM host) even the follow-up 300s budget can be
    # too tight, so bump to 480s to avoid flaking on genuine (slow-but-healthy)
    # convergence rather than a real failure.
    pytest_assert(
        wait_until(480, 10, 30, duthost.check_bgp_session_state, bgp_neighbors),
        "BGP sessions did not re-establish after BGP docker restart"
    )


def bgpcfgd_is_running(duthost):
    """Return True if the bgpcfgd process inside the bgp docker is still alive (didn't crash)."""
    out = duthost.shell(
        "docker exec bgp supervisorctl status bgpcfgd", module_ignore_errors=True
    )["stdout"]
    return "RUNNING" in out


def _bgp_docker_responsive(duthost):
    """Return True if the bgp docker is up and vtysh/bgpcfgd are responsive.

    Deliberately does NOT check neighbor session state. Some device types
    (e.g. LeafRouter) render a peer-group template that is fundamentally
    incompatible with this native URH confederation topology's real peers
    (drops the per-neighbor fast timers this topology's peers require), so
    sessions never re-establish under that device type on this testbed -
    that is expected/unrelated to what device-type-gating tests actually check.
    """
    out = duthost.shell("docker ps --filter name=bgp --format '{{.Status}}'",
                        module_ignore_errors=True)["stdout"]
    if "Up" not in out:
        return False
    vtysh_out = duthost.shell("docker exec bgp vtysh -c 'show version'", module_ignore_errors=True)
    return vtysh_out["rc"] == 0 and bgpcfgd_is_running(duthost)


def restart_bgp_and_wait_responsive(duthost):
    """Restart the bgp docker and wait only for it to come back up and be responsive.

    Use this instead of restart_bgp_and_wait() when the test intentionally
    applies a device type whose BGP sessions are not expected to (re)converge
    on this topology - e.g. a disallowed/filtered 'LeafRouter' probe. Session
    convergence is irrelevant there: the test only cares whether bgpcfgd
    renders config (e.g. table-map presence/absence) correctly, which only
    requires bgpd/bgpcfgd to be up and processing CONFIG_DB.
    """
    duthost.shell("sudo systemctl reset-failed bgp", module_ignore_errors=True)
    duthost.shell("docker restart bgp")
    pytest_assert(
        wait_until(60, 5, 10, _bgp_docker_responsive, duthost),
        "bgp docker did not come back up/responsive after restart"
    )


def is_route_in_rib(duthost, prefix, ip_version=4):
    """Return True if prefix is in BGP RIB on all frontend ASICs."""
    ip_ver = "ipv4" if ip_version == 4 else "ipv6"
    for asic_index in duthost.get_frontend_asic_ids():
        asic_ns = "-n asic{}".format(asic_index) if duthost.is_multi_asic else ""
        cmd = "vtysh {} -c 'show bgp {} {}'".format(asic_ns, ip_ver, prefix)
        output = duthost.shell(cmd, module_ignore_errors=True)["stdout"]
        if "Network not in table" in output or not output.strip():
            return False
    return True


def is_route_in_fib(duthost, prefix):
    """Return True if prefix is installed in FIB (APPL_DB ROUTE_TABLE) on all frontend ASICs."""
    for asic_index in duthost.get_frontend_asic_ids():
        asic_ns = "-n asic{}".format(asic_index) if duthost.is_multi_asic else ""
        cmd = "sonic-db-cli {} APPL_DB hgetall \"ROUTE_TABLE:{}\"".format(asic_ns, prefix)
        output = duthost.shell(cmd, module_ignore_errors=True)["stdout"].strip().replace("'", '"')
        route_info = json.loads(output) if output else {}
        if not route_info or route_info.get("blackhole") == "true":
            return False
    return True


def vtysh(duthost, *commands):
    """Run a sequence of vtysh commands inside 'configure terminal' on the BGP container."""
    cmd_args = " ".join(["-c '{}'".format(c) for c in ["configure terminal"] + list(commands)])
    duthost.shell("docker exec bgp vtysh {}".format(cmd_args))


def get_bgp_asn(duthost):
    """Return the DUT's BGP ASN from running config."""
    output = duthost.shell("docker exec bgp vtysh -c 'show running-config' | grep 'router bgp'")["stdout"]
    asn = None
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("router bgp"):
            asn = line.split()[2]
            break
    pytest_assert(asn is not None, "Could not determine BGP ASN from running config")
    return asn


def apply_table_map(duthost, asn, rmap_name, ip_version=4):
    """Apply table-map to BGP address-family via vtysh."""
    af = "address-family ipv4 unicast" if ip_version == 4 else "address-family ipv6 unicast"
    vtysh(duthost, "router bgp {}".format(asn), af, "table-map {}".format(rmap_name))


def remove_table_map(duthost, asn, rmap_name, ip_version=4):
    """Remove table-map from BGP address-family via vtysh."""
    af = "address-family ipv4 unicast" if ip_version == 4 else "address-family ipv6 unicast"
    vtysh(duthost, "router bgp {}".format(asn), af, "no table-map {}".format(rmap_name))


@pytest.fixture(scope="module")
def exabgp_setup(duthosts, nbrhosts, tbinfo, enum_dut_hostname):
    """Get PTF IP, ExaBGP ports, and next-hop IPs for route injection."""
    duthost = duthosts[enum_dut_hostname]
    ptf_ip = tbinfo["ptf_ip"]

    exabgp_ports, _ = get_exabgp_port(duthost, nbrhosts, tbinfo, EXABGP_BASE_PORT, is_random=True)
    exabgp_ports_v6, _ = get_exabgp_port(duthost, nbrhosts, tbinfo, EXABGP_BASE_PORT_V6, is_random=True)

    cfg_props = tbinfo["topo"]["properties"]["configuration_properties"]["common"]
    nhipv4 = cfg_props.get("nhipv4", "10.10.246.254")
    nhipv6 = cfg_props.get("nhipv6", "fc0a::ff")

    return {
        "ptf_ip": ptf_ip,
        "exabgp_port": exabgp_ports[0],
        "exabgp_port_v6": exabgp_ports_v6[0],
        "nhipv4": nhipv4,
        "nhipv6": nhipv6,
    }
