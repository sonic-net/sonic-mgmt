"""
Shared helpers for BGP table-map (SELECTIVE_ROUTE_DOWNLOAD) tests.

Used by:
  - tests/bgp/test_anchor_prefix.py
"""

import json
import logging

import pytest
import yaml

from tests.common.helpers.assertions import pytest_require
from tests.common.helpers.bgp import get_db_cli_prefix, get_vtysh_cmd_for_asic
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


def bgpcfgd_is_running(duthost):
    """Return True if the bgpcfgd process inside the bgp docker is still alive (didn't crash)."""
    out = duthost.shell(
        "docker exec bgp supervisorctl status bgpcfgd", module_ignore_errors=True
    )["stdout"]
    return "RUNNING" in out


def is_route_in_rib(duthost, prefix, ip_version=4):
    """Return True if prefix is in BGP RIB on all frontend ASICs."""
    ip_ver = "ipv4" if ip_version == 4 else "ipv6"
    for asic_index in duthost.get_frontend_asic_ids():
        cmd = get_vtysh_cmd_for_asic(duthost, asic_index, "vtysh -c 'show bgp {} {}'".format(ip_ver, prefix))
        output = duthost.shell(cmd, module_ignore_errors=True)["stdout"]
        if "Network not in table" in output or not output.strip():
            return False
    return True


def is_route_in_fib(duthost, prefix):
    """Return True if prefix is installed in FIB (APPL_DB ROUTE_TABLE) on all frontend ASICs."""
    for asic_index in duthost.get_frontend_asic_ids():
        cmd = "{} APPL_DB hgetall \"ROUTE_TABLE:{}\"".format(get_db_cli_prefix(duthost, asic_index), prefix)
        output = duthost.shell(cmd, module_ignore_errors=True)["stdout"].strip().replace("'", '"')
        route_info = json.loads(output) if output else {}
        if not route_info or route_info.get("blackhole") == "true":
            return False
    return True


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
