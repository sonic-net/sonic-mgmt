"""
test_vxlan_sport_range.py — VXLAN Source-Port Range, Hashing & Distribution

This test configures a VXLAN tunnel on the DUT, programs a source-port range
via SWITCH_TABLE (vxlan_sport / vxlan_mask), then invokes a PTF test that
sends 1000 distinct TCP flows.  The PTF side verifies:

  1. Every encapsulated packet's outer UDP source port is within the range.
  2. The same inner 5-tuple always hashes to the same outer source port.
  3. Traffic is distributed evenly across the range (≤ 10 % deviation).

The DUT setup mirrors test_scale_ecmp.py: one VNET, one tunnel, one prefix
with two endpoints.

CLI options (from conftest.py, already registered):
  --udp_src_port       Base port   (default here: 32768)
  --udp_src_port_mask  Mask bits   (default here: 4  →  16-port range)
"""

import json
import time
import sys
import traceback
import pytest
import logging

from tests.common.config_reload import config_reload
from tests.ptf_runner import ptf_runner
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory     # noqa:F401
from tests.common.vxlan_ecmp_utils import Ecmp_Utils
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.vxlan.vnet_constants import DUT_VXLAN_RANGE_JSON

logger = logging.getLogger(__name__)
ecmp_utils = Ecmp_Utils()

# todo navdhaj: does this need to be only on physical and cisco-8000?
pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.device_type('physical'),
    pytest.mark.asic('cisco-8000'),
]

VNET_NAME = "Vnet1"
TUNNEL_NAME = "tunnel_v4"
VNI = 10000
PREFIX = "150.0.3.1/32"
ENDPOINTS = ["100.0.1.10", "100.0.2.10"]

# Defaults intentionally different from production values (64128 / 7).
DEFAULT_SOURCE_PORT = 32768
DEFAULT_SOURCE_PORT_MASK = 4

NUM_FLOWS = 1000


# ---------- Utility helpers (same as test_scale_ecmp.py) ----------

def get_loopback_ip(cfg_facts):
    """Return the IPv4 address of Loopback0 from the DUT config."""
    for key in cfg_facts.get("LOOPBACK_INTERFACE", {}):
        if key.startswith("Loopback0|") and "." in key:
            return key.split("|")[1].split("/")[0]
    pytest.fail("Cannot find IPv4 Loopback0 address in LOOPBACK_INTERFACE")


def apply_chunk(duthost, payload, name):
    """Write a JSON payload to /tmp/<name>.json and load it into CONFIG_DB."""
    content = json.dumps(payload, indent=2)
    dest = f"/tmp/{name}.json"
    duthost.copy(content=content, dest=dest)
    duthost.shell(f"sonic-cfggen -j {dest} --write-to-db")


def get_available_vlan_id_and_ports(cfg_facts, num_ports_needed):
    """Find a VLAN with enough 'admin up' ports for the test."""
    port_status = cfg_facts["PORT"]
    vlan_id = -1
    available_ports = []
    pytest_require("VLAN_MEMBER" in cfg_facts, "Can't get vlan member")
    for vlan_name, members in list(cfg_facts["VLAN_MEMBER"].items()):
        if len(members) < num_ports_needed:
            continue
        possible_ports = []
        for vlan_member in members:
            if port_status[vlan_member].get("admin_status", "down") != "up":
                continue
            possible_ports.append(vlan_member)
            if len(possible_ports) == num_ports_needed:
                available_ports = possible_ports[:]
                vlan_id = int(''.join([i for i in vlan_name if i.isdigit()]))
                break
        if vlan_id != -1:
            break
    logger.debug(f"Vlan {vlan_id} has available ports: {available_ports}")
    return available_ports


# ---------- Source-port range configuration ----------

def configure_vxlan_source_port_range(duthost, vxlan_port, source_port,
                                      source_port_mask):
    """
    Program the VXLAN switch config (UDP port) and source-port range into the
    DUT via a single SWITCH_TABLE SET.

    The range is [source_port, source_port | (0xFF >> (8 - mask))].
    For example source_port=32768, mask=4  →  range 32768–32783 (16 ports).

    All SWITCH_TABLE fields are applied in one swssconfig SET so that
    orchagent processes them together.
    """
    # Validate: the lower 'mask' bits of the base port must all be zero.
    pytest_assert(
        source_port & (0xFF >> (8 - source_port_mask)) == 0,
        f"Mask {source_port_mask} is not valid for source port base "
        f"{source_port} — lower {source_port_mask} bits must be zero"
    )

    switch_config = [{
        "SWITCH_TABLE:switch": {
            "vxlan_port": str(vxlan_port),
            "vxlan_router_mac": "aa:bb:cc:dd:ee:ff",
            "vxlan_sport": str(source_port),
            "vxlan_mask": str(source_port_mask),
        },
        "OP": "SET",
    }]

    logger.info(f"Configuring VXLAN switch: port={vxlan_port}, "
                f"sport base={source_port}, mask={source_port_mask}")
    duthost.copy(content=json.dumps(switch_config, indent=4),
                 dest=DUT_VXLAN_RANGE_JSON)
    duthost.shell(
        f"docker cp {DUT_VXLAN_RANGE_JSON} swss:/vxlan_range.json")
    duthost.shell(
        'docker exec swss sh -c "swssconfig /vxlan_range.json"')
    time.sleep(3)


# ---------- DUT setup ----------

def vxlan_setup_with_sport_range(duthost, ptfhost, tbinfo, cfg_facts,
                                  config_facts, dut_indx, vxlan_port,
                                  source_port, source_port_mask):
    """
    End-to-end DUT setup:
      1. Pick an ingress port, remove it from its VLAN.
      2. Create a VXLAN tunnel sourced from Loopback0.
      3. Create a VNET bound to that tunnel.
      4. Bind an interface to the VNET, assign an IP, and bring up the PTF side.
      5. Program a route with two endpoints.
      6. Configure the VXLAN UDP port.
      7. Configure the source-port range.
    """
    ports = get_available_vlan_id_and_ports(config_facts, 1)
    pytest_assert(ports and len(ports) >= 1, "Not enough ports for VNET setup")

    port_indexes = config_facts["port_index_map"]
    host_interfaces = tbinfo["topo"]["ptf_map"][str(dut_indx)]
    ptf_ports_available_in_topo = {host_interfaces[k]: f"eth{k}" for k in host_interfaces}

    ecmp_utils.Constants["KEEP_TEMP_FILES"] = False
    ecmp_utils.Constants["DEBUG"] = True

    ingress_if = ports[0]
    logger.info(f"Selected ingress interface: {ingress_if}")
    duthost.shell(f"config vlan member del all {ingress_if} || true")

    dut_vtep = get_loopback_ip(cfg_facts)
    
    # --- VXLAN UDP port + source-port range (single SWITCH_TABLE SET) ---
    configure_vxlan_source_port_range(duthost, vxlan_port, source_port,
                                      source_port_mask)

    # Verify the config landed in APPDB
    switch_table = duthost.shell(
        'redis-cli -n 0 hgetall "SWITCH_TABLE:switch"')["stdout"]
    logger.info(f"SWITCH_TABLE:switch after config:\n{switch_table}")

    # --- VXLAN tunnel + VNET ---
    apply_chunk(duthost,
                {"VXLAN_TUNNEL": {TUNNEL_NAME: {"src_ip": dut_vtep}}},
                "vxlan_tunnel")
    apply_chunk(duthost,
                {"VNET": {VNET_NAME: {"vni": str(VNI),
                                       "vxlan_tunnel": TUNNEL_NAME}}},
                "vnet")

    # --- Bind interface to VNET and configure IPs ---
    ptf_port_index = port_indexes[ingress_if]
    port_name = ptf_ports_available_in_topo[ptf_port_index]

    dut_ip = "201.0.1.1"
    apply_chunk(
        duthost,
        {"INTERFACE": {ingress_if: {"vnet_name": VNET_NAME},
                        f"{ingress_if}|{dut_ip}/24": {}}},
        "intf_bind",
    )

    ptf_ip = "201.0.1.101"
    ptfhost.shell(f"ip addr flush dev {port_name}")
    ptfhost.shell(f"ip addr add {ptf_ip}/24 dev {port_name}")
    ptfhost.shell(f"ip link set {port_name} up")

    # --- Route with endpoints ---
    apply_chunk(
        duthost,
        {"VNET_ROUTE_TUNNEL": {
            f"{VNET_NAME}|{PREFIX}": {
                "endpoint": ",".join(ENDPOINTS),
                "vni": str(VNI),
            }}},
        "route_tunnel",
    )
    time.sleep(5)

    return {
        "dut_vtep": dut_vtep,
        "ptf_src_ip": ptf_ip,
        "dst_ip": PREFIX.split("/")[0],
        "ptf_ingress_port": ptf_port_index,
        "router_mac": duthost.facts["router_mac"],
        "vxlan_port": vxlan_port,
        "vni": VNI,
        "source_port": source_port,
        "source_port_mask": source_port_mask,
        "num_flows": NUM_FLOWS,
    }


# ---------- Fixture ----------

@pytest.fixture(scope="module", autouse=True)
def sport_range_setup_teardown(
    duthosts,
    rand_one_dut_hostname,
    ptfhost,
    tbinfo,
    request,
):
    """
    Module-level fixture: configures the DUT with a VXLAN tunnel, VNET,
    route, and source-port range.  Tears down via config_reload.
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Read CLI options; fall back to safe defaults.
    vxlan_port = request.config.option.vxlan_port # default is 4789 if not specified
    # todo navdhaj: add that here as well instead of as default in fn
    source_port = request.config.option.udp_src_port or DEFAULT_SOURCE_PORT
    source_port_mask = request.config.option.udp_src_port_mask or DEFAULT_SOURCE_PORT_MASK

    try:
        cfg_facts = json.loads(
            duthost.shell("sonic-cfggen -d --print-data")["stdout"])
        config_facts = duthost.config_facts(
            host=duthost.hostname, source="running")["ansible_facts"]
        # todo navdhaj: do we need both cfg_facts and config_facts? or are they totally diff?
        dut_indx = tbinfo["duts_map"][duthost.hostname]

        setup_params = vxlan_setup_with_sport_range(
            duthost, ptfhost, tbinfo, cfg_facts, config_facts,
            dut_indx, vxlan_port, source_port, source_port_mask,
        )
    except Exception as e:
        logger.error(f"Exception raised in setup: {repr(e)}")
        logger.error(json.dumps(
            traceback.format_exception(*sys.exc_info()), indent=2))
        config_reload(duthost, safe_reload=True, yang_validate=False)
        pytest.fail("VXLAN source-port range test setup failed")

    yield setup_params, duthost, ptfhost

    config_reload(duthost, safe_reload=True, yang_validate=False)


# ---------- PTF runner helper ----------

def run_sport_ptf_test(ptfhost, params):
    """
    Copy test parameters as JSON to the PTF host and invoke the
    VxlanSportRangeTest PTF class.
    """
    endpoints_file = "/tmp/ptf_sport_endpoints.json"
    ptfhost.copy(content=json.dumps(ENDPOINTS), dest=endpoints_file)

    ptf_params = params.copy()
    ptf_params["endpoints_file"] = endpoints_file

    params_path = "/tmp/ptf_sport_params.json"
    ptfhost.copy(content=json.dumps(ptf_params), dest=params_path)

    logger.info("Calling VxlanSportRangeTest PTF test")
    ptf_runner(
        ptfhost,
        "ptftests",
        "vxlan_sport_range_ptftest.VxlanSportRangeTest",
        platform_dir="ptftests",
        params={"params_file": params_path},
        log_file="/tmp/vxlan_sport_range_ptftest.log",
    )


# ---------- Test ----------

def test_vxlan_source_port_range_and_hashing(ptfhost, sport_range_setup_teardown):
    """
    Verify VXLAN outer-UDP source-port range, hash consistency, and
    distribution evenness.

    Sends 1000 distinct TCP flows through the DUT.  The DUT encapsulates
    each into a VXLAN packet.  The PTF test checks:
      Phase 1 – every outer UDP sport is within the configured range.
      Phase 2 – re-sending the same flow yields the same sport.
      Phase 3 – flows are evenly distributed across the range.
    """
    setup, duthost, _ = sport_range_setup_teardown
    run_sport_ptf_test(ptfhost, setup)
