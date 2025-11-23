import json
import time
import sys
from ipaddress import IPv4Address
import pytest
import logging
import traceback
from tests.common.config_reload import config_reload
from tests.ptf_runner import ptf_runner
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory     # noqa:F401
from tests.common.vxlan_ecmp_utils import Ecmp_Utils
from tests.common.helpers.assertions import pytest_assert, pytest_require

logger = logging.getLogger(__name__)
ecmp_utils = Ecmp_Utils()

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.device_type('physical'),
    pytest.mark.asic('cisco-8000')
]

VNET_NAME = "Vnet1"
TUNNEL_NAME = "tunnel_v4"
VNI = 10000
PREFIX = "150.0.3.1/32"
INITIAL_ENDPOINTS = ["100.0.1.10", "100.0.2.10"]
CHANGED_ENDPOINTS = ["100.0.3.10", "100.0.4.10"]
PACKET_MULTIPLIER = 10


# ---------- Utility ----------
def get_loopback_ip(cfg_facts):
    for key in cfg_facts.get("LOOPBACK_INTERFACE", {}):
        if key.startswith("Loopback0|") and "." in key:
            return key.split("|")[1].split("/")[0]
    pytest.fail("Cannot find IPv4 Loopback0 address in LOOPBACK_INTERFACE")


def apply_chunk(duthost, payload, name):
    content = json.dumps(payload, indent=2)
    dest = f"/tmp/{name}.json"
    duthost.copy(content=content, dest=dest)
    duthost.shell(f"sonic-cfggen -j {dest} --write-to-db")


def _update_vxlan_endpoints(duthost, vnet, prefix, endpoints, vni):
    logger.info(f"Updating VNET_ROUTE_TUNNEL {vnet}|{prefix} with {len(endpoints)} endpoints")
    ep_str = ",".join(endpoints)
    duthost.shell(
        f"sonic-db-cli CONFIG_DB hmset 'VNET_ROUTE_TUNNEL|{vnet}|{prefix}' "
        f"endpoint '{ep_str}' vni '{vni}'"
    )
    time.sleep(3)


def get_available_vlan_id_and_ports(cfg_facts, num_ports_needed):
    """
    Return vlan id and available ports in that vlan if there are enough ports available.
    Args:
        cfg_facts: DUT config facts
        num_ports_needed: number of available ports needed for test
    """
    port_status = cfg_facts["PORT"]
    vlan_id = -1
    available_ports = []
    pytest_require("VLAN_MEMBER" in cfg_facts, "Can't get vlan member")
    for vlan_name, members in list(cfg_facts["VLAN_MEMBER"].items()):
        # Number of members in vlan is insufficient
        if len(members) < num_ports_needed:
            continue

        # Get available ports in vlan
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


# ---------- Single-VNET setup ----------
def vxlan_setup_one_vnet(duthost, ptfhost, tbinfo, cfg_facts,
                         config_facts, dut_indx, vxlan_port):
    ports = get_available_vlan_id_and_ports(config_facts, 1)
    pytest_assert(ports and len(ports) >= 1, "Not enough ports for VNET setup")

    port_indexes = config_facts["port_index_map"]

    host_interfaces = tbinfo["topo"]["ptf_map"][str(dut_indx)]
    ptf_ports_available_in_topo = {host_interfaces[k]: f"eth{k}" for k in host_interfaces}
    logger.info(f"PTF port map: {ptf_ports_available_in_topo}")

    ecmp_utils.Constants["KEEP_TEMP_FILES"] = False
    ecmp_utils.Constants["DEBUG"] = True

    ingress_if = ports[0]
    logger.info(f"Selected ingress interface: {ingress_if}")

    duthost.shell(f"config vlan member del all {ingress_if} || true")

    dut_vtep = get_loopback_ip(cfg_facts)
    logger.info(f"Creating VXLAN tunnel {TUNNEL_NAME} with source {dut_vtep}")
    apply_chunk(duthost, {"VXLAN_TUNNEL": {TUNNEL_NAME: {"src_ip": dut_vtep}}}, "vxlan_tunnel")
    apply_chunk(duthost, {"VNET": {VNET_NAME: {"vni": str(VNI), "vxlan_tunnel": TUNNEL_NAME}}}, "vnet")

    ptf_port_index = port_indexes[ingress_if]
    port_name = ptf_ports_available_in_topo[ptf_port_index]

    dut_ip = "201.0.1.1"
    apply_chunk(
        duthost,
        {"INTERFACE": {ingress_if: {"vnet_name": VNET_NAME}, f"{ingress_if}|{dut_ip}/24": {}}},
        "intf_bind",
    )

    ptf_ip = "201.0.1.101"

    ptfhost.shell(f"ip addr flush dev {port_name}")
    ptfhost.shell(f"ip addr add {ptf_ip}/24 dev {port_name}")
    ptfhost.shell(f"ip link set {port_name} up")

    logger.info(f"Programming route {PREFIX} -> {','.join(INITIAL_ENDPOINTS)}")
    apply_chunk(
        duthost,
        {"VNET_ROUTE_TUNNEL": {f"{VNET_NAME}|{PREFIX}": {"endpoint": ",".join(INITIAL_ENDPOINTS), "vni": str(VNI)}}},
        "route_tunnel",
    )
    time.sleep(5)

    ecmp_utils.configure_vxlan_switch(duthost, vxlan_port=vxlan_port)

    return {
        "dut_vtep": dut_vtep,
        "ptf_src_ip": ptf_ip,
        "dst_ip": PREFIX.split("/")[0],
        "ptf_ingress_port": ptf_port_index,
        "router_mac": duthost.facts["router_mac"],
        "vxlan_port": vxlan_port,
    }


@pytest.fixture(scope="module", autouse=True)
def one_vnet_setup_teardown(
    duthosts,
    rand_one_dut_hostname,
    ptfhost,
    tbinfo,
    localhost,
    request,
    scaled_vnet_params
):
    """
    Module-level setup:
    - Configures 1 VNET, 1 VXLAN tunnel, and 1 VNET route
    - Passes num_endpoints from scaled_vnet_params
    """
    duthost = duthosts[rand_one_dut_hostname]
    try:
        cfg_facts = json.loads(duthost.shell("sonic-cfggen -d --print-data")["stdout"])
        config_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
        duts_map = tbinfo["duts_map"]
        dut_indx = duts_map[duthost.hostname]
        vxlan_port = request.config.option.vxlan_port

        num_endpoints = scaled_vnet_params.get("num_endpoints", 128) or 128
        setup_params = vxlan_setup_one_vnet(duthost, ptfhost, tbinfo, cfg_facts,
                                            config_facts, dut_indx, vxlan_port)
        setup_params["num_endpoints"] = int(num_endpoints)
    except Exception as e:
        logger.error("Exception raised in setup: {}".format(repr(e)))
        logger.error(json.dumps(
            traceback.format_exception(*sys.exc_info()), indent=2))
        config_reload(duthost, safe_reload=True, yang_validate=False)
        pytest.fail("Vnet testing setup failed")

    yield setup_params, duthost, ptfhost

    config_reload(duthost, safe_reload=True, yang_validate=False)


# ---------- PTF runner helper ----------
def run_vxlan_ptf_test(ptfhost, endpoints, params, num_packets):
    logger.info(f"Calling VXLAN ECMP PTF test: {len(endpoints)} endpoints, {num_packets} packets")

    endpoints_file = "/tmp/ptf_endpoints.json"
    ptfhost.copy(content=json.dumps(endpoints), dest=endpoints_file)
    ptf_params = params.copy()
    ptf_params.update({
        "endpoints_file": endpoints_file,
        "num_packets": num_packets
    })
    params_path = "/tmp/ptf_params.json"
    ptfhost.copy(content=json.dumps(ptf_params), dest=params_path)

    ptf_runner(
        ptfhost,
        "ptftests",
        "vxlan_ecmp_ptftest.VxlanEcmpTest",
        platform_dir="ptftests",
        params={"params_file": params_path},
        log_file="/tmp/vxlan_ecmp_ptftest.log",
    )


# ---------- Tests ----------
def test_ecmp_two_endpoints(ptfhost, one_vnet_setup_teardown):
    logger.info("Running test_ecmp_two_endpoints")
    setup, duthost, _ = one_vnet_setup_teardown
    run_vxlan_ptf_test(
        ptfhost,
        INITIAL_ENDPOINTS,
        setup,
        num_packets=6,
    )


def test_ecmp_change_endpoints(ptfhost, one_vnet_setup_teardown):
    logger.info("Running test_ecmp_change_endpoints")
    setup, duthost, _ = one_vnet_setup_teardown
    _update_vxlan_endpoints(duthost, VNET_NAME, PREFIX, CHANGED_ENDPOINTS, VNI)
    run_vxlan_ptf_test(
        ptfhost,
        CHANGED_ENDPOINTS,
        setup,
        num_packets=6,
    )


def test_ecmp_scale(ptfhost, one_vnet_setup_teardown):
    logger.info("Running test_ecmp_scale")
    setup, duthost, _ = one_vnet_setup_teardown
    num_endpoints = setup["num_endpoints"]

    base_ip = int(IPv4Address("100.0.10.1"))
    endpoints = [str(IPv4Address(base_ip + i)) for i in range(num_endpoints)]
    _update_vxlan_endpoints(duthost, VNET_NAME, PREFIX, endpoints, VNI)
    time.sleep(20)

    num_packets = num_endpoints * PACKET_MULTIPLIER
    run_vxlan_ptf_test(
        ptfhost,
        endpoints,
        setup,
        num_packets=num_packets,
    )
