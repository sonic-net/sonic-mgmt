import pytest
import time
import logging
import json
import sys
import traceback
from tests.ptf_runner import ptf_runner
from tests.common import config_reload
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.vxlan_ecmp_utils import Ecmp_Utils

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # noqa F401

# Constants
VNET_NAME = "Vnet1"
TUNNEL_NAME = "tunnel_v4"
VNI = 10000
PREFIX = "150.0.3.1/32"
BUCKET_SIZE = 125
NUM_ENDPOINTS = 10
INITIAL_ENDPOINTS = ["100.0.1.10", "100.0.1.11", "100.0.1.12", "100.0.1.13", "100.0.1.14","100.0.1.15","100.0.1.16","100.0.1.17","100.0.1.18","100.0.1.19",]
NUM_FLOWS = 1000
MAX_DEVIATION = 0.25
ROUTE_PREFIX_V4 = "150.0.0.0/24"
CONFIG_DB_PATH = '/etc/sonic/config_db.json'
FG_ECMP_PTF_CFG = '/tmp/vxlan_tunnel_fg_ecmp.json'
PERSIST_MAP_FILE = '/tmp/vxlan_tunnel_fg_ecmp_persist_map.json'
VXLAN_PORT = 4789

pytestmark = [
    # pytest.mark.topology('t0'),
    pytest.mark.disable_loganalyzer
]

logger = logging.getLogger(__name__)
ecmp_utils = Ecmp_Utils()


def generate_endpoint_list(count, base_ip=ENDPOINT_BASE_IP):
    """Generate list of endpoint IP addresses."""
    return [f"{base_ip}{i+1}" for i in range(count)]



def create_vnet_route_with_fg_ecmp(duthost, vnet_name, route_prefix, endpoints, vnet_vni):
    """Create VNET route tunnel with consistent hashing buckets."""
    logger.info(f"Creating VNET route {route_prefix} with FG-ECMP, endpoints: {endpoints}")
    
    endpoint_str = ",".join(endpoints)
    vni_str = ",".join([str(vnet_vni)] * len(endpoints))
    
    # Create VNET_ROUTE_TUNNEL_TABLE entry with consistent_hashing_buckets
    vnet_route_config = '''{{
                "VNET_ROUTE_TUNNEL_TABLE:{}:{}": {{
                    "endpoint": "{}",
                    "vni": "{}",
                    "consistent_hashing_buckets": "{}"
                }},
                "OP": "{}"
            }}'''.format(vnet_name, route_prefix, endpoint_str, vni_str, str(BUCKET_SIZE), "SET")
    
    ecmp_utils.apply_config_in_swss(duthost, vnet_route_config)


def create_ptf_config(ptfhost, endpoints, router_mac, t2_ports, loopback_ip):
    """Create PTF configuration file for VXLAN FG-ECMP test."""
    config = {
        "endpoints": endpoints,
        "dut_mac": router_mac,
        "t2_ports": t2_ports,
        "loopback_ip": loopback_ip,
        "num_flows": NUM_FLOWS,
        "vxlan_port": VXLAN_PORT,
        "bucket_size": BUCKET_SIZE,
        "max_deviation": MAX_DEVIATION
    }
    
    logger.info(f"Creating PTF config: {config}")
    ptfhost.copy(content=json.dumps(config, indent=2), dest=FG_ECMP_PTF_CFG)


def run_ptf_test(ptfhost, test_case, dst_ip, withdrawn_endpoint=None, added_endpoint=None):
    """Run PTF test for VXLAN tunnel FG-ECMP validation."""
    logger.info(f"Running PTF test case: {test_case}")
    
    params = {
        "test_case": test_case,
        "dst_ip": dst_ip,
        "config_file": FG_ECMP_PTF_CFG,
        "persist_map_file": PERSIST_MAP_FILE
    }
    
    if withdrawn_endpoint:
        params["withdrawn_endpoint"] = withdrawn_endpoint
    if added_endpoint:
        params["added_endpoint"] = added_endpoint
    
    log_file = f"/tmp/vxlan_tunnel_fg_ecmp.{test_case}"
    
    ptf_runner(
        ptfhost,
        "ptftests",
        "vxlan_tunnel_fg_ecmp_test.VxlanTunnelFgEcmpTest",
        platform_dir="ptftests",
        params=params,
        qlen=1000,
        log_file=log_file,
        is_python3=True
    )


def cleanup(duthost, ptfhost):
    logger.debug("cleanup: Loading backup config db json.")
    duthost.shell(f"mv {CONFIG_DB_PATH}.bak {CONFIG_DB_PATH}")

    # Reload to restore configuration
    config_reload(duthost, safe_reload=True, check_intf_up_ports=True)
    
    ptfhost.shell(f"rm -f {PERSIST_MAP_FILE}", module_ignore_errors=True)


@pytest.fixture(scope="module")
def common_setup_teardown(tbinfo, duthosts, rand_one_dut_hostname, ptfhost):
    duthost = duthosts[rand_one_dut_hostname]
    
    # backup config_db.json for cleanup
    duthost.shell(f"cp {CONFIG_DB_PATH} {CONFIG_DB_PATH}.bak")
    
    ecmp_utils.Constants["KEEP_TEMP_FILES"] = False
    ecmp_utils.Constants["DEBUG"] = True
    
    try:
        mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
        router_mac = duthost.facts['router_mac']
        
        # # Get T2 (uplink) ports - these are ports where VXLAN encap packets will be sent
        # t2_ports = []
        # for name, val in list(mg_facts['minigraph_portchannels'].items()):
        #     members = [mg_facts['minigraph_ptf_indices'][member] for member in val['members']]
        #     t2_ports.extend(members)
        
        # if not t2_ports:
        #     pytest.skip("No T2 ports available for VXLAN tunnel testing")
        
        # logger.info(f"T2 ports for VXLAN tunnel: {t2_ports}")
        
        tunnel_v4 = ecmp_utils.create_vxlan_tunnel(duthost, mg_facts, af="v4")
        vnet_dict = ecmp_utils.create_vnets(duthost, tunnel_v4)
        vnet_name, vnet_vni = next(iter(vnet_dict.items()))
        
        # # Bind interface to VNET
        # interface = bind_interface_to_vnet(duthost, VNET_NAME)
        
        endpoints = ecmp_utils.get_list_of_nexthops(NUM_ENDPOINTS, af="v4")
        logger.info(f"Generated {NUM_ENDPOINTS} endpoints: {endpoints}")
        
        # Create VNET route tunnel with FG-ECMP
        create_vnet_route_with_fg_ecmp(duthost, vnet_name, ROUTE_PREFIX_V4, endpoints, vnet_vni)
        
        # Create PTF configuration
        create_ptf_config(ptfhost, endpoints, router_mac, t2_ports, loopback_ip)
        
        # Wait for configuration to stabilize
        time.sleep(10)
        
        yield duthost, ptfhost, endpoints, router_mac, t2_ports, loopback_ip
        
    except Exception as e:
        # Cleanup on failure during setup
        logger.error(f"Exception during setup: {repr(e)}.")
        cleanup(duthost, ptfhost)
        pytest.fail(f"Setup failed: {repr(e)}")
        
    finally:
        # Cleanup after tests
        cleanup(duthost, ptfhost)


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

def setup_route_tunnel(duthost):
    logger.info(f"Programming route {PREFIX} -> {','.join(INITIAL_ENDPOINTS)}")
    
    vni_str = ",".join([str(VNI)] * len(INITIAL_ENDPOINTS))
    apply_chunk(
        duthost,
        {"VNET_ROUTE_TUNNEL": {f"{VNET_NAME}|{PREFIX}": {"endpoint": ",".join(INITIAL_ENDPOINTS), "vni": vni_str, "consistent_hashing_buckets": str(BUCKET_SIZE)}}},
        "route_tunnel",
    )
    
    
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

    setup_route_tunnel(duthost)

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

        setup_params = vxlan_setup_one_vnet(duthost, ptfhost, tbinfo, cfg_facts,
                                            config_facts, dut_indx, vxlan_port)
        setup_params["num_endpoints"] = NUM_ENDPOINTS
    except Exception as e:
        logger.error("Exception raised in setup: {}".format(repr(e)))
        logger.error(json.dumps(
            traceback.format_exception(*sys.exc_info()), indent=2))
        config_reload(duthost, safe_reload=True, yang_validate=False)
        pytest.fail("Vnet testing setup failed")

    yield setup_params, duthost, ptfhost

    config_reload(duthost, safe_reload=True, yang_validate=False)
    
    
# ---------- PTF runner helper ----------
def run_vxlan_ptf_test(ptfhost, endpoints, params, test_case, num_packets, **kwargs):
    logger.info(f"Calling VXLAN ECMP PTF test: {len(endpoints)} endpoints, {num_packets} packets")

    endpoints_file = "/tmp/ptf_endpoints.json"
    ptfhost.copy(content=json.dumps(endpoints), dest=endpoints_file)
    ptf_params = params.copy()
    
    exp_flow_count = {}
    flows_per_nh = NUM_FLOWS/len(endpoints)
    for nh in endpoints:
        exp_flow_count[nh] = flows_per_nh
        
    ptf_params.update({
        "endpoints_file": endpoints_file,
        "test_case": test_case,
        "num_packets": num_packets,
        "num_endpoints": len(endpoints),
        "exp_flow_count": exp_flow_count
    })
    params.update(kwargs)
    
    params_path = "/tmp/ptf_params.json"
    ptfhost.copy(content=json.dumps(ptf_params), dest=params_path)
        
    ptf_runner(
        ptfhost,
        "ptftests",
        "vxlan_tunnel_fg_ecmp_test.VxlanTunnelFgEcmpTest",
        platform_dir="ptftests",
        params={"params_file": params_path},
        log_file="/tmp/vxlan_tunnel_fg_ecmp_test.log",
    )


def test_vxlan_fg_ecmp(ptfhost, one_vnet_setup_teardown):
    logger.info("Running test_ecmp_ten_endpoints")
    setup, duthost, _ = one_vnet_setup_teardown
    run_vxlan_ptf_test(
        ptfhost,
        INITIAL_ENDPOINTS,
        setup,
        "create_flows",
        num_packets=1000,
    )
    
    logger.info("Hashing verification: Send the same flows again, "
                "and verify packets end up on the same ports for a given flow")
    run_vxlan_ptf_test(
        ptfhost,
        INITIAL_ENDPOINTS,
        setup,
        "verify_consistent_hash",
        num_packets=1000,
    )
    
    withdrawn_endpoint = INITIAL_ENDPOINTS.pop()
    logger.info("Testing endpoint withdrawal: Removing one endpoint and verifying flows are redistributed")
    
    setup_route_tunnel(duthost)
    run_vxlan_ptf_test(
        ptfhost,
        INITIAL_ENDPOINTS,
        setup,
        "withdraw_endpoint",
        num_packets=1000,
        withdrawn_endpoint=withdrawn_endpoint
    )
    
    run_vxlan_ptf_test(
        ptfhost,
        INITIAL_ENDPOINTS,
        setup,
        "verify_consistent_hash",
        num_packets=1000,
    )
    
    
    
    