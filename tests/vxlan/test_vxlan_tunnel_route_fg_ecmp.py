import pytest
import time
import logging
import json
import sys
import traceback
from tests.ptf_runner import ptf_runner
from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.vxlan_ecmp_utils import Ecmp_Utils
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory  # noqa: F401

# Constants
VNET_NAME = "Vnet1"
TUNNEL_NAME = "tunnel_v4"
VNI = 1000
PREFIX = "150.0.3.1/32"
BUCKET_SIZE = 125
NUM_INITIAL_ENDPOINTS = 10
ENDPOINT_BASE_IP = "100.0.1."
NUM_FLOWS = 1000
CONFIG_DB_PATH = '/etc/sonic/config_db.json'
PERSIST_MAP_FILE = '/tmp/vxlan_tunnel_fg_ecmp_persist_map.json'
PTF_PARAMS_FILE = '/tmp/vxlan_tunnel_fg_ecmp_ptf_params.json'
PTF_LOG_FILE = '/tmp/vxlan_tunnel_fg_ecmp_test.log'

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.disable_loganalyzer
]

logger = logging.getLogger(__name__)
ecmp_utils = Ecmp_Utils()


def generate_endpoint_list(base_ip=ENDPOINT_BASE_IP, count=NUM_INITIAL_ENDPOINTS):
    """Generate list of endpoint IP addresses."""
    return [f"{base_ip}{i}" for i in range(count)]


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
    Return (vlan_id, available_ports) from the first VLAN that has
    enough administratively up ports.

    Args:
        cfg_facts: DUT config facts (from source="running")
        num_ports_needed: number of up ports required
    Returns:
        (vlan_id, list_of_port_names)
    """
    port_status = cfg_facts["PORT"]
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
                vlan_id = int(''.join([c for c in vlan_name if c.isdigit()]))
                logger.debug(f"Vlan {vlan_id} has available ports: {possible_ports}")
                return vlan_id, possible_ports

    pytest.fail(f"Could not find a VLAN with {num_ports_needed} up port(s)")


def set_route_tunnel(duthost, endpoints):
    """
    Program the initial VNET_ROUTE_TUNNEL entry with fine-grained ECMP.
    Uses sonic-cfggen --write-to-db (writes the full entry including
    consistent_hashing_buckets).
    """
    logger.info(f"Programming route {PREFIX} -> {','.join(endpoints)}")
    vni_str = ",".join([str(VNI)] * len(endpoints))
    apply_chunk(
        duthost,
        {"VNET_ROUTE_TUNNEL": {
            f"{VNET_NAME}|{PREFIX}": {
                "endpoint": ",".join(endpoints),
                "vni": vni_str,
                "consistent_hashing_buckets": str(BUCKET_SIZE),
            }
        }},
        "route_tunnel",
    )
    time.sleep(3)


# def update_route_tunnel(duthost, endpoints):
#     """
#     Update the endpoint list on an existing VNET_ROUTE_TUNNEL entry and
#     wait for route convergence.

#     Uses sonic-db-cli hmset so that existing fields (including
#     consistent_hashing_buckets) are preserved; only 'endpoint' and 'vni'
#     are overwritten.
#     """
#     logger.info(f"Updating route {PREFIX} -> {len(endpoints)} endpoints")
#     ep_str = ",".join(endpoints)
#     vni_str = ",".join([str(VNI)] * len(endpoints))
#     duthost.shell(
#         f"sonic-db-cli CONFIG_DB hmset 'VNET_ROUTE_TUNNEL|{VNET_NAME}|{PREFIX}' "
#         f"endpoint '{ep_str}' vni '{vni_str}'"
#     )
#     time.sleep(3)


def cleanup(duthost, ptfhost, ptf_port_name):
    logger.debug("cleanup: restoring config_db backup")
    duthost.shell(f"mv {CONFIG_DB_PATH}.bak {CONFIG_DB_PATH}")
    config_reload(duthost, safe_reload=True, check_intf_up_ports=True)
    for f in [PERSIST_MAP_FILE, PTF_PARAMS_FILE, PTF_LOG_FILE]:
        ptfhost.shell(f"rm -f {f}")
    if ptf_port_name:
        ptfhost.shell(f"ip addr flush dev {ptf_port_name}")


def vxlan_setup_one_vnet(duthost, ptfhost, tbinfo, cfg_facts,
                         config_facts, dut_indx, vxlan_port):
    vlan_id, ports = get_available_vlan_id_and_ports(config_facts, 1)
    pytest_assert(ports, "No available VLAN ports for VNET setup")

    port_indexes = config_facts["port_index_map"]
    host_interfaces = tbinfo["topo"]["ptf_map"][str(dut_indx)]
    ptf_ports_available_in_topo = {host_interfaces[k]: f"eth{k}" for k in host_interfaces}
    logger.info(f"PTF port map: {ptf_ports_available_in_topo}")

    ecmp_utils.Constants["KEEP_TEMP_FILES"] = False
    ecmp_utils.Constants["DEBUG"] = True

    ingress_if = ports[0]
    logger.info(f"Selected ingress interface: {ingress_if} from VLAN {vlan_id}")

    # Remove port from its VLAN so we can bind it directly to the VNET interface
    duthost.shell(f"config vlan member del {vlan_id} {ingress_if} || true")

    dut_vtep = get_loopback_ip(cfg_facts)
    logger.info(f"Creating VXLAN tunnel {TUNNEL_NAME} with source {dut_vtep}")

    apply_chunk(duthost, {"VXLAN_TUNNEL": {TUNNEL_NAME: {"src_ip": dut_vtep}}}, "vxlan_tunnel")
    apply_chunk(duthost, {"VNET": {VNET_NAME: {"vni": str(VNI), "vxlan_tunnel": TUNNEL_NAME}}}, "vnet")

    ptf_port_index = port_indexes[ingress_if]
    ptf_port_name = ptf_ports_available_in_topo[ptf_port_index]

    dut_ip = "201.0.1.1"
    apply_chunk(
        duthost,
        {"INTERFACE": {ingress_if: {"vnet_name": VNET_NAME}, f"{ingress_if}|{dut_ip}/24": {}}},
        "intf_bind",
    )

    ptf_ip = "201.0.1.101"
    ptfhost.shell(f"ip addr flush dev {ptf_port_name}")
    ptfhost.shell(f"ip addr add {ptf_ip}/24 dev {ptf_port_name}")
    ptfhost.shell(f"ip link set {ptf_port_name} up")

    initial_endpoints = generate_endpoint_list()
    set_route_tunnel(duthost, initial_endpoints)
    time.sleep(3)

    ecmp_utils.configure_vxlan_switch(duthost, vxlan_port=vxlan_port)

    return {
        "dut_vtep": dut_vtep,
        "ptf_src_ip": ptf_ip,
        "dst_ip": PREFIX.split("/")[0],
        "ptf_ingress_port": ptf_port_index,
        "router_mac": duthost.facts["router_mac"],
        "vxlan_port": vxlan_port,
        "ptf_port_name": ptf_port_name,
    }


@pytest.fixture(scope="module", autouse=True)
def common_setup_teardown(
    duthosts,
    rand_one_dut_hostname,
    ptfhost,
    tbinfo,
    request,
):
    """
    Module-level setup:
    - Configures 1 VNET, 1 VXLAN tunnel, and 1 VNET route with fine-grained ECMP
    """
    duthost = duthosts[rand_one_dut_hostname]
    duthost.shell(f"cp {CONFIG_DB_PATH} {CONFIG_DB_PATH}.bak")

    setup_params = None
    try:
        cfg_facts = json.loads(duthost.shell("sonic-cfggen -d --print-data")["stdout"])
        config_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
        duts_map = tbinfo["duts_map"]
        dut_indx = duts_map[duthost.hostname]
        vxlan_port = request.config.option.vxlan_port

        setup_params = vxlan_setup_one_vnet(
            duthost, ptfhost, tbinfo, cfg_facts, config_facts, dut_indx, vxlan_port
        )

        yield setup_params, duthost, ptfhost

    except Exception as e:
        logger.error("Exception raised in setup: {}".format(repr(e)))
        logger.error(json.dumps(traceback.format_exception(*sys.exc_info()), indent=2))
        pytest.fail("Vnet testing setup failed")

    finally:
        ptf_port_name = (setup_params or {}).get("ptf_port_name", "")
        cleanup(duthost, ptfhost, ptf_port_name)


def run_vxlan_ptf_test(ptfhost, endpoints, params, test_case, num_packets, **kwargs):
    """
    Invoke the PTF fine-grained ECMP test.

    Args:
        ptfhost: PTF host object
        endpoints: list of endpoint IP strings active for this phase
        params: setup_params dict from the fixture
        test_case: one of 'create_flows', 'verify_consistent_hash',
                   'withdraw_endpoint', 'add_endpoint'
        num_packets: number of flows to send
        **kwargs: additional per-test-case params (e.g. withdraw_endpoint,
                  add_endpoint)
    """
    logger.info(f"PTF test: test_case={test_case}, endpoints={len(endpoints)}, flows={num_packets}")

    flows_per_nh = NUM_FLOWS / len(endpoints)
    exp_flow_count = {ep: flows_per_nh for ep in endpoints}

    ptf_params = params.copy()
    # # Remove ptf_port_name — it's an orchestration detail, not needed by PTF test
    # ptf_params.pop("ptf_port_name", None)
    ptf_params.update({
        "endpoints": endpoints,
        "test_case": test_case,
        "num_packets": num_packets,
        "exp_flow_count": exp_flow_count,
        "persist_map": PERSIST_MAP_FILE,
    })
    ptf_params.update(kwargs)

    ptfhost.copy(content=json.dumps(ptf_params), dest=PTF_PARAMS_FILE)

    ptf_runner(
        ptfhost,
        "ptftests",
        "vxlan_tunnel_fg_ecmp_test.VxlanTunnelFgEcmpTest",
        platform_dir="ptftests",
        params={"params_file": PTF_PARAMS_FILE},
        log_file=PTF_LOG_FILE,
        qlen=1000,
        is_python3=True,
    )


def test_vxlan_fg_ecmp(ptfhost, common_setup_teardown):
    logger.info("Running test_vxlan_fg_ecmp")
    setup, duthost, _ = common_setup_teardown

    endpoints = generate_endpoint_list()  # 100.0.1.0 .. 100.0.1.9 (10 endpoints)

    # Phase 1: Create flow-to-endpoint mapping (1000 unique flows)
    logger.info("Phase 1: create_flows — send 1000 flows, record endpoint distribution")
    run_vxlan_ptf_test(ptfhost, endpoints, setup, "create_flows", num_packets=NUM_FLOWS)

    # Phase 2: Verify consistent hashing — same flow must hit same endpoint
    logger.info("Phase 2: verify_consistent_hash — replay flows, assert 100% match")
    run_vxlan_ptf_test(ptfhost, endpoints, setup, "verify_consistent_hash", num_packets=NUM_FLOWS)

    # Phase 3: Withdraw one endpoint; only its ~100 flows should redistribute
    withdrawn_endpoint = endpoints[-1]  # 100.0.1.9
    remaining_endpoints = endpoints[:-1]
    logger.info(f"Phase 3: withdraw_endpoint {withdrawn_endpoint} (9 remaining)")
    set_route_tunnel(duthost, remaining_endpoints)
    run_vxlan_ptf_test(
        ptfhost, remaining_endpoints, setup, "withdraw_endpoint",
        num_packets=NUM_FLOWS, withdraw_endpoint=withdrawn_endpoint,
    )

    # Phase 4: Add a new endpoint; only ~10% of flows should move back
    new_endpoint = f"{ENDPOINT_BASE_IP}{NUM_INITIAL_ENDPOINTS}"  # 100.0.1.10
    readded_endpoints = remaining_endpoints + [new_endpoint]
    logger.info(f"Phase 4a: add_endpoint — add {new_endpoint} (back to 10 endpoints)")
    set_route_tunnel(duthost, readded_endpoints)
    run_vxlan_ptf_test(
        ptfhost, readded_endpoints, setup, "add_endpoint",
        num_packets=NUM_FLOWS, add_endpoint=new_endpoint,
    )

    # # Phase 4b: Add a brand-new endpoint; only ~9% of flows should move to it
    # new_endpoint = f"{ENDPOINT_BASE_IP}{NUM_INITIAL_ENDPOINTS}"  # 100.0.1.10
    # all_endpoints = readded_endpoints + [new_endpoint]
    # logger.info(f"Phase 4b: add_endpoint — new endpoint {new_endpoint} (11 total)")
    # update_route_tunnel(duthost, all_endpoints)
    # run_vxlan_ptf_test(
    #     ptfhost, all_endpoints, setup, "add_endpoint",
    #     num_packets=NUM_FLOWS, add_endpoint=new_endpoint,
    # )
