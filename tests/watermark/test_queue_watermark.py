import pytest
import logging
import time
import ptf.testutils as testutils
import ast
import random

from tests.common.helpers.assertions import pytest_assert
from tests.common.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload
from tests.common.utilities import wait_until


pytestmark = [pytest.mark.topology("t0", "t1")]

logger = logging.getLogger(__name__)

ASIC_DB_SYNC_TIME = 10
WATERMARK_CLEAR_WAIT_TIME = 5  # Clearing watermarks is relatively fast
WATERMARK_UPDATE_WAIT_TIME = 120  # Updating watermarks can take much longer

# ASIC DB key patterns
SCHEDULER_PATTERN = "ASIC_STATE:SAI_OBJECT_TYPE_SCHEDULER:oid:*"

PACKET_COUNT = 1000
PACKET_SIZE = 128  # total size of each packet in bytes
# This is the percentage tolerance for the watermark values (meaning that watermark values after sending
# all of the congestion packets should be at most TOLERANCE% less than the number of bytes sent).
TOLERANCE = 5
BLOCKING_SCHEDULER = "SCHEDULER_BLOCK_DATA_PLANE"
# Number of queues to randomly select and test for each ip_version/queue_type combination.
NUM_QUEUES_TO_TEST = 3

sonic_db_cli = "sonic-db-cli"
namespace = ""


@pytest.fixture(scope="module", autouse=True)
def checkpoint(duthost):
    create_checkpoint(duthost)
    yield
    try:
        rollback_or_reload(duthost)
    finally:
        delete_checkpoint(duthost)


@pytest.fixture(scope="module", autouse=True)
def set_namespace(duthost, enum_frontend_asic_index):
    global namespace
    if duthost.is_multi_asic:
        namespace = duthost.get_namespace_from_asic_id(enum_frontend_asic_index)
    else:
        namespace = ""


def get_namespace_option():
    global namespace
    if namespace:
        return f"-n {namespace}"
    else:
        return ""


@pytest.fixture(scope="module", autouse=True)
def set_sonic_db_cli(set_namespace):  # noqa F811
    global sonic_db_cli
    sonic_db_cli = f"sonic-db-cli {get_namespace_option()}"


def count_keys(duthost, db, pattern):
    result = duthost.shell(f"{sonic_db_cli} {db} KEYS '{pattern}'")["stdout"].strip()
    if not result:
        return 0
    return len(result.splitlines())


@pytest.fixture(scope="module")
def create_blocking_scheduler(duthost):
    old_scheduler_count = count_keys(duthost, "ASIC_DB", SCHEDULER_PATTERN)
    logger.info(f"Creating the blocking scheduler '{BLOCKING_SCHEDULER}' on the DUT.")
    cmd = f"{sonic_db_cli} CONFIG_DB HSET 'SCHEDULER|{BLOCKING_SCHEDULER}' 'type' 'DWRR' 'weight' '15'" + \
        " 'pir' '1' 'cir' '1'"
    if duthost.facts["asic_type"] == "broadcom":
        cmd += " 'meter_type' 'packets'"
    duthost.shell(cmd)
    pytest_assert(
        wait_until(ASIC_DB_SYNC_TIME, 2, 0,
                   lambda: count_keys(duthost, "ASIC_DB", SCHEDULER_PATTERN) == old_scheduler_count + 1),
        f"Scheduler {BLOCKING_SCHEDULER} was not added to ASIC DB."
    )


def select_egress_interface_ipv4(duthost, portchannel_info):
    ip_interfaces = duthost.show_ip_interface()["ansible_facts"]["ip_interfaces"]
    for intf, info in ip_interfaces.items():
        if (intf.startswith("Ethernet") or intf.startswith("PortChannel")) and info["oper_state"].lower() == "up":
            neigh_ip = info.get("peer_ipv4", "")
            if not neigh_ip or neigh_ip.lower() == "n/a":
                continue

            if intf.startswith("PortChannel"):
                members = portchannel_info[intf]["members"]
            else:
                members = [intf]
            logger.info(f"Selected egress packet's dest IPv4 '{neigh_ip}' and egress interface '{intf}'.")
            return (neigh_ip, members)
    pytest.skip("No suitable egress interface found on the DUT.")


def select_egress_interface_ipv6(duthost, portchannel_info):
    ip_interfaces = duthost.show_ipv6_interfaces()
    for intf, info in ip_interfaces.items():
        if (intf.startswith("Ethernet") or intf.startswith("PortChannel")) and info["oper"].lower() == "up":
            neigh_ip = info.get("neighbor ip", "")
            if not neigh_ip or neigh_ip.lower() == "n/a":
                continue

            if intf.startswith("PortChannel"):
                members = portchannel_info[intf]["members"]
            else:
                members = [intf]
            logger.info(f"Selected egress packet's dest IPv6 '{neigh_ip}' and egress interface '{intf}'.")
            return (neigh_ip, members)
    pytest.skip("No suitable egress interface found on the DUT.")


def select_egress_interface(duthost, minigraph_facts, ipv4=True):
    """
    Find an Ethernet or a PortChannel interface that is oper UP and has a neighbor IP.
    Traffic sent to DUT will go out from this interface.
    """
    portchannel_info = minigraph_facts["minigraph_portchannels"]
    if ipv4:
        return select_egress_interface_ipv4(duthost, portchannel_info)
    else:
        return select_egress_interface_ipv6(duthost, portchannel_info)


def select_ingress_port(duthost, exclude_ports=[]):
    """
        Returns the name of an oper UP Ethernet interface that is not in the exclude_ports list.
        PTF will send traffic to this interface.
    """
    interfaces_status = duthost.show_interface(command="status")["ansible_facts"]["int_status"]
    for intf, info in interfaces_status.items():
        if info["oper_state"].lower() == "up" and intf.startswith("Ethernet") and intf not in exclude_ports:
            logger.info(f"Selected '{intf}' as ingress port.")
            return intf
    pytest.skip("No suitable ingress port found on the DUT.")


def get_dest_mac(duthost, tbinfo, minigraph_facts, ingress_port, router_mac):
    """
    Returns the destination MAC the ingress packet must have to be L3-routed (and therefore
    forwarded to the egress queue) when it ingresses on 'ingress_port'.

    On t1 the server/downlink ports are routed (L3) interfaces, so the global router MAC
    is the termination MAC. On t0/dualtor the server ports are VLAN member ports; routing
    for that subnet is done by the VLAN SVI, whose MAC may differ from the router MAC
    (on dualtor it is the shared gateway MAC). Using the router MAC on such a port leaves
    the frame at L2 and it gets flooded in the VLAN instead of being routed to the egress port.
    """
    if tbinfo["topo"]["type"] == "t0":
        for vlan_name, vlan_info in minigraph_facts.get("minigraph_vlans", {}).items():
            if ingress_port in vlan_info.get("members", []):
                return duthost.get_dut_iface_mac(vlan_name)
    return router_mac


def find_qos_mapping_table_name(duthost, ports, qos_mapping):
    qos_table_name = ""
    for port in ports:
        table = duthost.shell(f"{sonic_db_cli} CONFIG_DB HGET 'PORT_QOS_MAP|{port}' '{qos_mapping}'")["stdout"].strip()
        if not table:
            continue
        if qos_table_name and qos_table_name != table:
            pytest.fail(f"{qos_mapping} is not the same for all ports in {ports}.")
        qos_table_name = table
    if not qos_table_name:
        # Check the global table
        table = duthost.shell(f"{sonic_db_cli} CONFIG_DB HGET 'PORT_QOS_MAP|global' '{qos_mapping}'")["stdout"].strip()
        if not table:
            pytest.fail(f"{qos_mapping} is not defined for any port in {ports} or globally.")
        qos_table_name = table
    return qos_table_name


def collect_dut_all_prio(duthost, ports):
    config_facts = duthost.get_running_config_facts()

    dscp_to_tc_map_lists = config_facts.get("DSCP_TO_TC_MAP")
    if not dscp_to_tc_map_lists:
        return []

    profile = find_qos_mapping_table_name(duthost, ports, "dscp_to_tc_map")
    dscp_to_tc_map = dscp_to_tc_map_lists[profile]

    tc = [int(p) for p in list(dscp_to_tc_map.values())]
    return list(set(tc))


def collect_dut_lossless_prio(duthost, ports):
    config_facts = duthost.get_running_config_facts()

    port_qos_map = config_facts.get("PORT_QOS_MAP")
    if not port_qos_map:
        return []

    # lossless_prios will be set to the union of all PFC-enabled priorities across the ports
    lossless_prios = set()
    for port in ports:
        pfc_enable = port_qos_map.get(port, {}).get("pfc_enable", "").split(',')
        lossless_prios.update(int(x) for x in pfc_enable)
    return list(lossless_prios)


def collect_dut_lossy_prio(duthost, ports):
    lossless_prio = collect_dut_lossless_prio(duthost, ports)
    all_prio = collect_dut_all_prio(duthost, ports)
    return list(set(all_prio) - set(lossless_prio))


def get_tc_to_queue_mapping(duthost, egress_ports, tc_list):
    """
    Get the mapping from traffic class (TC) to queue for the specified TCs.

    Args:
        duthost: The DUT host object.
        egress_ports: List of egress ports.
        tc_list: List of traffic classes to retrieve the mapping for.

    Returns:
        A dictionary mapping each TC in tc_list to its corresponding queue.
    """
    tc_to_queue_table = find_qos_mapping_table_name(duthost, egress_ports, "tc_to_queue_map")
    tc_to_queue_str = \
        duthost.shell(f"{sonic_db_cli} CONFIG_DB HGETALL 'TC_TO_QUEUE_MAP|{tc_to_queue_table}'")["stdout"].strip()
    tc_to_queue = ast.literal_eval(tc_to_queue_str)
    tc_to_queue = {int(tc_str): int(queue_str) for tc_str, queue_str in tc_to_queue.items() if int(tc_str) in tc_list}
    logger.info(f"TC to queue mapping: {tc_to_queue}.")
    return tc_to_queue


def get_queue_to_dscp_mapping(duthost, ingress_port, egress_ports, tc_list):
    """
    Get the mapping from queue to DSCP values for the specified traffic classes (TCs).

    Args:
        duthost: The DUT host object.
        ingress_port: The ingress port.
        egress_ports: List of egress ports.
        tc_list: List of traffic classes to retrieve the mapping for.

    Returns:
        A dictionary mapping each queue to a list of DSCP values that map to that queue.
    """
    tc_to_queue = get_tc_to_queue_mapping(duthost, egress_ports, tc_list)
    dscp_to_tc_table = find_qos_mapping_table_name(duthost, [ingress_port], "dscp_to_tc_map")
    dscp_to_tc_map_str = \
        duthost.shell(f"{sonic_db_cli} CONFIG_DB HGETALL 'DSCP_TO_TC_MAP|{dscp_to_tc_table}'")["stdout"].strip()
    dscp_to_tc_map = ast.literal_eval(dscp_to_tc_map_str)
    dscp_to_tc_map = {int(dscp): int(tc) for dscp, tc in ast.literal_eval(dscp_to_tc_map_str).items()
                      if int(tc) in tc_list}
    queue_to_dscp = {}  # Each queue will be mapped to a list of DSCP values
    for dscp, tc in dscp_to_tc_map.items():
        queue = tc_to_queue.get(tc)
        if queue is None:
            logger.warning(f"Traffic class {tc} is not mapped to any queues.")
            continue
        queue_to_dscp[queue] = queue_to_dscp.get(queue, [])
        queue_to_dscp[queue].append(dscp)
    return queue_to_dscp


def select_random_queues(duthost, ingress_port, egress_ports, queue_type):
    """
    Returns a dictionary mapping each randomly-selected queue to a DSCP value associated with that queue.
    """
    if queue_type == "lossless":
        tc_list = collect_dut_lossless_prio(duthost, [ingress_port])
    else:
        tc_list = collect_dut_lossy_prio(duthost, [ingress_port])
    if not tc_list:
        return {}

    queue_to_dscp = get_queue_to_dscp_mapping(duthost, ingress_port, egress_ports, tc_list)
    queues = list(queue_to_dscp.keys())
    if not queues:
        return {}
    selected_queues = random.sample(queues, min(NUM_QUEUES_TO_TEST, len(queues)))

    return {queue: random.choice(queue_to_dscp[queue]) for queue in selected_queues}


def apply_blocking_scheduler(duthost, egress_ports, queues):
    """
    For each egress port, sets the scheduler of each specified queue to the blocking scheduler.
    """
    for port in egress_ports:
        for queue in queues:
            logger.info(f"Setting the scheduler of {port}|{queue} to '{BLOCKING_SCHEDULER}'...")
            duthost.shell(f"{sonic_db_cli} CONFIG_DB HSET 'QUEUE|{port}|{queue}' 'scheduler' '{BLOCKING_SCHEDULER}'")
    logger.info(f"Waiting {ASIC_DB_SYNC_TIME} seconds for the configuration to take effect...")
    time.sleep(ASIC_DB_SYNC_TIME)  # Wait for the configuration to take effect


@pytest.fixture(params=[("ipv4", "lossy"), ("ipv4", "lossless"), ("ipv6", "lossy"), ("ipv6", "lossless")],
                ids=["ipv4-lossy", "ipv4-lossless", "ipv6-lossy", "ipv6-lossless"])
def setup(duthost, tbinfo, request, create_blocking_scheduler):  # noqa F811
    minigraph_facts = duthost.get_extended_minigraph_facts(tbinfo)
    ptf_indices = minigraph_facts["minigraph_ptf_indices"]
    ip_version = request.param[0]
    queue_type = request.param[1]

    test_params = {}
    test_params["ip_version"] = request.param[0]
    neigh_ip, egress_ports = select_egress_interface(duthost, minigraph_facts,
                                                     ipv4=(ip_version == "ipv4"))
    test_params["neigh_ip"] = neigh_ip
    test_params["egress_ports"] = egress_ports

    ingress_port = select_ingress_port(duthost, exclude_ports=egress_ports)
    test_params["ingress_port_index"] = ptf_indices[ingress_port]

    queue_to_dscp = select_random_queues(duthost, ingress_port, egress_ports, queue_type)
    if not queue_to_dscp:
        pytest.skip(f"No {queue_type} TC found on DUT.")
    test_params["queue_to_dscp"] = queue_to_dscp
    # On t0/dualtor the ingress port may be a VLAN member, in which case the congestion packet must be
    # addressed to the VLAN SVI MAC (the L3 termination MAC) to be routed to the egress queue rather
    # than flooded in the VLAN.
    router_mac = duthost.facts["router_mac"]
    test_params["dest_mac"] = get_dest_mac(duthost, tbinfo, minigraph_facts, ingress_port, router_mac)

    # Apply the blocking scheduler to each selected queue (for each egress port)
    apply_blocking_scheduler(duthost, egress_ports, list(queue_to_dscp.keys()))

    logger.info(f"Test parameters: {test_params}")
    return test_params


def get_congestion_packet(dest_mac, ip_version, dest_ip, dscp, pkt_len):
    if ip_version == "ipv4":
        pkt = testutils.simple_udp_packet(
            eth_dst=dest_mac,
            ip_dst=dest_ip,
            ip_dscp=dscp,
            pktlen=pkt_len
        )
    else:
        pkt = testutils.simple_udpv6_packet(
            eth_dst=dest_mac,
            ipv6_dst=dest_ip,
            ipv6_dscp=dscp,
            pktlen=pkt_len
        )
    return pkt


def get_queue_watermarks(duthost, watermark_type):
    """
    Get watermarks for all ports and queues.
    """
    watermarks_list_str = \
        duthost.shell(f"show queue {watermark_type} unicast {get_namespace_option()} --json")["stdout"].strip()
    watermarks_list = ast.literal_eval(watermarks_list_str)
    # watermarks_list is a list of dictionaries, each representing the watermarks for a single port. Example:
    # [
    #   {
    #       "Port": "Ethernet0",
    #       "UC0": "0",
    #       "UC1": "0",
    #       "UC2": "0",
    #       "UC3": "0",
    #       "UC4": "0",
    #       "UC5": "0",
    #       "UC6": "0",
    #       "UC7": "0"
    #   },
    #   {
    #       "Port": "Ethernet4",
    #       "UC0": "0",
    #       "UC1": "0",
    #       "UC2": "0",
    #       "UC3": "0",
    #       "UC4": "0",
    #       "UC5": "0",
    #       "UC6": "0",
    #       "UC7": "0"
    #   }
    # ]
    watermarks = {}
    for port_watermarks in watermarks_list:
        port = port_watermarks.pop("Port")
        watermarks[port] = port_watermarks
    return watermarks


def check_queue_watermarks(duthost, egress_ports, queue, watermark_type, expected_value):
    watermarks = get_queue_watermarks(duthost, watermark_type)
    watermark_str = "user-watermark" if watermark_type == "watermark" else watermark_type
    count = 0
    for port in egress_ports:
        queue_watermark_str = watermarks[port].get(f"UC{queue}", "N/A").replace(",", "")
        logger.info(f"{watermark_str} for {port}|{queue} is {queue_watermark_str}.")
        pytest_assert(queue_watermark_str.isdigit(),
                      f"Could not get the {watermark_str} for queue {port}|{queue}.")
        count += int(queue_watermark_str)
    logger.info(f"Sum of {watermark_str}s for queue {queue} across egress ports {egress_ports} is {count}.")
    logger.info(f"Expected sum is {expected_value}.")
    if expected_value == 0:
        return count == 0
    else:
        return count >= expected_value


def clear_queue_watermarks(duthost, egress_ports, queue, watermark_type):
    watermark_str = "user-watermark" if watermark_type == "watermark" else watermark_type
    logger.info(f"Clearing queue {watermark_str}s...")
    duthost.shell(f"sudo sonic-clear queue {watermark_type} unicast {get_namespace_option()}")
    pytest_assert(wait_until(WATERMARK_CLEAR_WAIT_TIME, 1, 0, check_queue_watermarks,
                             duthost, egress_ports, queue, watermark_type, expected_value=0),
                  f"{watermark_str}s for queue {queue} across egress ports {egress_ports} were not cleared after " +
                  f"{WATERMARK_CLEAR_WAIT_TIME} seconds.")


def create_congestion(ptfadapter, dest_mac, ip_version, neigh_ip, dscp, ingress_port_index):
    pkt = get_congestion_packet(dest_mac, ip_version, neigh_ip, dscp, pkt_len=PACKET_SIZE)
    logger.info(f"Congestion packet: {pkt}")
    logger.info(f"Sending {PACKET_COUNT} packets of size {PACKET_SIZE} to ingress port {ingress_port_index}...")
    testutils.send(ptfadapter, ingress_port_index, pkt, count=PACKET_COUNT)


@pytest.mark.dualtor_active_standby_toggle_to_upper_tor
@pytest.mark.dualtor_active_active_setup_standby_on_lower_tor
@pytest.mark.parametrize("watermark_type", ["persistent-watermark", "watermark"],
                         ids=["persistent-watermark", "user-watermark"])
def test_queue_watermarks(duthost, ptfadapter, setup, watermark_type):
    """
    This test sends IPv4/IPv6 packets to blocked queues and verifies that persistent/user watermarks
    for those queues are increased as expected. It also checks that watermarks can be cleared using
    the `sonic-clear` command.
    """
    test_params = setup
    egress_ports = test_params["egress_ports"]
    queue_to_dscp = test_params["queue_to_dscp"]
    queues = list(queue_to_dscp.keys())

    for queue in queues:
        clear_queue_watermarks(duthost, egress_ports, queue, watermark_type)

    for queue, dscp in queue_to_dscp.items():
        logger.info(f"Creating congestion in the egress queue {queue} with DSCP {dscp}.")
        create_congestion(ptfadapter, test_params["dest_mac"], test_params["ip_version"],
                          test_params["neigh_ip"], dscp, test_params["ingress_port_index"])

    min_watermark_value = PACKET_COUNT * PACKET_SIZE * (1 - TOLERANCE / 100)
    for queue in queues:
        pytest_assert(wait_until(WATERMARK_UPDATE_WAIT_TIME, 10, 0, check_queue_watermarks,
                                 duthost, egress_ports, queue, watermark_type,
                                 expected_value=min_watermark_value),
                      f"{watermark_type}s for queue {queue} across egress ports " +
                      f"{egress_ports} were not updated correctly after " +
                      f"{WATERMARK_UPDATE_WAIT_TIME} seconds.")
