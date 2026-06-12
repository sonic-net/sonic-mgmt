import pytest
import logging
import time
import ptf.testutils as testutils
import ast
import random

from tests.common.helpers.assertions import pytest_assert
from tests.common.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload
from tests.common.utilities import wait_until
from tests.conftest import generate_priority_lists


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


def find_qos_mapping_table_name(duthost, egress_ports, qos_mapping):
    qos_table_name = ""
    for port in egress_ports:
        table = duthost.shell(f"{sonic_db_cli} CONFIG_DB HGET 'PORT_QOS_MAP|{port}' '{qos_mapping}'")["stdout"].strip()
        if not table:
            continue
        if qos_table_name and qos_table_name != table:
            pytest.fail(f"{qos_mapping} is not the same for all egress ports {egress_ports}.")
        qos_table_name = table
    if not qos_table_name:
        # Check the global table
        table = duthost.shell(f"{sonic_db_cli} CONFIG_DB HGET 'PORT_QOS_MAP|global' '{qos_mapping}'")["stdout"].strip()
        if not table:
            pytest.fail(f"{qos_mapping} is not defined for any egress port {egress_ports} or globally.")
        qos_table_name = table
    return qos_table_name


def find_reverse_qos_mapping(duthost, egress_ports, qos_mapping, value_to_find):
    qos_table = find_qos_mapping_table_name(duthost, egress_ports, qos_mapping)
    qos_map_str = \
        duthost.shell(f"{sonic_db_cli} CONFIG_DB HGETALL '{qos_mapping.upper()}|{qos_table}'")["stdout"].strip()
    qos_map = ast.literal_eval(qos_map_str)
    for key, value in qos_map.items():
        if int(value) == value_to_find:
            return int(key)
    pytest.fail(f"Could not find a key mapped to value {value_to_find} in {qos_mapping.upper()}|{qos_table}.")


def find_tc_for_queue(duthost, egress_ports, queue):
    tc = find_reverse_qos_mapping(duthost, egress_ports, "tc_to_queue_map", queue)
    logger.info(f"The traffic class '{tc}' is mapped to queue '{queue}' for egress ports {egress_ports}.")
    return tc


def find_dscp_for_queue(duthost, egress_ports, queue):
    tc = find_tc_for_queue(duthost, egress_ports, queue)
    dscp = find_reverse_qos_mapping(duthost, egress_ports, "dscp_to_tc_map", tc)
    logger.info(f"The DSCP value '{dscp}' is mapped to traffic class '{tc}' for egress ports {egress_ports}.")
    return dscp


def select_random_queue(request, queue_type, default_queue=None):
    queue_list = generate_priority_lists(request, queue_type)
    queue_list = [int(x.split("|")[1]) for x in queue_list]
    if not queue_list:
        return default_queue
    elif len(queue_list) == 1:
        return queue_list[0]
    else:
        return random.choice(queue_list)


def apply_blocking_scheduler(duthost, egress_ports, queue):
    """
    For each egress port, sets the scheduler of the specified queue to the blocking scheduler.
    """
    for port in egress_ports:
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
    default_queue = 0 if queue_type == "lossy" else None
    queue = select_random_queue(request, queue_type, default_queue)

    test_params = {}
    test_params["ip_version"] = request.param[0]
    test_params["queue"] = queue
    if test_params["queue"] is None:
        pytest.skip(f"No {queue_type} queue found on DUT.")
    neigh_ip, egress_ports = select_egress_interface(duthost, minigraph_facts,
                                                     ipv4=(ip_version == "ipv4"))
    test_params["neigh_ip"] = neigh_ip
    test_params["egress_ports"] = egress_ports
    ingress_port = select_ingress_port(duthost, exclude_ports=egress_ports)
    test_params["ingress_port_index"] = ptf_indices[ingress_port]
    test_params["dscp"] = find_dscp_for_queue(duthost, egress_ports, queue)

    # Apply the blocking scheduler to the queue (for each egress port)
    apply_blocking_scheduler(duthost, egress_ports, queue)

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


def get_watermarks(duthost, watermark_type):
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
    watermarks = get_watermarks(duthost, watermark_type)
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


def create_congestion(ptfadapter, router_mac, ip_version, neigh_ip, dscp, ingress_port_index):
    logger.info("Creating congestion in the egress queue.")
    pkt = get_congestion_packet(router_mac, ip_version, neigh_ip, dscp, pkt_len=PACKET_SIZE)
    logger.info(f"Congestion packet: {pkt}")
    logger.info(f"Sending {PACKET_COUNT} packets of size {PACKET_SIZE} to ingress port {ingress_port_index}...")
    testutils.send(ptfadapter, ingress_port_index, pkt, count=PACKET_COUNT)


@pytest.mark.parametrize("watermark_type", ["persistent-watermark", "watermark"],
                         ids=["persistent-watermark", "user-watermark"])
def test_queue_watermarks(duthost, ptfadapter, setup, watermark_type):
    """
    This test sends IPv4/IPv6 packets to a blocked queue and verifies that persistent/user watermarks
    for that queue are increased as expected. It also checks that watermarks can be cleared using
    the `sonic-clear` command.
    """
    test_params = setup
    router_mac = duthost.facts["router_mac"]
    clear_queue_watermarks(duthost, test_params["egress_ports"], test_params["queue"], watermark_type)
    create_congestion(ptfadapter, router_mac, test_params["ip_version"], test_params["neigh_ip"],
                      test_params["dscp"], test_params["ingress_port_index"])
    min_watermark_value = PACKET_COUNT * PACKET_SIZE * (1 - TOLERANCE / 100)
    pytest_assert(wait_until(WATERMARK_UPDATE_WAIT_TIME, 10, 0, check_queue_watermarks,
                             duthost, test_params["egress_ports"], test_params["queue"],
                             watermark_type, expected_value=min_watermark_value),
                  f"{watermark_type}s for queue {test_params['queue']} across egress ports " +
                  f"{test_params['egress_ports']} were not updated correctly after " +
                  f"{WATERMARK_UPDATE_WAIT_TIME} seconds.")
