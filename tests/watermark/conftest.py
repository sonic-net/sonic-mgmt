import pytest
import logging
import time
import ptf.testutils as testutils
import ast
import random

from abc import ABC, abstractmethod

# Renaming "pytest_assert" to avoid the "unknown hook 'pytest_assert'" error.
from tests.common.helpers.assertions import pytest_assert as py_assert
from tests.common.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload
from tests.common.utilities import wait_until


logger = logging.getLogger(__name__)

ASIC_DB_SYNC_TIME = 10
WATERMARK_CLEAR_WAIT_TIME = 5  # Clearing watermarks is relatively fast
WATERMARK_UPDATE_WAIT_TIME = 120  # Updating watermarks can take much longer

# ASIC DB key patterns
SCHEDULER_PATTERN = "ASIC_STATE:SAI_OBJECT_TYPE_SCHEDULER:oid:*"

PACKET_COUNT = 1000
PACKET_SIZE = 128  # total size of each packet in bytes
BLOCKING_SCHEDULER = "SCHEDULER_BLOCK_DATA_PLANE"
# Number of containers (queues/PGs) to randomly select and test for each traffic_type/watermark_type combination.
NUM_CONTAINERS_TO_TEST = 3

# Traffic types the watermark tests are parametrized over.
TRAFFIC_TYPES = ["lossy", "lossless"]

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
def set_sonic_db_cli(set_namespace):
    global sonic_db_cli
    sonic_db_cli = f"sonic-db-cli {get_namespace_option()}"


@pytest.fixture(scope="module")
def minigraph_facts(duthost, tbinfo):
    return duthost.get_extended_minigraph_facts(tbinfo)


@pytest.fixture(scope="module")
def config_facts(duthost):
    return duthost.get_running_config_facts()


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
    py_assert(
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


def collect_dut_all_prio(duthost, config_facts, ports):
    dscp_to_tc_map_lists = config_facts.get("DSCP_TO_TC_MAP")
    if not dscp_to_tc_map_lists:
        return []

    profile = find_qos_mapping_table_name(duthost, ports, "dscp_to_tc_map")
    dscp_to_tc_map = dscp_to_tc_map_lists[profile]

    tc = [int(p) for p in list(dscp_to_tc_map.values())]
    return list(set(tc))


def collect_dut_lossless_prio(config_facts, ports):
    port_qos_map = config_facts.get("PORT_QOS_MAP")
    if not port_qos_map:
        return []

    # lossless_prios will be set to the union of all PFC-enabled priorities across the ports
    lossless_prios = set()
    for port in ports:
        pfc_enable_str = port_qos_map.get(port, {}).get("pfc_enable")
        if pfc_enable_str:
            pfc_enable = pfc_enable_str.split(',')
            lossless_prios.update(int(x) for x in pfc_enable)
    return list(lossless_prios)


def collect_dut_lossy_prio(duthost, config_facts, ports):
    lossless_prio = collect_dut_lossless_prio(config_facts, ports)
    all_prio = collect_dut_all_prio(duthost, config_facts, ports)
    return list(set(all_prio) - set(lossless_prio))


def get_tc_to_container_mapping(duthost, ports, tc_map_name, tc_map_table):
    """
    Get the full mapping from traffic class (TC) to container (queue or priority group).

    Args:
        duthost: The DUT host object.
        ports: Ports whose PORT_QOS_MAP is used to locate the TC-to-container map table.
        tc_map_name: The PORT_QOS_MAP field name of the TC-to-container map (e.g., "tc_to_queue_map").
        tc_map_table: The CONFIG_DB table name of the TC-to-container map (e.g., "TC_TO_QUEUE_MAP").

    Returns:
        A dictionary mapping each TC to its corresponding container.
    """
    tc_to_container_table = find_qos_mapping_table_name(duthost, ports, tc_map_name)
    tc_to_container_str = \
        duthost.shell(f"{sonic_db_cli} CONFIG_DB HGETALL '{tc_map_table}|{tc_to_container_table}'")["stdout"].strip()
    tc_to_container = ast.literal_eval(tc_to_container_str)
    tc_to_container = {int(tc): int(cont) for tc, cont in tc_to_container.items()}
    logger.info(f"TC to container mapping: {tc_to_container}.")
    return tc_to_container


def get_container_to_dscp_mapping(duthost, ingress_port, container_ports, tc_list, tc_map_name, tc_map_table):
    """
    Get the mapping from container (queue or priority group) to DSCP values for the specified traffic classes (TCs).

    Args:
        duthost: The DUT host object.
        ingress_port: The ingress port.
        container_ports: Ports whose PORT_QOS_MAP is used to locate the TC-to-container map table.
        tc_list: List of traffic classes to retrieve the mapping for.
        tc_map_name: The PORT_QOS_MAP field name of the TC-to-container map (e.g., "tc_to_queue_map").
        tc_map_table: The CONFIG_DB table name of the TC-to-container map (e.g., "TC_TO_QUEUE_MAP").

    Returns:
        A dictionary mapping each container to a list of DSCP values that map to that container.
    """
    tc_to_container = get_tc_to_container_mapping(duthost, container_ports, tc_map_name, tc_map_table)
    dscp_to_tc_table = find_qos_mapping_table_name(duthost, [ingress_port], "dscp_to_tc_map")
    dscp_to_tc_map_str = \
        duthost.shell(f"{sonic_db_cli} CONFIG_DB HGETALL 'DSCP_TO_TC_MAP|{dscp_to_tc_table}'")["stdout"].strip()
    dscp_to_tc_map = ast.literal_eval(dscp_to_tc_map_str)
    dscp_to_tc_map = {int(dscp): int(tc) for dscp, tc in dscp_to_tc_map.items() if int(tc) in tc_list}
    container_to_dscp = {}  # Each container will be mapped to a list of DSCP values
    for dscp, tc in dscp_to_tc_map.items():
        container = tc_to_container.get(tc)
        if container is None:
            logger.warning(f"Traffic class {tc} is not mapped to any PG/queue.")
            continue
        container_to_dscp[container] = container_to_dscp.get(container, [])
        container_to_dscp[container].append(dscp)
    return container_to_dscp


def select_random_containers(duthost, ingress_port, container_ports, tc_list, tc_map_name, tc_map_table):
    """
    Returns a dictionary mapping each randomly-selected container (queue or priority group) to a DSCP value
    associated with that container.
    """
    if not tc_list:
        return {}

    container_to_dscp = get_container_to_dscp_mapping(duthost, ingress_port, container_ports, tc_list,
                                                      tc_map_name, tc_map_table)
    containers = list(container_to_dscp.keys())
    if not containers:
        return {}
    selected_containers = random.sample(containers, min(NUM_CONTAINERS_TO_TEST, len(containers)))

    return {container: random.choice(container_to_dscp[container]) for container in selected_containers}


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


def get_egress_queues_for_pgs(duthost, ingress_port, egress_ports, pgs):
    """
    Returns the sorted list of egress queues that carry traffic for the given priority groups (PGs).

    Blocking these queues creates congestion in the shared buffers of those PGs on the ingress port. Each PG
    is mapped back to the traffic classes that use it (via the ingress port's TC-to-PG map), and each such
    traffic class is mapped to its egress queue (via the egress ports' TC-to-queue map).
    """
    tc_to_pg = get_tc_to_container_mapping(duthost, [ingress_port], "tc_to_pg_map", "TC_TO_PRIORITY_GROUP_MAP")
    tc_to_queue = get_tc_to_container_mapping(duthost, egress_ports, "tc_to_queue_map", "TC_TO_QUEUE_MAP")
    queues = set()
    for tc, pg in tc_to_pg.items():
        if pg in pgs and tc in tc_to_queue:
            queues.add(tc_to_queue[tc])
    logger.info(f"Egress queues associated with PGs {pgs}: {queues}.")
    return list(queues)


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


def create_congestion(ptfadapter, dest_mac, ip_version, neigh_ip, dscp, ingress_port_index):
    pkt = get_congestion_packet(dest_mac, ip_version, neigh_ip, dscp, pkt_len=PACKET_SIZE)
    logger.info(f"Congestion packet: {pkt}")
    logger.info(f"Sending {PACKET_COUNT} packets of size {PACKET_SIZE} to ingress port {ingress_port_index}...")
    testutils.send(ptfadapter, ingress_port_index, pkt, count=PACKET_COUNT)


def get_watermarks(duthost, watermark_type, container, subtype):
    """
    Get watermarks for all ports and containers (queues or priority groups).
    """
    watermarks_list_str = \
        duthost.shell(f"show {container} {watermark_type} {subtype} {get_namespace_option()} --json")["stdout"].strip()
    watermarks_list = ast.literal_eval(watermarks_list_str)
    # watermarks_list is a list of dictionaries, each representing the watermarks for a single port. Example
    # (for unicast queues; for shared priority groups the "UC<n>" keys are "PG<n>" instead):
    # [
    #   {
    #       "Port": "Ethernet0",
    #       "UC0": "0",
    #       "UC1": "0",
    #       ...
    #       "UC7": "0"
    #   },
    #   {
    #       "Port": "Ethernet4",
    #       "UC0": "0",
    #       "UC1": "0",
    #       ...
    #       "UC7": "0"
    #   }
    # ]
    watermarks = {}
    for port_watermarks in watermarks_list:
        port = port_watermarks.pop("Port")
        watermarks[port] = port_watermarks
    return watermarks


def check_watermarks(duthost, ports, container_id, watermark_type, container, subtype, column_prefix,
                     expected_value):
    watermarks = get_watermarks(duthost, watermark_type, container, subtype)
    watermark_str = "user-watermark" if watermark_type == "watermark" else watermark_type
    count = 0
    for port in ports:
        watermark_val_str = watermarks[port].get(f"{column_prefix}{container_id}", "N/A").replace(",", "")
        logger.info(f"{watermark_str} for {port}|{column_prefix}{container_id} is {watermark_val_str}.")
        py_assert(watermark_val_str.isdigit(),
                  f"Could not get the {watermark_str} for {port}|{column_prefix}{container_id}.")
        count += int(watermark_val_str)
    logger.info(f"Sum of {watermark_str}s for {column_prefix}{container_id} across ports "
                f"{ports} is {count}.")
    logger.info(f"Expected sum is {expected_value}.")
    if expected_value == 0:
        return count == 0
    else:
        return count >= expected_value


def clear_watermarks(duthost, ports, container_id, watermark_type, container, subtype, column_prefix):
    watermark_str = "user-watermark" if watermark_type == "watermark" else watermark_type
    logger.info(f"Clearing {container} {watermark_str}s...")
    duthost.shell(f"sudo sonic-clear {container} {watermark_type} {subtype} {get_namespace_option()}")
    py_assert(wait_until(WATERMARK_CLEAR_WAIT_TIME, 1, 0, check_watermarks,
                         duthost, ports, container_id, watermark_type, container, subtype, column_prefix,
                         expected_value=0),
              f"{watermark_str}s for {column_prefix}{container_id} across ports {ports} were not " +
              f"cleared after {WATERMARK_CLEAR_WAIT_TIME} seconds.")


def run_watermark_test(duthost, ptfadapter, test_params, watermark_type, container, subtype, column_prefix, tolerance):
    """
    Sends IPv4/IPv6 packets to blocked queues and verifies that the persistent/user watermarks for the
    corresponding containers (queues or priority groups) are increased as expected. It also checks that the
    watermarks can be cleared using the `sonic-clear` command.
    """
    ports = test_params["watermark_ports"]
    container_to_dscp = test_params["container_to_dscp"]
    containers = list(container_to_dscp.keys())

    for container_id in containers:
        clear_watermarks(duthost, ports, container_id, watermark_type, container, subtype, column_prefix)

    for container_id, dscp in container_to_dscp.items():
        logger.info(f"Creating congestion in {column_prefix}{container_id} with DSCP {dscp}.")
        create_congestion(ptfadapter, test_params["dest_mac"], test_params["ip_version"],
                          test_params["neigh_ip"], dscp, test_params["ingress_port_index"])

    min_watermark_value = PACKET_COUNT * PACKET_SIZE * (1 - tolerance / 100)
    for container_id in containers:
        py_assert(wait_until(WATERMARK_UPDATE_WAIT_TIME, 10, 0, check_watermarks,
                             duthost, ports, container_id, watermark_type, container, subtype,
                             column_prefix, expected_value=min_watermark_value),
                  f"{watermark_type}s for {column_prefix}{container_id} across ports " +
                  f"{ports} were not updated correctly after " +
                  f"{WATERMARK_UPDATE_WAIT_TIME} seconds.")


class WatermarkTestBase(ABC):
    """
    Base class for the queue and PG watermark tests. Concrete subclasses set the container-specific class
    attributes and the IP version (IPv4/IPv6 are split into separate subclasses).

    The expensive, read-only setup is done in module- and class-scoped fixtures so that it is not repeated
    for every parameter combination:
      - `minigraph_facts` and `config_facts` (module-scoped) are collected once per test module.
      - `egress_interface`, `ingress_port`, and `tc_lists` (class-scoped) are computed once per IP version.
    Only the container selection and blocking-scheduler application (which depend on the traffic type) are
    done per traffic type, and they are shared across the two watermark types via the class-scoped `setup`.
    """
    # These are overridden by the concrete subclasses.
    IP_VERSION = None
    CONTAINER = None
    SUBTYPE = None
    COLUMN_PREFIX = None
    TC_MAP_NAME = None
    TC_MAP_TABLE = None
    # Percentage tolerance for the watermark values (meaning that watermark values after sending all of the
    # congestion packets should be at most TOLERANCE% less than the number of bytes sent).
    TOLERANCE = None

    @abstractmethod
    def get_container_ports(self, ingress_port, egress_ports):
        """
        Returns one of the two arguments based on the container type.
        """
        raise NotImplementedError()

    @abstractmethod
    def get_queues_to_block(self, container_ids, duthost, ingress_port, egress_ports):
        """
        Returns the list of queues to block for the given container IDs.
        """
        raise NotImplementedError()

    @pytest.fixture(scope="class")
    def egress_interface(self, duthost, minigraph_facts):
        """Returns (neigh_ip, egress_ports). Selected once per class since it depends only on the IP version."""
        return select_egress_interface(duthost, minigraph_facts, ipv4=(self.IP_VERSION == "ipv4"))

    @pytest.fixture(scope="class")
    def ingress_port(self, duthost, egress_interface):
        _, egress_ports = egress_interface
        return select_ingress_port(duthost, exclude_ports=egress_ports)

    @pytest.fixture(scope="class")
    def tc_lists(self, duthost, config_facts, ingress_port):
        """Lossy/lossless traffic classes for the ingress port. Collected once per class."""
        return {
            "lossless": collect_dut_lossless_prio(config_facts, [ingress_port]),
            "lossy": collect_dut_lossy_prio(duthost, config_facts, [ingress_port]),
        }

    @pytest.fixture(scope="class", params=TRAFFIC_TYPES)
    def setup(self, request, duthost, tbinfo, minigraph_facts, egress_interface, ingress_port, tc_lists,
              create_blocking_scheduler):
        traffic_type = request.param
        ptf_indices = minigraph_facts["minigraph_ptf_indices"]
        neigh_ip, egress_ports = egress_interface

        # Queues are associated with egress ports; PGs are associated with the ingress port.
        container_ports = self.get_container_ports(ingress_port, egress_ports)
        container_to_dscp = select_random_containers(duthost, ingress_port, container_ports,
                                                     tc_lists[traffic_type], self.TC_MAP_NAME, self.TC_MAP_TABLE)
        if not container_to_dscp:
            pytest.skip(f"No {traffic_type} PG/queue found on DUT.")

        # The blocking scheduler is always applied to egress queues. If containers are PGs,
        # the blocking scheduler is applied to the egress queue(s) associated with those PGs.
        queues_to_block = self.get_queues_to_block(container_to_dscp.keys(), duthost, ingress_port, egress_ports)
        if not queues_to_block:
            pytest.skip(f"No queues associated with these priorities: {tc_lists[traffic_type]}.")
        apply_blocking_scheduler(duthost, egress_ports, queues_to_block)

        # On t0/dualtor the ingress port may be a VLAN member, in which case the congestion packet must be
        # addressed to the VLAN SVI MAC (the L3 termination MAC) to be routed to the egress queue rather
        # than flooded in the VLAN.
        router_mac = duthost.facts["router_mac"]
        test_params = {
            "ip_version": self.IP_VERSION,
            "neigh_ip": neigh_ip,
            "ingress_port_index": ptf_indices[ingress_port],
            "container_to_dscp": container_to_dscp,
            # Watermarks for queues are read on the egress ports; watermarks for PGs are read on the ingress port.
            "watermark_ports": container_ports,
            "dest_mac": get_dest_mac(duthost, tbinfo, minigraph_facts, ingress_port, router_mac),
        }
        logger.info(f"Test parameters: {test_params}")
        return test_params

    @pytest.mark.dualtor_active_standby_toggle_to_upper_tor
    @pytest.mark.dualtor_active_active_setup_standby_on_lower_tor
    @pytest.mark.parametrize("watermark_type", ["persistent-watermark", "watermark"],
                             ids=["persistent-watermark", "user-watermark"])
    def test_watermarks(self, duthost, ptfadapter, setup, watermark_type):
        """
        Sends IPv4/IPv6 packets to blocked queues and verifies that the persistent/user watermarks for the
        corresponding containers (queues or priority groups) are increased as expected. It also checks that
        the watermarks can be cleared using the `sonic-clear` command.
        """
        run_watermark_test(duthost, ptfadapter, setup, watermark_type,
                           self.CONTAINER, self.SUBTYPE, self.COLUMN_PREFIX, self.TOLERANCE)
