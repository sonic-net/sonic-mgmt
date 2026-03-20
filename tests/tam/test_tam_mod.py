import json
import logging
import pytest
import ptf.testutils as testutils
from scapy.all import Ether, IP, UDP, TCP, Raw, IPv6
import time
import threading
import re
import copy

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until, get_dscp_to_queue_value
from tests.common import config_reload
from ipfix_common import IPFIXHeader, PsampModHeader
from tests.packet_trimming.packet_trimming_helper import (
    create_blocking_scheduler,
    ConfigTrimming,
    get_interface_peer_addresses,
    get_queue_trim_counters_json
)
from tests.packet_trimming.constants import DEFAULT_DSCP

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("t1"),
]

TAM_ASICDB_TIMEOUT = 180
TAM_ASICDB_INTERVAL = 10

IP_PROTOCOL_TCP = "6"
IP_PROTOCOL_UDP = "17"

# IP family specific collector configurations
TAM_COLLECTOR_IPV4 = {
    "src_ip": "11.22.33.44",
    "dst_ip": "10.20.30.40",
}

TAM_COLLECTOR_IPV6 = {
    "src_ip": "2001:db8:1::44",
    "dst_ip": "2001:db8:2::40",
}

# TAM Mirror on Drop configuration template
# Note: ports will be dynamically populated in the fixture
# IP addresses will be set based on ip_family parameter
TAM_MOD_CONFIG_TEMPLATE = {
    "TAM": {
        "device": {
            "device-id": "12345",
            "enterprise-id": "54321",
        }
    },
    "TAM_COLLECTOR": {
        "COLLECTOR1": {
            "src_ip": "",  # Will be set based on IP family
            "dst_ip": "",  # Will be set based on IP family
            "dst_port": "10000",
            "dscp_value": "32",
            "vrf": "default"
        }
    },
    "TAM_SESSION": {
        "DROPMONITOR": {
            "type": "drop-monitor",
            "report_type": "ipfix",
            "collector": ["COLLECTOR1"]
        }
    }
}


MATCHED_FLOWS = [
    ("10.1.1.0/24", "20.2.2.0/24", IP_PROTOCOL_TCP, "1000", "80"),
]


MATCHED_FLOWS_IPV6 = [
    ("2000:10:1:1::0/120", "2000:20:2:2::0/120", IP_PROTOCOL_TCP, "1000", "80"),
]


UNMATCHED_FLOWS = [
    ("100.1.1.1", "101.2.2.2", IP_PROTOCOL_TCP, "1001", "81"),
    ("101.3.3.3", "101.4.4.4", IP_PROTOCOL_UDP, "5001", "6001")
]


UNMATCHED_FLOWS_IPV6 = [
    ("2001:10:1:1::100/120", "2001:20:2:2::100/120", IP_PROTOCOL_TCP, "1000", "80"),
]


def tam_asicdb_state(duthost, shouldExist):
    """
    Verify that ASIC_DB contains all required TAM objects:
    - TAM_TRANSPORT
    - TAM_COLLECTOR
    - TAM_EVENT
    - TAM_EVENT_ACTION
    - TAM_REPORT
    - TAM

    Returns:
        bool: True if all required TAM objects are present, False otherwise
    """
    required_tam_objects = [
        "TAM_TRANSPORT",
        "TAM_COLLECTOR",
        "TAM_EVENT",
        "TAM_EVENT_ACTION",
        "TAM_REPORT",
        "TAM"
    ]

    for tam_object in required_tam_objects:
        out = duthost.shell(f'sonic-db-cli ASIC_DB KEYS "*{tam_object}:oid:*"')  # noqa: E231
        lines = out.get("stdout_lines", [])
        if shouldExist and not lines:
            logger.warning(f"ASIC_DB missing {tam_object} objects")
            return False
        elif not shouldExist and lines:
            logger.debug(f"ASIC_DB has {tam_object} objects: {lines}")
            return False

    logger.info("ASIC_DB has expected state")
    return True


def wait_for_tam_asicdb_applied(duthost, timeout=TAM_ASICDB_TIMEOUT, interval=TAM_ASICDB_INTERVAL):
    """
    Wait for TAM configuration to be applied to ASIC_DB.

    Verifies that all required TAM objects are present:
    - TAM_TRANSPORT
    - TAM_COLLECTOR
    - TAM_EVENT
    - TAM_EVENT_ACTION
    - TAM_REPORT
    - TAM

    Args:
        duthost: DUT host object
        timeout: Maximum time to wait in seconds
        interval: Check interval in seconds

    Returns:
        bool: True if all TAM objects are present within timeout, False otherwise
    """
    return wait_until(timeout, interval, 0, lambda: tam_asicdb_state(duthost, True))


def verify_tam_mod_config_applied(duthost, ip_family, flow_aware):
    """
    Verify that TAM Mirror on Drop config has been applied:
    - CONFIG_DB contains TAM tables with expected fields
    - ASIC_DB contains TAM-related SAI objects
    """
    # Check TAM device config
    show = duthost.shell('sonic-db-cli CONFIG_DB HGETALL "TAM|device"', module_ignore_errors=False)
    lines = show.get("stdout_lines", []) or []
    pytest_assert(lines, "CONFIG_DB: TAM|device not found or empty")

    # Check TAM collector config
    show = duthost.shell('sonic-db-cli CONFIG_DB HGETALL "TAM_COLLECTOR|COLLECTOR1"', module_ignore_errors=False)
    lines = show.get("stdout_lines", []) or []
    pytest_assert(lines, "CONFIG_DB: TAM_COLLECTOR|COLLECTOR1 not found or empty")

    # Check TAM session config
    show = duthost.shell('sonic-db-cli CONFIG_DB HGETALL "TAM_SESSION|DROPMONITOR"', module_ignore_errors=False)
    lines = show.get("stdout_lines", []) or []
    pytest_assert(lines, "CONFIG_DB: TAM_SESSION|DROPMONITOR not found or empty")

    if flow_aware:
        # Check TAM flow group config
        show = duthost.shell('sonic-db-cli CONFIG_DB HGETALL "TAM_FLOW_GROUP|FG1"', module_ignore_errors=False)
        lines = show.get("stdout_lines", []) or []
        pytest_assert(lines, "CONFIG_DB: TAM_FLOW_GROUP|FG1 not found or empty")
        # Only IPv4 is supported for flow aware at this moment
        num_flow_rules = len(MATCHED_FLOWS)
        for idx in range(1, num_flow_rules + 1):
            rule_key = f"FG1|RULE{idx}"
            show = duthost.shell(f'sonic-db-cli CONFIG_DB HGETALL "TAM_FLOW_GROUP|{rule_key}"',
                                 module_ignore_errors=False)
            lines = show.get("stdout_lines", []) or []
            pytest_assert(lines, f"CONFIG_DB: TAM_FLOW_GROUP|{rule_key} not found or empty")

    # Ensure orchagent applied TAM config into ASIC_DB
    pytest_assert(
        wait_for_tam_asicdb_applied(duthost, TAM_ASICDB_TIMEOUT, TAM_ASICDB_INTERVAL),
        "ASIC_DB missing TAM keys; orchagent may not have processed TAM config.",
    )


def _get_blackhole_commands(ip_family, collector_dst_ip):
    """
    Get blackhole route add and remove commands for the given IP family.

    Args:
        ip_family: "ipv4" or "ipv6"
        collector_dst_ip: Collector destination IP address

    Returns:
        tuple: (blackhole_cmd, remove_blackhole_cmd)
    """
    if ip_family == "ipv4":
        blackhole_cmd = (f"vtysh -c 'configure terminal' "
                        f"-c 'ip route {collector_dst_ip}/32 blackhole'")  # noqa: E128
        remove_blackhole_cmd = (f"vtysh -c 'configure terminal' "
                               f"-c 'no ip route {collector_dst_ip}/32 blackhole'")  # noqa: E128
    else:  # ipv6
        blackhole_cmd = (f"vtysh -c 'configure terminal' "
                        f"-c 'ipv6 route {collector_dst_ip}/128 blackhole'")  # noqa: E128
        remove_blackhole_cmd = (f"vtysh -c 'configure terminal' "
                               f"-c 'no ipv6 route {collector_dst_ip}/128 blackhole'")  # noqa: E128
    return blackhole_cmd, remove_blackhole_cmd


@pytest.fixture(scope="module", params=["ipv4", "ipv6"], ids=["IPv4_collector", "IPv6_collector",])
def ip_family_param(request):
    return request.param


@pytest.fixture(scope="module", params=[False, True], ids=["flow_unaware", "flow_aware",])
def flow_aware_param(request):
    return request.param


@pytest.fixture(scope="module")
def tam_mod_config(ip_family_param, flow_aware_param, duthosts, rand_one_dut_hostname, tbinfo):
    """
    Apply TAM Mirror on Drop config with dynamically selected ports and clean up after.

    This fixture:
    1. Applies TAM Mirror on Drop configuration with dynamically selected ports
    2. Verifies TAM config is applied to both CONFIG_DB and ASIC_DB
    3. Cleans up TAM configurations after test completes

    Parametrized to run with both IPv4 and IPv6 collector configurations.

    Returns:
        tuple: (duthost, ingress_ports, collector_ports, ip_family) where:
            - duthost: DUT host object
            - ingress_ports: dict of {port_name: ptf_index} for ingress traffic
            - collector_ports: list of PTF indices where collector is reachable
            - ip_family: str, either "ipv4" or "ipv6"
    """
    duthost = duthosts[rand_one_dut_hostname]

    ip_family = ip_family_param
    flow_aware = flow_aware_param

    logger.info(f"Setting up TAM MoD configuration with {ip_family.upper()} collector")

    # Get available ports
    logger.info("Discovering available ports...")
    available_ports = _get_available_ports(duthost, tbinfo)
    logger.info(f"Available ports: {available_ports}")

    # Select ingress ports (can be any available ports)
    ingress_port_names = list(available_ports.keys())
    logger.info(f"Selected ingress ports: {ingress_port_names}")

    ingress_port = (ingress_port_names[0], available_ports[ingress_port_names[0]])

    # Create and apply TAM config with selected ports and IP family
    logger.info(f"Applying TAM Mirror on Drop configuration with {ip_family.upper()} addresses...")
    tam_config = _get_tam_config(ip_family, ingress_port[0], flow_aware)

    # Get collector egress ports based on routing
    collector_config = _get_collector_config(tam_config)
    collector_ports = _get_collector_egress_ports(duthost, collector_config["dst_ip"], available_ports, ip_family)
    logger.info(f"Collector reachable on PTF ports: {collector_ports}")

    # Apply config to CONFIG_DB using sonic-cfggen
    tam_cfg_path = "/tmp/tam_mod_config.json"
    duthost.copy(content=json.dumps(tam_config, indent=2), dest=tam_cfg_path)
    res = duthost.shell(f"sonic-cfggen -j {tam_cfg_path} --write-to-db")
    pytest_assert(res["rc"] == 0, f"Failed to apply TAM MoD config: {res}")

    # Verify TAM config is applied to both CONFIG_DB and ASIC_DB
    verify_tam_mod_config_applied(duthost, ip_family, flow_aware)

    # Build ingress_ports dict for test: map port/LAG names to individual PTF indices
    # For LAGs, we need to expand to individual member ports for packet injection
    ingress_ports_for_test = {}
    for port_name in ingress_port_names:
        port_value = available_ports[port_name]
        if isinstance(port_value, list):
            # LAG: map LAG name to list of member PTF indices
            ingress_ports_for_test[port_name] = port_value
        else:
            # Individual port: map port name to PTF index
            ingress_ports_for_test[port_name] = port_value

    yield duthost, ingress_port, collector_ports, collector_config, ip_family, flow_aware

    # Remove blackhole route if it was added during test
    collector_dst_ip = collector_config["dst_ip"]
    _, remove_blackhole_cmd = _get_blackhole_commands(ip_family, collector_dst_ip)

    logger.info(f"Removing any blackhole routes for {ip_family.upper()} collector IP: {collector_dst_ip}")
    duthost.shell(remove_blackhole_cmd, module_ignore_errors=True)

    # Remove TAM configurations from CONFIG_DB
    logger.info(f"Cleaning up TAM configurations for {ip_family.upper()}...")
    duthost.shell('sonic-db-cli CONFIG_DB DEL "TAM|device"', module_ignore_errors=True)
    duthost.shell('sonic-db-cli CONFIG_DB DEL "TAM_COLLECTOR|COLLECTOR1"', module_ignore_errors=True)
    duthost.shell('sonic-db-cli CONFIG_DB DEL "TAM_SESSION|DROPMONITOR"', module_ignore_errors=True)

    # Wait for ASIC_DB to be cleaned up
    cleanup_result = wait_until(TAM_ASICDB_TIMEOUT, TAM_ASICDB_INTERVAL, 0,
                                lambda: tam_asicdb_state(duthost, False))

    # TODO - There is a known bug where, after TAM config is added and deleted 8 times,
    # the config fails on the 9th time.  Since we are doing multiple tests here, doing
    # a config_reload before starting the new test so that we don't run into that known
    # issue.
    config_reload(duthost, safe_reload=True, check_intf_up_ports=True, wait_for_bgp=True)

    if cleanup_result:
        logger.info(f"TAM cleanup completed {ip_family.upper()}")
    else:
        pytest.fail(f"TAM cleanup failed for {ip_family.upper()}: ASIC_DB still has some TAM keys")


def _get_available_ports(duthost, tbinfo):
    """
    Get all available front-panel ports that are admin up, handling LAGs.

    If a port is part of a LAG, returns the LAG name instead of individual member ports.
    Returns a dict where keys are either port names or LAG names, and values are either
    PTF indices (for individual ports) or lists of PTF indices (for LAGs).

    Returns:
        dict: Mapping of port/LAG name to PTF index or list of indices
              e.g., {"Ethernet0": 0, "Ethernet4": 1, "PortChannel0": [2, 3], ...}
    """
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']

    # Get ports that are admin up
    admin_up_ports = {k: v for k, v in list(cfg_facts['PORT'].items())
                      if v.get('admin_status', 'down') == 'up'}

    # Get LAG member ports
    config_portchannels = cfg_facts.get('PORTCHANNEL_MEMBER', {})
    lag_member_ports = set()
    lag_members_map = {}  # Map LAG name to list of member ports

    for lag_name, members in config_portchannels.items():
        member_list = list(members.keys())
        lag_members_map[lag_name] = member_list
        lag_member_ports.update(member_list)

    # Build available ports dict
    available_ports = {}

    # Add LAGs (with their member PTF indices)
    for lag_name, member_ports in lag_members_map.items():
        # Check if all members are admin up
        if all(port in admin_up_ports for port in member_ports):
            # Get PTF indices for all members
            ptf_indices = [mg_facts['minigraph_ptf_indices'][port]
                           for port in member_ports
                           if port in mg_facts['minigraph_ptf_indices']]
            if ptf_indices:
                available_ports[lag_name] = ptf_indices
                logger.info(f"Added LAG {lag_name} with member PTF indices: {ptf_indices}")

    # Add individual ports that are NOT LAG members
    for port in admin_up_ports.keys():
        if port not in lag_member_ports and port in mg_facts['minigraph_ptf_indices']:
            available_ports[port] = mg_facts['minigraph_ptf_indices'][port]
            logger.info(f"Added individual port {port} with PTF index: {available_ports[port]}")

    pytest_assert(len(available_ports) > 0, "No available front-panel ports found")
    return available_ports


def _get_collector_egress_ports(duthost, collector_ip, available_ports, ip_family="ipv4"):
    """
    Get the egress ports where collector is reachable.
    Uses 'ip route get <collector-ip> fibmatch' to determine all egress interface(s).
    This command returns all ECMP paths to the destination.

    Handles LAGs by expanding them to individual member ports for collection.

    Args:
        duthost: DUT host object
        collector_ip: Collector IP address (string)
        available_ports: Dict of available ports {port_name: ptf_index or [ptf_indices]}
        ip_family: IP family ("ipv4" or "ipv6")

    Returns:
        list: List of individual PTF port indices where collector is reachable
    """
    try:
        # Use 'ip route get <ip> fibmatch' to get all ECMP paths
        # For IPv6, use 'ip -6 route get'
        if ip_family == "ipv6":
            cmd = f"ip -6 route get {collector_ip} fibmatch"
        else:
            cmd = f"ip route get {collector_ip} fibmatch"
        result = duthost.shell(cmd, module_ignore_errors=True)

        if result["rc"] != 0:
            logger.warning(
                f"Failed to get route for {collector_ip}: {result.get('stderr', '')}, using all available ports")
            return _flatten_port_indices(available_ports)

        route_lines = result.get("stdout_lines", [])
        if not route_lines:
            logger.warning(f"No route found for {collector_ip}, using all available ports")
            return _flatten_port_indices(available_ports)

        logger.info(f"Route output for {collector_ip}:\n{chr(10).join(route_lines)}")  # noqa: E231

        # Parse the output to extract interfaces
        # Example output:
        # 2.2.2.2 via 10.0.0.1 dev PortChannel0001 table 0 src 10.1.0.32 uid 0
        # 2.2.2.2 via 10.0.0.2 dev PortChannel0002 table 0 src 10.1.0.32 uid 0
        # 2.2.2.2 via 10.0.0.3 dev PortChannel0003 table 0 src 10.1.0.32 uid 0

        egress_ports = []
        seen_interfaces = set()

        for line in route_lines:
            # Match pattern: "... dev <interface> ..."
            match = re.search(r'\bdev\s+(\S+)', line)
            if match:
                interface = match.group(1)
                # Avoid duplicates
                if interface not in seen_interfaces and interface in available_ports:
                    port_value = available_ports[interface]
                    # If it's a LAG (list of indices), add all member indices
                    if isinstance(port_value, list):
                        egress_ports.extend(port_value)
                        logger.info(f"Collector reachable via LAG {interface} (PTF ports {port_value})")
                    else:
                        egress_ports.append(port_value)
                        logger.info(f"Collector reachable via {interface} (PTF port {port_value})")
                    seen_interfaces.add(interface)

        if egress_ports:
            return egress_ports
        else:
            logger.warning(f"No available ports found in route for {collector_ip}, using all available ports")
            return _flatten_port_indices(available_ports)

    except Exception as e:
        logger.warning(f"Failed to get route info for {collector_ip}: {e}, using all available ports")
        return _flatten_port_indices(available_ports)


def _flatten_port_indices(available_ports):
    """
    Flatten available_ports dict to a list of individual PTF indices.

    Handles both individual ports (int values) and LAGs (list values).

    Args:
        available_ports: Dict of {port_name: ptf_index or [ptf_indices]}

    Returns:
        list: Flattened list of all PTF indices
    """
    flattened = []
    for port_value in available_ports.values():
        if isinstance(port_value, list):
            flattened.extend(port_value)
        else:
            flattened.append(port_value)
    return flattened


def _get_router_mac(duthost):
    out = duthost.shell("sonic-db-cli CONFIG_DB HGET 'DEVICE_METADATA|localhost' mac")
    pytest_assert(out["rc"] == 0 and out["stdout"], "Failed to read DUT router MAC")
    return out["stdout"].strip().lower()


def _get_collector_config(tam_config):
    """Get collector config from the TAM config template with proper type conversion."""
    config = tam_config["TAM_COLLECTOR"]["COLLECTOR1"].copy()
    config["dst_port"] = int(config["dst_port"])
    config["dscp_value"] = int(config["dscp_value"])
    return config


class PacketTest:
    def __init__(self, ptfadapter, ptf_ingress_port, collector, router_mac, ip_family,
                 drop_stage="ingress", flow_aware=False, expected_flows=None,
                 unexpected_flows=None):
        self.ptfadapter = ptfadapter
        self.ptf_ingress_port = ptf_ingress_port
        self.collector = collector
        self.router_mac = router_mac
        self.ip_family = ip_family
        self.drop_stage = drop_stage
        self.flow_aware = flow_aware
        self.num_packets = 10 if drop_stage == "ingress" else 10000
        self.expected_flows = expected_flows or []
        self.unexpected_flows = unexpected_flows or []

    def _is_ipv4(self):
        return self.ip_family == "ipv4"

    def _build_packet(self, ptfadapter, router_mac, ptf_src_port,
                      src_ip, dst_ip, ip_protocol, l4_src_port,
                      l4_dst_port):
        """
        TTL=1 ensures packet will be dropped due to TTL expiry during forwarding.
        """
        is_ipv4 = self._is_ipv4()
        src_mac = ptfadapter.dataplane.get_mac(0, ptf_src_port)

        # Create packet with TTL=1
        if self.drop_stage == "ingress":
            ip = IP(src=src_ip, dst=dst_ip, ttl=1) if is_ipv4 \
                else IPv6(src=src_ip, dst=dst_ip, hlim=1)
            payload = Raw(b"TTL expiry test packet for MoD V4") if is_ipv4 \
                else Raw(b"TTL expiry test packet for MoD V6")
        elif self.drop_stage == "mmu":
            ip = IP(src=src_ip, dst=dst_ip, tos=DEFAULT_DSCP << 2) if is_ipv4 \
                else IPv6(src=src_ip, dst=dst_ip, tc=DEFAULT_DSCP << 2)
            payload = Raw(b"Packet"*1000)
        else:
            pytest_assert(False, f"Unsupported drop type: {self.drop_stage}")

        if ip_protocol == IP_PROTOCOL_TCP:
            l4 = TCP(sport=int(l4_src_port), dport=int(l4_dst_port))
        elif ip_protocol == IP_PROTOCOL_UDP:
            l4 = UDP(sport=int(l4_src_port), dport=int(l4_dst_port))
        else:
            pytest_assert(False, f"Unsupported IP protocol: {ip_protocol}")
        packet = Ether(src=src_mac, dst=router_mac) / ip / l4 / payload

        return packet

    def send_packets(self):
        try:
            # Start collecting IPFIX reports on all possible collector ports
            self.collector.start_collection(timeout=30)
            logger.info(f"Started IPFIX collection on PTF ports {self.collector.collector_ports}")

            for src_ip, dst_ip, ip_protocol, l4_src_port, l4_dst_port in self.expected_flows:
                pkt = self._build_packet(
                    self.ptfadapter, self.router_mac,
                    self.ptf_ingress_port, src_ip, dst_ip,
                    ip_protocol, l4_src_port, l4_dst_port)

                logger.info("Sending packets that match flow rules and trigger MoD...")
                testutils.send(self.ptfadapter, self.ptf_ingress_port, pkt, count=self.num_packets)

            # Send packets that should not match any flow rule
            for src_ip, dst_ip, ip_protocol, l4_src_port, l4_dst_port in self.unexpected_flows:
                pkt = self._build_packet(
                    self.ptfadapter, self.router_mac,
                    self.ptf_ingress_port, src_ip, dst_ip,
                    ip_protocol, l4_src_port, l4_dst_port)

                logger.info("Sending packets that do not trigger MoD...")
                testutils.send(self.ptfadapter, self.ptf_ingress_port, pkt, count=self.num_packets)

            # Wait for IPFIX reports to be generated and sent
            time.sleep(5)

        finally:
            # Stop collector
            self.collector.stop_collection()

    def validate_mod_packets(self, expect_reports):
        # Verify that there were IPFIX packets sent out on one of the ports to the collector
        report_count = self.collector.get_report_count()
        logger.info(f"Found {report_count} IPFIX reports on collector")

        # If no reports were expected and there are no packets, we are good
        if not expect_reports:
            pytest_assert(report_count == 0, "No report must have been sent")
            return

        for src_ip, dst_ip, ip_protocol, l4_src_port, l4_dst_port in self.expected_flows:
            actual_reports =  \
                self.collector.get_matched_reports_by_packet_fields(
                    src_ip=src_ip, dst=dst_ip, ip_protocol=ip_protocol,
                    l4_src_port=l4_src_port, l4_dst_port=l4_dst_port
                )
            pytest_assert(len(actual_reports) > 0, "No expected reports found")

        for src_ip, dst_ip, ip_protocol, l4_src_port, l4_dst_port in self.unexpected_flows:
            actual_reports = \
                self.collector.get_matched_reports_by_packet_fields(
                    src_ip=src_ip, dst_ip=dst_ip,
                    ip_protocol=ip_protocol, l4_src_port=l4_src_port,
                    l4_dst_port=l4_dst_port
                )
            pytest_assert(
                len(actual_reports) == 0, f"Received unexpected reports: {len(actual_reports)}"
            )

    def run_packet_test(self, expect_reports):
        self.collector.cleanup()
        self.send_packets()
        self.validate_mod_packets(expect_reports)


class IPFIXCollector:
    """
    IPFIX collector that captures and validates IPFIX reports.
    Collects packets from all specified ports and tracks which port each packet arrived on.
    """
    def __init__(self, ptfadapter, collector_ports, collector_config, flows_to_collect, device_id=None):
        self.ptfadapter = ptfadapter
        self.collector_ports = collector_ports  # List of ports to collect from
        self.collector_config = collector_config
        self.captured_reports = {}  # {port: [packets]}
        self.collecting = False
        self.collection_thread = None
        self.flows_to_collect = flows_to_collect
        self.device_id = int(device_id) if device_id is not None else None

        # Initialize dictionaries for each port
        for port in collector_ports:
            self.captured_reports[port] = []

        self.ip_addresses_to_collect = set()
        for src_ip, _, _, _, _ in flows_to_collect:
            self.ip_addresses_to_collect.add(src_ip)

    def start_collection(self, timeout=30):
        """Start collecting IPFIX reports in a separate thread."""
        self.ptfadapter.dataplane.flush()
        self.cleanup()
        self.collecting = True
        self.collection_thread = threading.Thread(target=self._collect_reports, args=(timeout,))
        self.collection_thread.start()

    def stop_collection(self):
        """Stop collecting IPFIX reports."""
        self.collecting = False
        if self.collection_thread:
            self.collection_thread.join()

    def _collect_reports(self, timeout):
        """Collect IPFIX reports from the dataplane on all configured ports."""
        deadline = time.time() + timeout
        logger.info("Collecting IPFIX reports... on ports {self.collector_ports}")
        while self.collecting and time.time() < deadline:
            res = testutils.dp_poll(self.ptfadapter, device_number=0, timeout=0.5)
            if not isinstance(res, self.ptfadapter.dataplane.PollSuccess):
                continue

            # Only process packets from configured collector ports
            if res.port not in self.collector_ports:
                continue

            try:
                pkt = Ether(res.packet)
                if self._is_ipfix_report(pkt):
                    self.captured_reports[res.port].append(pkt)
                    logger.info(f"Captured IPFIX report on port {res.port}: {pkt.summary()}")

            except Exception as e:
                logger.debug(f"Failed to parse packet on port {res.port}: {e}")

    def _is_ipfix_report(self, packet):
        """Check if the packet is an IPFIX report matching our collector config."""
        # Check for both IPv4 and IPv6
        has_ipv4 = IP in packet
        has_ipv6 = IPv6 in packet

        if not (has_ipv4 or has_ipv6) or UDP not in packet:
            return False

        # Get the appropriate IP layer
        if has_ipv4:
            ip_layer = packet[IP]
        else:
            ip_layer = packet[IPv6]

        udp_layer = packet[UDP]

        # Check if it matches our collector configuration
        # For IPv4: use ip_layer.src and ip_layer.dst
        # For IPv6: use ip_layer.src and ip_layer.dst (same attribute names)
        if (not (ip_layer.src == self.collector_config["src_ip"] and
           ip_layer.dst == self.collector_config["dst_ip"] and
           udp_layer.dport == self.collector_config["dst_port"])):
            return False
        return True

    def _is_valid_mod_packet(self, packet, drop_stage):
        # Verify that it is an IPFix packet
        udp_payload = bytes(packet[UDP].payload)

        if len(udp_payload) < 44:  # Minimum IPFIX+Psamp header size
            return (False, f"Invalid UDP payload length {len(udp_payload)}")

        # Check if it looks like IPFIX (version 10)
        header = IPFIXHeader(udp_payload[:20])
        if header.version != 10:
            return (False, f"Invalid IPFIX version {header.version}")

        # TODO - Need to verify DSCP values,
        # they seem incorrect
        # For IPv4: dscp = (ip_layer.tos >> 2) & 0x3F
        # For IPv6: dscp = (ip_layer.tc >> 2) & 0x3F
        # pytest_assert( dscp == int( self.collector_config["dscp_value"] ) )

        psamp_header = PsampModHeader(udp_payload[16:])

        inner_packet = Ether(udp_payload[44:])

        has_inner_ip = IP in inner_packet
        has_inner_ipv6 = IPv6 in inner_packet

        # If the inner packet is not IP, ignore it
        if not (has_inner_ip or has_inner_ipv6):
            return (False, "Ignore")

        # If the source IP address of the inner packet does not match our traffic
        # ignore it
        if (has_inner_ip and inner_packet[IP].src not in self.ip_addresses_to_collect) or \
           (has_inner_ipv6 and inner_packet[IPv6].src not in self.ip_addresses_to_collect):
            return (True, "")

        # This is a packet we are intersted in.  Validate some of the psamp header
        # TODO - Need to verify based on type of drop
        # Verify that the ingress drop reason code is non-zero.
        if drop_stage == "ingress" and psamp_header.drop_reason_ip == 0:
            return (False, "Invalid ingress drop-reason-code")
        elif drop_stage == "mmu" and psamp_header.drop_reason_ep_or_mmu == 0:
            return (False, "Invalid MMU drop-reason-code")

        # Verify that the switch_id matches the configured device-id
        if self.device_id is not None and psamp_header.switch_id != self.device_id:
            return (False, f"switch_id mismatch: expected {self.device_id}, got {psamp_header.switch_id}")

        return (True, "Valid")

    def _parse_packet(self, packet):
        """Parse the packet and return a dictionary of interesting fields."""
        # Verify that it is an IPFix packet
        udp_payload = bytes(packet[UDP].payload)

        if len(udp_payload) < 44:  # Minimum IPFIX+Psamp header size
            logger.debug(f"Invalid UDP payload length {len(udp_payload)}")
            return {}

        # Check if it looks like IPFIX (version 10)
        header = IPFIXHeader(udp_payload[:20])
        if header.version != 10:
            logger.debug(f"Invalid IPFIX version {header.version}")
            return {}

        psamp_header = PsampModHeader(udp_payload[16:])

        inner_packet = Ether(udp_payload[44:])

        has_inner_ip = IP in inner_packet
        has_inner_ipv6 = IPv6 in inner_packet

        # If the inner packet is not IP, ignore it
        if not (has_inner_ip or has_inner_ipv6):
            logger.debug("Inner packet is not IP")
            return {}

        if not (TCP in inner_packet or UDP in inner_packet):
            logger.debug("Inner packet is not TCP or UDP")
            return {}

        return {
            "switch_id": psamp_header.switch_id,
            "drop_reason_ip": psamp_header.drop_reason_ip,
            "drop_reason_ep_or_mmu": psamp_header.drop_reason_ep_or_mmu,
            "is_ipv4": has_inner_ip,
            "src_ip": inner_packet[IP].src if has_inner_ip else inner_packet[IPv6].src,
            "dst_ip": inner_packet[IP].dst if has_inner_ip else inner_packet[IPv6].dst,
            "ip_protocol": inner_packet[IP].proto if has_inner_ip else inner_packet[IPv6].nh,
            "l4_src_port": inner_packet[TCP].sport if TCP in inner_packet else inner_packet[UDP].sport,
            "l4_dst_port": inner_packet[TCP].dport if TCP in inner_packet else inner_packet[UDP].dport,
        }

    def get_report_count(self, port=None):
        """Get the number of captured IPFIX reports.

        Args:
            port: If specified, return count for that port only. Otherwise return total.
        """
        if port is not None:
            return len(self.captured_reports.get(port, []))
        return sum(len(reports) for reports in self.captured_reports.values())

    def get_reports_for_port(self, port):
        """Get captured reports for a specific port."""
        return self.captured_reports.get(port, [])

    def get_matched_reports(self, match_func):
        """Get the captured IPFIX reports that match the given function on the given port.

        Args:
            port: Port to check
            match_func: Function that takes a report and returns True if it matches
        """
        matched_reports = []
        for packets in self.captured_reports.values():
            for packet in packets:
                report = self._parse_packet(packet)
                if report and match_func(report):
                    matched_reports.append(report)
        return matched_reports

    def get_matched_reports_by_packet_fields(self, **kwargs):
        """Get the captured IPFIX reports that match the given partial fields on the given port.

        Args:
            port: Port to check
            kwargs: Dictionary of fields to match. If the field is not present in the report, it is ignored.
        """
        def _match_func(report):
            for k, v in kwargs.items():
                if k not in report:
                    continue
                if report[k] != v:
                    return False
                return True

        return self.get_matched_reports(_match_func)

    def cleanup(self):
        # Delete all the old reports
        for port in self.collector_ports:
            self.captured_reports[port] = []


def _get_tam_config(ip_family, ports, flow_aware):
    # Build tam_config with IP addresses based on IP family (same pattern as fixture)
    tam_config = copy.deepcopy(TAM_MOD_CONFIG_TEMPLATE)  # Deep copy
    if ip_family == "ipv4":
        tam_config["TAM_COLLECTOR"]["COLLECTOR1"]["src_ip"] = TAM_COLLECTOR_IPV4["src_ip"]
        tam_config["TAM_COLLECTOR"]["COLLECTOR1"]["dst_ip"] = TAM_COLLECTOR_IPV4["dst_ip"]
    else:  # ipv6
        tam_config["TAM_COLLECTOR"]["COLLECTOR1"]["src_ip"] = TAM_COLLECTOR_IPV6["src_ip"]
        tam_config["TAM_COLLECTOR"]["COLLECTOR1"]["dst_ip"] = TAM_COLLECTOR_IPV6["dst_ip"]

    if not flow_aware:
        return tam_config

    if not isinstance(ports, list):
        ports = [ports]

    # Add ports to flow group
    tam_config["TAM_FLOW_GROUP"] = {}
    tam_config["TAM_FLOW_GROUP"]["FG1"] = {
        "aging_interval": "1000",
        "ports": ports
    }

    tam_config["TAM_SESSION"]["DROPMONITOR"]["flow_group"] = ["FG1"]

    # Only IPv4 is supported for flow aware at this moment
    flow_rules = MATCHED_FLOWS

    for idx, (src_ip_prefix, dst_ip_prefix, ip_protocol, l4_src_port, l4_dst_port) in enumerate(flow_rules, start=1):
        rule_key = f"FG1|RULE{idx}"
        tam_config["TAM_FLOW_GROUP"][rule_key] = {
            "src_ip_prefix": src_ip_prefix,
            "dst_ip_prefix": dst_ip_prefix,
            "ip_protocol": ip_protocol,
            "l4_src_port": l4_src_port,
            "l4_dst_port": l4_dst_port
        }

    return tam_config


def _select_ingress_port(ingress_port, log_context="packet injection"):
    """
    Select ingress port and PTF port index from ingress_port tuple.

    Args:
        ingress_port: Tuple of (port_name, port_value) where port_value can be
                     a single PTF index or a list of PTF indices (for LAG)
        log_context: Context string for logging (e.g., "packet injection", "MMU drop injection")

    Returns:
        tuple: (ingress_port_name, ptf_ingress_port) where ptf_ingress_port is a single PTF index
    """
    ingress_port_name = ingress_port[0]
    port_value = ingress_port[1]

    # If it's a LAG (list of indices), pick the first member port
    if isinstance(port_value, list):
        ptf_ingress_port = port_value[0]
        logger.info(
            f"Using ingress LAG {ingress_port_name} with member PTF port {ptf_ingress_port} for {log_context}")
    else:
        ptf_ingress_port = port_value
        logger.info(f"Using ingress port {ingress_port_name}/PTF{ptf_ingress_port} for {log_context}")

    return ingress_port_name, ptf_ingress_port


def _prefix_to_ip(prefix, is_ipv4):
    """
    Convert IP prefix to IP address by appending '100' to the prefix.

    Args:
        prefix: IP prefix string (e.g., "10.1.1.0/24" or "2000:10:1:1::0/120")
        is_ipv4: Boolean indicating if this is IPv4

    Returns:
        str: IP address (e.g., "10.1.1.100" or "2000:10:1:1::100")
    """
    index = prefix.rfind(".") + 1 if is_ipv4 else prefix.rfind(":") + 1
    return prefix[:index] + "100"


def _prepare_flows(ip_family, flow_aware):
    """
    Prepare matched and unmatched flows for testing.

    Args:
        ip_family: "ipv4" or "ipv6"
        flow_aware: Boolean indicating if flow-aware mode is enabled

    Returns:
        tuple: (matched_flows, unmatched_flows, flows_to_collect) where each is a list of
               (src_ip, dst_ip, ip_protocol, l4_src_port, l4_dst_port) tuples
    """
    is_ipv4 = ip_family == "ipv4"
    matched_flows_prefixes = MATCHED_FLOWS if is_ipv4 else MATCHED_FLOWS_IPV6
    matched_flows = [
        (_prefix_to_ip(src_prefix, is_ipv4), _prefix_to_ip(dst_prefix, is_ipv4), proto, src_port, dst_port)
        for src_prefix, dst_prefix, proto, src_port, dst_port in matched_flows_prefixes
    ]

    if flow_aware:
        unmatched_flows_prefixes = UNMATCHED_FLOWS if is_ipv4 else UNMATCHED_FLOWS_IPV6
        unmatched_flows = [
            (_prefix_to_ip(src_prefix, is_ipv4), _prefix_to_ip(dst_prefix, is_ipv4), proto, src_port, dst_port)
            for src_prefix, dst_prefix, proto, src_port, dst_port in unmatched_flows_prefixes
        ]
    else:
        unmatched_flows = []

    flows_to_collect = matched_flows + unmatched_flows
    return matched_flows, unmatched_flows, flows_to_collect


def _setup_collector(ptfadapter, collector_ports, collector_config, flows_to_collect, device_id=None):
    """
    Set up IPFIX collector with logging.

    Args:
        ptfadapter: PTF adapter object
        collector_ports: List of PTF port indices where collector is reachable
        collector_config: Collector configuration dictionary
        flows_to_collect: List of flows to collect
        device_id: Expected device-id value for switch_id verification

    Returns:
        IPFIXCollector: Configured collector instance
    """
    logger.info(f"Collector ports (from routing): {collector_ports}")
    logger.info(f"Collector config: {collector_config}")
    return IPFIXCollector(ptfadapter, collector_ports, collector_config, flows_to_collect, device_id)


def _test_with_blackhole_route(duthost, ip_family, collector_config, packet_test):
    """
    Test TAM MoD behavior with blackhole route (should disable reporting).

    This function:
    1. Adds a blackhole route for the collector IP
    2. Waits for TAM ASIC DB to be cleared
    3. Verifies no reports are sent
    4. Removes the blackhole route
    5. Waits for TAM ASIC DB to be restored
    6. Verifies reports are sent again

    Args:
        duthost: DUT host object
        ip_family: "ipv4" or "ipv6"
        collector_config: Collector configuration dictionary
        packet_test: PacketTest instance to run tests with
    """
    blackhole_cmd, remove_blackhole_cmd = _get_blackhole_commands(ip_family, collector_config['dst_ip'])

    # Add blackhole route and verify ASIC DB is cleared
    logger.info(f"Adding blackhole route for {ip_family.upper()} collector IP: {collector_config['dst_ip']}")
    duthost.shell(blackhole_cmd, module_ignore_errors=True)
    wait_until(TAM_ASICDB_TIMEOUT, TAM_ASICDB_INTERVAL, 0, lambda: tam_asicdb_state(duthost, False))

    # Verify that now no drop reports are sent
    packet_test.run_packet_test(expect_reports=False)

    # Remove blackhole route and verify TAM configuration is recreated
    logger.info(f"Removing blackhole route for {ip_family.upper()} collector IP: {collector_config['dst_ip']}")
    duthost.shell(remove_blackhole_cmd, module_ignore_errors=True)
    wait_until(TAM_ASICDB_TIMEOUT, TAM_ASICDB_INTERVAL, 0, lambda: tam_asicdb_state(duthost, True))

    # Verify that now reports are generated on drops again
    packet_test.run_packet_test(expect_reports=True)


@pytest.mark.disable_loganalyzer
def test_mod_ingress_drops(tam_mod_config, ptfadapter):
    """
    Test basic TAM Mirror on Drop(stateless, flow aware) functionality with TTL expiry drops.

    This test is parametrized to run with both IPv4 and IPv6 collector configurations.

    1. Configure TAM MoD with dynamically selected ports and IP family
    2. Send packets with TTL=1 that will expire and be dropped on ingress ports
    3. Verify IPFIX reports are sent to the collector on the designated egress port

    Note: Reports are sent to only ONE collector port (determined at TAM configuration time),
    not distributed across multiple ports. We collect on all possible ports and identify
    which one receives the reports.
    """
    duthost, ingress_port, collector_ports, collector_config, ip_family, flow_aware = tam_mod_config

    logger.info(f"Running test with {ip_family.upper()} collector configuration")

    # Get router MAC
    router_mac = _get_router_mac(duthost)

    # Select ingress port for packet injection
    ingress_port_name, ptf_ingress_port = _select_ingress_port(ingress_port, "packet injection")

    traffic_ip_families = ['ipv4'] if flow_aware else ['ipv4', 'ipv6']

    for traffic_ip_family in traffic_ip_families:
        # Prepare flows for testing
        matched_flows, unmatched_flows, flows_to_collect = _prepare_flows(traffic_ip_family, flow_aware)

        # Set up IPFIX collector
        device_id = TAM_MOD_CONFIG_TEMPLATE["TAM"]["device"]["device-id"]
        collector = _setup_collector(ptfadapter, collector_ports, collector_config, flows_to_collect, device_id)

        # Create packet test instance
        packet_test = PacketTest(ptfadapter, ptf_ingress_port, collector, router_mac, traffic_ip_family,
                                 flow_aware=flow_aware, expected_flows=matched_flows,
                                 unexpected_flows=unmatched_flows)

        # Run initial packet test
        packet_test.run_packet_test(expect_reports=True)

    # Test with blackhole route (should disable reporting, then re-enable)
    _test_with_blackhole_route(duthost, ip_family, collector_config, packet_test)


@pytest.mark.disable_loganalyzer
def test_mod_mmu_drops(tam_mod_config, ptfadapter, tbinfo, mg_facts, dut_qos_maps_module):
    """Verify TAM MoD reports MMU/queue drops (egress blocked, port up).

    Flow:
    1. Use TAM MoD config (drop-monitor + IPFIX collector).
    2. Pick an ingress front-panel/lag port and corresponding egress interface.
    3. Map a DSCP to a specific egress queue using QoS maps.
    4. Attach a blocking scheduler to that queue (disables TX, keeps port up).
    5. Send enough DSCP-marked traffic to overflow MMU buffer and cause drops.
    6. Verify MoD/IPFIX reports are exported to the collector.
    """
    duthost, ingress_ports, collector_ports, collector_config, ip_family, flow_aware = tam_mod_config

    if flow_aware:
        pytest.skip("Skipping unsupported test variant")

    logger.info(f"Running MMU drop MoD test with {ip_family.upper()} collector configuration")

    # Get router MAC
    router_mac = _get_router_mac(duthost)

    # Select ingress port for MMU drop injection
    ingress_port_name, ptf_ingress_port = _select_ingress_port(ingress_ports, "MMU drop injection")

    # Use the same interface as egress for congestion (simple but effective)
    egress_interface = ingress_port_name

    # Derive queue to block from QoS maps using DEFAULT_DSCP
    port_qos_map = dut_qos_maps_module["port_qos_map"]
    pytest_assert(
        ingress_port_name in port_qos_map,
        f"Ingress port {ingress_port_name} not present in port_qos_map"  # noqa
    )

    dscp_to_tc_map_name = port_qos_map[ingress_port_name]["dscp_to_tc_map"].split("|")[-1].strip("]")
    tc_to_queue_map_name = port_qos_map[ingress_port_name]["tc_to_queue_map"].split("|")[-1].strip("]")

    dscp_to_tc_map = dut_qos_maps_module["dscp_to_tc_map"][dscp_to_tc_map_name]
    tc_to_queue_map = dut_qos_maps_module["tc_to_queue_map"][tc_to_queue_map_name]

    block_queue = get_dscp_to_queue_value(DEFAULT_DSCP, dscp_to_tc_map, tc_to_queue_map)
    pytest_assert(block_queue is not None, "Failed to derive queue for DEFAULT_DSCP from QoS maps")

    logger.info(
        f"Using queue {block_queue} on egress interface {egress_interface} for "
        "MMU-drop congestion (DSCP={DEFAULT_DSCP})"
    )

    # Get peer IPv4/IPv6 address for the egress interface to use as traffic destination
    ipv4_peer, ipv6_peer = get_interface_peer_addresses(mg_facts, egress_interface)

    # Ensure blocking scheduler exists
    create_blocking_scheduler(duthost, pir=1000)

    def _wait_for_drop_count(prevCount):
        currCount = get_queue_trim_counters_json(duthost, egress_interface)
        return currCount['UC1']['droppacket'] > prevCount

    # Block only the selected queue on the chosen egress interface
    with ConfigTrimming(duthost, egress_interface, block_queue, pir=1000):
        queue_counters_before = get_queue_trim_counters_json(duthost, egress_interface)
        for traffic_ip_family in ['ipv4', 'ipv6']:
            if traffic_ip_family == "ipv4":
                pytest_assert(ipv4_peer, f"No IPv4 peer address for interface {egress_interface}")
                dst_ip = ipv4_peer
            else:
                pytest_assert(ipv6_peer, f"No IPv6 peer address for interface {egress_interface}")
                dst_ip = ipv6_peer

            logger.info(f"Using destination {dst_ip} on interface {egress_interface} for MMU drop traffic")

            # Prepare expected flows for MMU drop test
            expected_flows = [("10.1.1.100", dst_ip, IP_PROTOCOL_TCP, "1000", "80")] if traffic_ip_family == "ipv4" \
                else [("2000:10:1:1::100", dst_ip, IP_PROTOCOL_TCP, "1000", "80")]
            # Set up IPFIX collector
            device_id = TAM_MOD_CONFIG_TEMPLATE["TAM"]["device"]["device-id"]
            collector = _setup_collector(ptfadapter, collector_ports, collector_config, expected_flows, device_id)
            packet_test = PacketTest(ptfadapter, ptf_ingress_port, collector, router_mac,
                                     traffic_ip_family, drop_stage="mmu", flow_aware=flow_aware,
                                     expected_flows=expected_flows)
            packet_test.run_packet_test(expect_reports=True)
        # Verify that indeed packets were dropped
        pytest_assert(wait_until(30, 5, 0, lambda: _wait_for_drop_count(queue_counters_before['UC1']['droppacket'])),
                      "PacketTest is buggy, it had passed, but the dropcounter has not incremented. "
                      f"droppacket:{queue_counters_before['UC1']['droppacket']}")  # noqa: E231


# Running this test only for flow-unaware since the collector config change
# does not really matter whether it is flow aware or not
@pytest.mark.parametrize("flow_aware_param", [False], ids=["flow_unaware"], indirect=True)
@pytest.mark.disable_loganalyzer
def test_mod_collector_config_change(tam_mod_config, ptfadapter, tbinfo):
    """
    Test TAM Mirror on Drop collector configuration change functionality.

    This test verifies that changing the collector configuration (src_ip, dst_ip, dst_port)
    dynamically updates the TAM behavior without requiring a full reconfiguration.

    1. Configure TAM MoD with dynamically selected ports and IP family
    2. Send packets with TTL=1 that will expire and be dropped on ingress ports
    3. Verify IPFIX reports are sent to the collector on the designated egress port
    4. Change the collector config and verify that the drops still happen and use newer
       collector configuration

    Note: This test only runs with flow_aware=False since collector config change
    is agnostic to flow awareness.
    """
    duthost, ingress_port, collector_ports, collector_config, ip_family, flow_aware = tam_mod_config

    logger.info(f"Running test with {ip_family.upper()} collector configuration")

    # Get router MAC
    router_mac = _get_router_mac(duthost)

    # Select ingress port for packet injection
    ingress_port_name, ptf_ingress_port = _select_ingress_port(ingress_port, "packet injection")

    # Modified collector configurations for testing collector config updates
    # Note: dst_port must be int for comparison in IPFIXCollector._is_ipfix_report()
    TAM_COLLECTOR_IPV4_MODIFIED = {
        "src_ip": "11.22.33.55",
        "dst_ip": "10.20.30.50",
        "dst_port": 20000,
    }

    TAM_COLLECTOR_IPV6_MODIFIED = {
        "src_ip": "2001:db8:1::55",
        "dst_ip": "2001:db8:2::50",
        "dst_port": 20000,
    }

    # Get modified collector config from dictionaries
    if ip_family == "ipv4":
        modified_collector_config = TAM_COLLECTOR_IPV4_MODIFIED
    else:
        modified_collector_config = TAM_COLLECTOR_IPV6_MODIFIED

    # Test with both original and modified collector configurations
    collector_configs = [
        ("modified", modified_collector_config),
        ("original", collector_config)
    ]

    available_ports = _get_available_ports(duthost, tbinfo)

    for config_name, test_collector_config in collector_configs:
        logger.info(f"Testing with {config_name} collector configuration: {test_collector_config}")

        # Get collector egress ports based on dst_ip routing
        test_collector_ports = _get_collector_egress_ports(duthost, test_collector_config["dst_ip"],
                                                           available_ports, ip_family)

        # Build full collector config with all required fields
        full_collector_config = collector_config.copy()
        full_collector_config.update(test_collector_config)

        # Update CONFIG_DB with collector configuration
        duthost.shell(f'sonic-db-cli CONFIG_DB HSET "TAM_COLLECTOR|COLLECTOR1" "src_ip" '
                      f'"{full_collector_config["src_ip"]}"')
        duthost.shell(f'sonic-db-cli CONFIG_DB HSET "TAM_COLLECTOR|COLLECTOR1" "dst_ip" '
                      f'"{full_collector_config["dst_ip"]}"')
        duthost.shell(f'sonic-db-cli CONFIG_DB HSET "TAM_COLLECTOR|COLLECTOR1" "dst_port" '
                      f'"{full_collector_config["dst_port"]}"')

        # Wait for TAM ASIC DB to reflect the configuration
        pytest_assert(
            wait_for_tam_asicdb_applied(duthost, TAM_ASICDB_TIMEOUT, TAM_ASICDB_INTERVAL),
            f"ASIC_DB missing TAM keys after applying {config_name} collector config"
        )

        for traffic_ip_family in ['ipv4', 'ipv6']:
            # Prepare flows for testing
            matched_flows, unmatched_flows, flows_to_collect = _prepare_flows(traffic_ip_family, flow_aware)

            # Set up IPFIX collector
            device_id = TAM_MOD_CONFIG_TEMPLATE["TAM"]["device"]["device-id"]
            collector = _setup_collector(ptfadapter, test_collector_ports, full_collector_config, flows_to_collect,
                                         device_id)

            # Create packet test instance
            packet_test = PacketTest(ptfadapter, ptf_ingress_port, collector, router_mac, traffic_ip_family,
                                     flow_aware=flow_aware, expected_flows=matched_flows,
                                     unexpected_flows=unmatched_flows)

            # Run packet test
            packet_test.run_packet_test(expect_reports=True)
