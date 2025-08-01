import logging
import pytest
import threading
import random
import allure
import re
import time
from scapy.all import rdpcap
from .syslog_utils import create_vrf, remove_vrf, add_syslog_server, del_syslog_server, capture_syslog_packets, \
    replace_ip_neigh, bind_interface_to_vrf, check_vrf, syslogUtilsConst
from tests.common.utilities import wait_until
from tests.common.helpers.syslog_helpers import is_mgmt_vrf_enabled
from tests.common.helpers.assertions import pytest_assert
from tests.common.reboot import reboot, SONIC_SSH_PORT, SONIC_SSH_REGEX
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network, IPv6Network
from tests.common.fixtures.duthost_utils import backup_and_restore_config_db_on_duts  # noqa F401
from tests.common.config_reload import config_reload
from ipaddress import IPv4Network
from unittest.mock import patch

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("any")
]

DEFAULT_VRF_IP_ADDRESSES = {"ipv4": {"syslog_server_ip": "100.100.100.1", "syslog_server_mac": "90:90:90:90:90:01",
                                     "source_ip": "100.100.100.2/24"},
                            "ipv6": {"syslog_server_ip": "2222::1111", "syslog_server_mac": "90:90:90:90:90:02",
                                     "source_ip": "2222::1112/64"}}

DATA_VRF_IP_ADDRESSES = {"ipv4": {"syslog_server_ip": "200.200.200.1", "syslog_server_mac": "90:90:90:90:90:11",
                                  "source_ip": "200.200.200.2/24"},
                         "ipv6": {"syslog_server_ip": "2221::1111", "syslog_server_mac": "90:90:90:90:90:12",
                                  "source_ip": "2221::1112/64"}}

MGMT_IP_ADDRESSES = {"ipv4": {"syslog_server_ip": "", "syslog_server_mac": "90:90:90:90:90:31",
                              "source_ip": ""},
                     "ipv6": {"syslog_server_ip": "", "syslog_server_mac": "90:90:90:90:90:32",
                              "source_ip": ""}}

VRF_LIST = ["default", "Vrf-data", "mgmt"]

SYSLOG_TEST_DATA = {"default": DEFAULT_VRF_IP_ADDRESSES,
                    "Vrf-data": DATA_VRF_IP_ADDRESSES,
                    "mgmt": MGMT_IP_ADDRESSES}

SYSLOG_CONFIG_COMBINATION = {
    "vrf_unset_source_unset_port_None": {"is_set_vrf": False, "is_set_source": False, "port": None,
                                         "vrf_list": VRF_LIST[0:1]},
    "vrf_unset_source_unset_port_600": {"is_set_vrf": False, "is_set_source": False, "port": 600,
                                        "vrf_list": VRF_LIST[0:1]},
    "vrf_unset_source_set_port_None": {"is_set_vrf": False, "is_set_source": True, "port": None,
                                       "vrf_list": VRF_LIST[0:1]},
    "vrf_unset_source_set_port_650": {"is_set_vrf": False, "is_set_source": True, "port": 650,
                                      "vrf_list": VRF_LIST[0:1]},
    "vrf_set_source_unset_None": {"is_set_vrf": True, "is_set_source": False, "port": None, "vrf_list": VRF_LIST},
    "vrf_set_source_unset_700": {"is_set_vrf": True, "is_set_source": False, "port": 700, "vrf_list": VRF_LIST},
    "vrf_set_source_set_None": {"is_set_vrf": True, "is_set_source": True, "port": None, "vrf_list": VRF_LIST},
    "vrf_set_source_set_800": {"is_set_vrf": True, "is_set_source": True, "port": 800, "vrf_list": VRF_LIST}}

SYSLOG_CONFIG_COMBINATION_CASE = ["vrf_unset_source_unset_port_None",
                                  "vrf_unset_source_unset_port_600",
                                  "vrf_unset_source_set_port_None",
                                  "vrf_unset_source_set_port_650",
                                  "vrf_set_source_unset_None",
                                  "vrf_set_source_unset_700",
                                  "vrf_set_source_set_None",
                                  "vrf_set_source_set_800"]
SYSLOG_DEFAULT_PORT = 514
TEST_FORWARD_FLAGS_AND_MSGS = {
    "default": ('', ''),
    "teamd_": ("-t teamd_", "teamd_"),
    "bgp0#frr": ("-t bgp0#frr", "bgp0#frr"),
    "bgp0#zebra": ("-t bgp0#zebra", "bgp0#zebra"),
    "bgp0#staticd": ("-t bgp0#staticd", "bgp0#staticd"),
    "bgp0#watchfrr": ("-t bgp0#watchfrr", "bgp0#watchfrr"),
    "bgp0#bgpd": ("-t bgp0#bgpd", "bgp0#bgpd"),
    "bgp#bgpd": ("-t bgp#bgpd", "bgp#bgpd"),
    "gnmi-native": ("-t gnmi-native", "gnmi-native"),
    "telemetry": ("-t telemetry", "telemetry"),
    "dialout": ("-t dialout", "dialout")}

SYSLOG_THREAD_TIMEOUT = 90


@pytest.fixture(scope="module", autouse=True)
def is_support_ssip(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """
    Check if the image support ssip feature. If no, skip all tests

    Args:
        duthosts: DUT hosts fixture
        enum_rand_one_per_hwsku_frontend_hostname: DUT fixture
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    show_syslog_res = duthost.command('show syslog', module_ignore_errors=True)['stderr_lines']
    if show_syslog_res:
        pytest.skip("This image doesn't support ssip feature, so skipp all related tests")


@pytest.fixture(scope="module", autouse=True)
def restore_config_by_config_reload(duthosts, enum_rand_one_per_hwsku_frontend_hostname, localhost):
    yield
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    if is_mgmt_vrf_enabled(duthost):
        # when removing mgmt vrf, dut connection will be lost for a while. So, before config reload,
        # we need remove mgmt vrf, otherwise it will cause host unreachable
        remove_vrf(duthost, VRF_LIST[2])
        localhost.wait_for(host=duthost.mgmt_ip, port=SONIC_SSH_PORT, search_regex=SONIC_SSH_REGEX,
                           state='absent', delay=1, connect_timeout=1, timeout=30)
        localhost.wait_for(host=duthost.mgmt_ip, port=SONIC_SSH_PORT, search_regex=SONIC_SSH_REGEX,
                           state='started', delay=2, timeout=180)
    config_reload(duthost, safe_reload=True)


@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exceptions(enum_rand_one_per_hwsku_frontend_hostname, loganalyzer):
    """
    Ignore expected failures logs during test execution.
    The log error is caused by a fake unresolved neighbors: on a high message send rate, the buffer overflow is
    happening due to kernel neighbor resolution.
    Refer below link:
    https://www.rsyslog.com/rsyslog-error-2354/
    https://stackoverflow.com/questions/14370489/what-can-cause-a-resource-temporarily-unavailable-on-sock-send-command
    Args:
        duthost: DUT fixture
        loganalyzer: Loganalyzer utility fixture
    """
    ignoreRegex = [
        ".*ERR rsyslogd: omfwd: socket.*sending via udp: Resource temporarily unavailable.*",
        ".*ERR rsyslogd: omfwd.*udp: socket.*sendto.* error: Resource temporarily unavailable*"
    ]

    if loganalyzer:  # Skip if loganalyzer is disabled
        loganalyzer[enum_rand_one_per_hwsku_frontend_hostname].ignore_regex.extend(ignoreRegex)


def skip_ssip_reboot_test_when_dut_mgmt_network_is_sub_network_forced_mgmt(duthost):
    """
    Skip test_syslog_config_work_after_reboot due to https://github.com/sonic-net/sonic-buildimage/issues/21201.
    When the issue is fixed, we can remove the function
    """
    ip_intfs = duthost.show_and_parse('show ip interface')
    dut_mgmt_network = ''
    for intf in ip_intfs:
        if intf['interface'] == 'eth0':
            dut_mgmt_network = intf['ipv4 address/mask']
    assert dut_mgmt_network, "Not find mgmt interface eth0"

    cmd_get_forced_mgmt_network_info = \
        f'redis-cli -n 4 hget \"MGMT_INTERFACE|eth0|{dut_mgmt_network}\" forced_mgmt_routes@'
    forced_mgmt_routes_info = duthost.shell(cmd_get_forced_mgmt_network_info)["stdout"]
    forced_mgmt_routes_info_list = forced_mgmt_routes_info.split(",") if forced_mgmt_routes_info else []

    def _is_dut_mgmt_network_subnet_forced_mgmt(dut_mgmt_network, forced_mgmt_route):
        """
        Checks if network_a is a subnet of network_b.
        """
        logger.info(f"dut_mgmt_network:{dut_mgmt_network}, forced_mgmt_route: {forced_mgmt_route}")
        net_dut_mgmt = IPv4Network(dut_mgmt_network, strict=False)
        net_forced_mgmt = IPv4Network(forced_mgmt_route, strict=False)
        return net_dut_mgmt.subnet_of(net_forced_mgmt)

    for forced_mgmt_route in forced_mgmt_routes_info_list:
        if _is_dut_mgmt_network_subnet_forced_mgmt(dut_mgmt_network, forced_mgmt_route.strip()):
            pytest.skip(
                "Skip the SSIP reboot test due to the issue:https://github.com/sonic-net/sonic-buildimage/issues/21201")


@pytest.fixture(autouse=True, scope="function")
def error_on_raise_in_thread():
    """Fixture to capture thread exceptions using a global list."""
    global thread_exceptions
    thread_exceptions = []  # Reset exceptions before each test

    class ThreadWrapper(threading.Thread):
        def run(self):
            try:
                super().run()
            except BaseException as e:
                thread_exceptions.append(e)  # Store exceptions globally

    with patch('threading.Thread', ThreadWrapper):
        yield  # No need to return exceptions explicitly


def handle_thread_exceptions():
    """Format and handle thread exceptions with improved error reporting.

    Returns:
        None: Raises pytest.fail() if exceptions exist
    """
    global thread_exceptions
    if thread_exceptions:
        error_messages = "\n".join(f"{type(e).__name__}: {e}" for e in thread_exceptions)
        thread_exceptions.clear()
        pytest.fail(f"Thread Failures Occurred:\n{error_messages}")


def attach_pcapfile_to_allure(pcapfile, pcap_name):
    """
    Attach pcap file to allure report
    """
    try:
        allure.attach.file(source=pcapfile, name=pcap_name, attachment_type=allure.attachment_type.PCAP)
        logger.info(f"Attached pcap file to allure report: {pcapfile}")
    except Exception as e:
        logger.error(f"Failed to attach pcap file to allure report: {e}")


class TestSSIP:
    @pytest.fixture(scope="class")
    def routed_interfaces(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_frontend_asic_index):
        """
        Find routed interface to test

        Args:
            duthosts: DUT hosts fixture
            enum_rand_one_per_hwsku_frontend_hostname: DUT fixture
            enum_frontend_asic_index: asic index fixture

        Retruns:
            routedInterface (str): Routed interface used for testing
        """
        self.duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        self.asichost = self.duthost.asic_instance(enum_frontend_asic_index)
        test_routed_interfaces = []

        def find_routed_interface():
            intf_status = self.asichost.show_interface(command="status")["ansible_facts"]["int_status"]
            for intf, status in list(intf_status.items()):
                if "routed" in status["vlan"] and "up" in status["oper_state"]:
                    test_routed_interfaces.append(intf)
                    if len(test_routed_interfaces) == 2:
                        break
            return test_routed_interfaces

        if not wait_until(120, 2, 0, find_routed_interface):
            pytest.skip('This topo has no route Interface, skip it')
        yield test_routed_interfaces

    @pytest.fixture(scope="class")
    def mgmt_interface(self, duthosts, rand_one_dut_hostname):
        """
        Find mgmt interface to test, and update the dict of MGMT_IP_ADDRESSES

        Args:
            duthost (AnsibleHost): Device Under Test (DUT)

        Retruns:
            mgmt_interface (str): mgmt interface used for testing
        """
        duthost = duthosts[rand_one_dut_hostname]

        mgmt_interface_info = duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts'][
            "MGMT_INTERFACE"]
        mgmt_interface = list(mgmt_interface_info.keys())

        logger.info("Update mgmt dict according to the real config on dut")
        for k, v in list(mgmt_interface_info[mgmt_interface[0]].items()):
            ip_addr_instance = ip_address(str(k.split("/")[0]))
            if isinstance(ip_addr_instance, IPv4Address):
                MGMT_IP_ADDRESSES["ipv4"]["source_ip"] = k
                for host in ip_network(str(v["gwaddr"])):
                    if host != ip_addr_instance:
                        syslog_server_ip = str(host)
                        break
                MGMT_IP_ADDRESSES["ipv4"]["syslog_server_ip"] = syslog_server_ip
            elif isinstance(ip_addr_instance, IPv6Address):
                MGMT_IP_ADDRESSES["ipv6"]["source_ip"] = k
                for host in IPv6Network(str(v["gwaddr"])):
                    if host != ip_addr_instance:
                        syslog_server_ip = str(host)
                        break
                MGMT_IP_ADDRESSES["ipv6"]["syslog_server_ip"] = syslog_server_ip

        logger.info("Updated mgmt dict:{}".format(MGMT_IP_ADDRESSES))
        return mgmt_interface

    @pytest.fixture(scope="class", autouse=True)
    def setup_ssip_test_env(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                            enum_frontend_asic_index, mgmt_interface, routed_interfaces,
                            backup_and_restore_config_db_on_duts, localhost):  # noqa F811
        """
        Setup env for ssip(syslog soruce ip) test
        """
        self.duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        self.asichost = self.duthost.asic_instance(enum_frontend_asic_index)

        logger.info("Configure IP on the selected interface in default vrf")
        self.configure_default_vrf_test_data(routed_interfaces)

        logger.info("Enable mgmt vrf and configure IP on the mgmt interface")
        self.configure_mgmt_vrf_test_data(localhost)

        logger.info("Create data vrf and configure IP on the data vrf interface")
        self.configure_data_vrf_test_data(routed_interfaces)

    @pytest.fixture(scope="function", autouse=True)
    def clear_syslog_config(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_frontend_asic_index):
        """
        clear syslog config for very test
        """
        self.duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        yield
        syslog_config_list = self.duthost.show_syslog()
        if syslog_config_list:
            for syslog_config in syslog_config_list:
                del_syslog_server(self.duthost, syslog_server_ip=syslog_config["server ip"])

    def configure_data_vrf_test_data(self, routed_interfaces):
        """
        Configure test data for data vrf
        """
        logger.info("Create data vrf {}".format(VRF_LIST[1]))
        create_vrf(self.duthost, VRF_LIST[1])

        logger.info(f"Validate vrf {VRF_LIST[1]} is created")
        wait_until(5, 1, 0, check_vrf, self.duthost, VRF_LIST[1])

        logger.info("Bind interface {} to  data vrf {}".format(routed_interfaces[1], VRF_LIST[1]))
        bind_interface_to_vrf(self.asichost, VRF_LIST[1], routed_interfaces[1])

        logger.info("Configure Ip address on the selected interface and add ip neigh for data vrf on dut")
        for k, v in list(DATA_VRF_IP_ADDRESSES.items()):
            self.asichost.config_ip_intf(routed_interfaces[1], DATA_VRF_IP_ADDRESSES[k]["source_ip"], "add")
            replace_ip_neigh(self.duthost, neighbour=DATA_VRF_IP_ADDRESSES[k]["syslog_server_ip"],
                             neigh_mac_addr=DATA_VRF_IP_ADDRESSES[k]["syslog_server_mac"],
                             dev=VRF_LIST[1])

    def configure_default_vrf_test_data(self, routed_interfaces):
        """
        Configure test data for default vrf
        """
        logger.info("Configure Ip address on the selected interface and add ip neigh for default vrf on dut")
        for k, v in list(DEFAULT_VRF_IP_ADDRESSES.items()):
            self.asichost.config_ip_intf(routed_interfaces[0], DEFAULT_VRF_IP_ADDRESSES[k]["source_ip"], "add")
            replace_ip_neigh(self.duthost, neighbour=DEFAULT_VRF_IP_ADDRESSES[k]["syslog_server_ip"],
                             neigh_mac_addr=DEFAULT_VRF_IP_ADDRESSES[k]["syslog_server_mac"],
                             dev=routed_interfaces[0])

    def configure_mgmt_vrf_test_data(self, localhost):
        """
        Configure test data for mgmt vrf
        """
        if not is_mgmt_vrf_enabled(self.duthost):
            logger.info("Create mgmt vrf")
            create_vrf(self.duthost, VRF_LIST[2])
            # when create mgmt vrf, dut connection will be lost for a while
            localhost.wait_for(host=self.duthost.mgmt_ip, port=SONIC_SSH_PORT, search_regex=SONIC_SSH_REGEX,
                               state='absent', delay=1, connect_timeout=1, timeout=30)
            localhost.wait_for(host=self.duthost.mgmt_ip, port=SONIC_SSH_PORT, search_regex=SONIC_SSH_REGEX,
                               state='started', delay=2, timeout=180)

        for k, v in list(MGMT_IP_ADDRESSES.items()):
            logger.info("Add neigh for {}".format(v))
            replace_ip_neigh(self.duthost, neighbour=MGMT_IP_ADDRESSES[k]["syslog_server_ip"],
                             neigh_mac_addr=MGMT_IP_ADDRESSES[k]["syslog_server_mac"],
                             dev=VRF_LIST[2])

    def verify_syslog_config(self, syslog_server_ip, vrf, port, source="N/A"):
        """
        Verify syslog config

        Args:
            dut (SonicHost): The target device
            syslog_server_ip (str): Syslog server address
            source (str): Source ip address
            vrf (str): Vrf device (default,mgmt,Vrf-data)
            port (str): Server udp port
        Return: True if syslog config exist else False
        """
        syslog_config_list = self.duthost.show_syslog()
        for syslog_config in syslog_config_list:
            if all([syslog_config["server ip"].lower() == syslog_server_ip.lower(),
                    syslog_config["source ip"].lower() == source.lower(),
                    syslog_config["vrf"] == vrf,
                    syslog_config["port"] == port]):
                return True
        return False

    def check_no_syslog_one_vrf(self, routed_interfaces, port, vrf, logging_data, is_set_source):
        tcpdump_file = self.gen_tcpdump_cmd_and_capture_syslog_packets(routed_interfaces, port, vrf,
                                                                       logging_data=logging_data, neg=True)
        packets = rdpcap(tcpdump_file)
        for k, v in list(SYSLOG_TEST_DATA[vrf].items()):
            source_ip = v["source_ip"].split("/")[0] if is_set_source else None
            pytest_assert(
                not self.verify_syslog_packets(packets,
                                               syslog_server_ip=v["syslog_server_ip"],
                                               port=port if port else SYSLOG_DEFAULT_PORT,
                                               source=source_ip),
                "Syslog packet with dest_ip:{}, source_ip:{}, port:{}  is not stopped on vrf of {}".format(
                    v["syslog_server_ip"], source_ip, port if port else SYSLOG_DEFAULT_PORT, vrf))
            logger.info("Vrf {},{}: stop syslog msg check pass".format(vrf, k))

    def check_syslog_one_vrf(self, routed_interfaces, port, vrf, logging_data, is_set_source, rsyslog=False):
        tcpdump_file = self.gen_tcpdump_cmd_and_capture_syslog_packets(routed_interfaces, port, vrf, logging_data)
        attach_pcapfile_to_allure(tcpdump_file, f'{vrf}_syslog_packets')
        packets = rdpcap(tcpdump_file)
        logger.info("Total packets captured: %d", len(packets))
        for k, v in list(SYSLOG_TEST_DATA[vrf].items()):
            if self.is_link_local_ip(v["source_ip"]):
                continue
            source_ip = v["source_ip"].split("/")[0] if is_set_source else None
            pytest_assert(
                self.verify_syslog_packets(packets,
                                           syslog_server_ip=v["syslog_server_ip"],
                                           port=port if port else SYSLOG_DEFAULT_PORT,
                                           source=source_ip),
                "Syslog packet with dest_ip:{}, source_ip:{}, port:{}  is not sent on vrf of {}".format(
                    v["syslog_server_ip"], source_ip, port if port else SYSLOG_DEFAULT_PORT, vrf))
            logger.info("Vrf {},{}: send syslog msg check pass".format(vrf, k)
                        )
        if rsyslog:
            pytest_assert(
                self.verify_rsyslog_packets(packets, expected_forward_types=TEST_FORWARD_FLAGS_AND_MSGS.keys()),
                "Not all syslog were forwarded to rsyslog")
            logger.info(f"Vrf {vrf}: forward syslog msg check pass")

    def verify_syslog_packets(self, packets, syslog_server_ip, port, source):
        """
        verify syslog packets

        Args:
            packets (list): list of packets
            syslog_server_ip (str): Syslog server address
            source (str): Source ip address
            port (str): Server udp port
        Return: True
        """
        for data in packets:
            proto = "IPv6" if "IPv6" in data else "IP"
            if all([data[proto].dst == syslog_server_ip,
                    data[proto].dport == port,
                    data[proto].src == source if source else True]):
                logger.info(f"Found packet from {source} to {syslog_server_ip} on port {port}")
                return True
        logger.info(f"No packet from {source} to {syslog_server_ip} on port {port}")
        return False

    def extract_forward_type_from_message(self, syslog_message):
        """Extract the forward type parameter from a syslog message.
        Args:
            syslog_message (str): The syslog message to parse
        Returns:
            str or None: The forward type if found, None otherwise
        """
        forward_type_match = re.search(rf"{self.duthost.hostname} CRIT\s+([^:]+):", syslog_message)
        if forward_type_match:
            return forward_type_match.group(1)  # Returns the forward type value
        return 'default'

    def get_forward_types(self, packets, expected_forward_types):
        """Count the number of messages for each forward type in the captured packets.

        Args:
            packets (list): List of captured network packets

        Returns:
            dict: Dictionary mapping forward types to their message counts
        """
        forward_type_counts = {key: 0 for key in expected_forward_types}
        for packet in packets:
            message_content = packet['Raw'].raw_packet_cache.decode()
            forward_type = self.extract_forward_type_from_message(message_content)
            if forward_type in expected_forward_types:
                forward_type_counts[forward_type] += 1

        return forward_type_counts

    def verify_rsyslog_packets(self, packets, expected_forward_types):
        """Verify that all expected forward types are present in the captured packets with sufficient count.

        Args:
            packets (list): List of captured network packets
            expected_forward_types (list): List of forward types that should be present in the packets

        Returns:
            bool: True if all expected forward types are found with sufficient packets, False otherwise
        """
        forward_type_counts = self.get_forward_types(packets, expected_forward_types)

        logger.info("Expected Forward Types: %s", expected_forward_types)
        logger.info("Forward Types Found in Packets: %s", forward_type_counts)

        missing_forward_types = [f_type for f_type in expected_forward_types if forward_type_counts[f_type] == 0]
        if missing_forward_types:
            logger.error(f"Missing expected forward types: {missing_forward_types}")
            return False

        # Check if all types have sufficient packets
        insufficient_types = [f_type for f_type, cnt in forward_type_counts.items() if
                              cnt < syslogUtilsConst.PACKETS_NUM]
        if insufficient_types:
            logger.error(
                f"Types with insufficient packets (expected >= {syslogUtilsConst.PACKETS_NUM}): {insufficient_types}")
            logger.error("Try to increase TCPDUMP_CAPTURE_TIME to capture more packets")
            return False

        logger.info("All rsyslog packets verified successfully")
        return True

    def add_syslog_config(self, port, vrf_list, is_set_source, is_set_vrf):
        for vrf in vrf_list:
            for k, v in list(SYSLOG_TEST_DATA[vrf].items()):
                if self.is_link_local_ip(v["source_ip"]):
                    continue
                add_syslog_server(self.duthost,
                                  syslog_server_ip=v["syslog_server_ip"],
                                  source=v["source_ip"].split("/")[0] if is_set_source else None,
                                  vrf=vrf if is_set_vrf else None,
                                  port=port)

    def remove_syslog_config(self, vrf_list):
        for vrf in vrf_list:
            for k, v in list(SYSLOG_TEST_DATA[vrf].items()):
                if self.is_link_local_ip(v["source_ip"]):
                    continue
                del_syslog_server(self.duthost, syslog_server_ip=v["syslog_server_ip"])

    def check_syslog_config_exist(self, port, vrf_list, is_set_source, is_set_vrf):
        for vrf in vrf_list:
            for k, v in list(SYSLOG_TEST_DATA[vrf].items()):
                if self.is_link_local_ip(v["source_ip"]):
                    continue
                source_ip = v["source_ip"].split("/")[0] if is_set_source else "N/A"
                pytest_assert(
                    wait_until(30, 5, 0, self.verify_syslog_config,
                               v["syslog_server_ip"],
                               vrf if is_set_vrf else "N/A",
                               str(port) if port else "N/A",
                               source_ip),
                    "Excepted syslog config: server_ip {}, source_ip {}, vrf {}, port {} doesn't exist".format(
                        v["syslog_server_ip"], source_ip, vrf, port))

    def check_syslog_config_nonexist(self, port, vrf_list, is_set_source, is_set_vrf):
        logger.info("Check syslog config nonexist")
        for vrf in vrf_list:
            for k, v in list(SYSLOG_TEST_DATA[vrf].items()):
                if self.is_link_local_ip(v["source_ip"]):
                    continue
                source_ip = v["source_ip"].split("/")[0] if is_set_source else "N/A"
                pytest_assert(not self.verify_syslog_config(syslog_server_ip=v["syslog_server_ip"],
                                                            vrf=vrf if is_set_vrf else "N/A",
                                                            port=port if port else "N/A",
                                                            source=source_ip),
                              "Syslog config: server_ip {}, source_ip {}, vrf {}, port {} still exist".format(
                                  v["syslog_server_ip"], source_ip, vrf, port))

    def check_syslog_msg_is_sent(self, routed_interfaces, mgmt_interface, port, vrf_list, is_set_source, logging_data,
                                 rsyslog=False):
        thread_pool = []
        for vrf in vrf_list:
            logger.info("Create thread for {} to check syslog msg is sent".format(vrf))
            th = threading.Thread(target=self.check_syslog_one_vrf,
                                  args=(routed_interfaces, port, vrf, logging_data, is_set_source, rsyslog))
            thread_pool.append(th)
            th.start()

        for thread in thread_pool:
            thread.join(timeout=SYSLOG_THREAD_TIMEOUT)

        handle_thread_exceptions()

    def is_link_local_ip(self, ip):
        if ip.startswith("fe80::"):
            logger.info("link_local address {} is not supported, the relevant case should be skipped".format(ip))
            return True
        return False

    def check_syslog_msg_is_stopped(self, routed_interfaces, mgmt_interface, port, vrf_list, is_set_source,
                                    logging_data=[('', '')]):
        thread_pool = []
        for vrf in vrf_list:
            logger.info("Create thread for {} to check syslog msg is stopped".format(vrf))
            th = threading.Thread(target=self.check_no_syslog_one_vrf,
                                  args=(routed_interfaces, port, vrf, logging_data, is_set_source))
            thread_pool.append(th)
            th.start()

        for thread in thread_pool:
            thread.join(timeout=SYSLOG_THREAD_TIMEOUT)

        handle_thread_exceptions()

    def gen_tcpdump_cmd_and_capture_syslog_packets(self, routed_interfaces, port, vrf, logging_data=[("", "")],
                                                   neg=False):
        if vrf == VRF_LIST[0]:
            tcpdump_interface = routed_interfaces[0]
        else:
            tcpdump_interface = vrf
        tcpdump_file_name = syslogUtilsConst.DUT_PCAP_FILEPATH.format(
            vrf=vrf + '_neg' if neg else vrf,
            time=time.strftime("%m%d_%H%M%S")
            )
        tcpdump_cmd = (
            f"sudo timeout {syslogUtilsConst.TCPDUMP_CAPTURE_TIME} tcpdump -i {tcpdump_interface} "
            f"port {port if port else SYSLOG_DEFAULT_PORT} -w {tcpdump_file_name}"
        )
        tcpdump_file = capture_syslog_packets(self.duthost, tcpdump_cmd, logging_data)
        return tcpdump_file

    @pytest.mark.parametrize("syslog_config_combination_case", SYSLOG_CONFIG_COMBINATION_CASE)
    def test_basic_syslog_config(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_frontend_asic_index,
                                 routed_interfaces, mgmt_interface, syslog_config_combination_case):
        """
        Validates that adding syslog config with different combination for parameters: vrf, source, port
        1. Add syslog config
        2. Check adding syslog config succeeds
        3. Check the related interface sends corresponding syslog msg
        4. Remove syslog config
        5. Check syslog config will be removed successfully
        6. Check the related interface will stop sending corresponding syslog msg
        """
        logger.info("Starting syslog tests :{}".format(syslog_config_combination_case))
        self.duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        self.asichost = self.duthost.asic_instance(enum_frontend_asic_index)
        port = SYSLOG_CONFIG_COMBINATION[syslog_config_combination_case]["port"]
        vrf_list = SYSLOG_CONFIG_COMBINATION[syslog_config_combination_case]["vrf_list"]
        is_set_source = SYSLOG_CONFIG_COMBINATION[syslog_config_combination_case]["is_set_source"]
        is_set_vrf = SYSLOG_CONFIG_COMBINATION[syslog_config_combination_case]["is_set_vrf"]

        with allure.step("Add syslog config"):
            self.add_syslog_config(port, vrf_list=vrf_list, is_set_source=is_set_source, is_set_vrf=is_set_vrf)

        with allure.step("Check syslog config is configured successfully"):
            self.check_syslog_config_exist(
                port, vrf_list=vrf_list, is_set_source=is_set_source, is_set_vrf=is_set_vrf)

        with allure.step("Check interface of {} send syslog and rsyslog rules msg ".format(routed_interfaces[0])):
            self.check_syslog_msg_is_sent(routed_interfaces, mgmt_interface, port, vrf_list=vrf_list,
                                          is_set_source=is_set_source,
                                          logging_data=TEST_FORWARD_FLAGS_AND_MSGS.values(), rsyslog=True)

        with allure.step("Remove syslog config"):
            self.remove_syslog_config(vrf_list=vrf_list)

        with allure.step("Check syslog config is removed"):
            self.check_syslog_config_nonexist(port, vrf_list=vrf_list, is_set_source=is_set_source,
                                              is_set_vrf=is_set_vrf)

        with allure.step("Check interface of {} will not send syslog msg ".format(routed_interfaces[0])):
            self.check_syslog_msg_is_stopped(routed_interfaces, mgmt_interface, port, vrf_list=vrf_list,
                                             is_set_source=is_set_source)

    @pytest.mark.parametrize("non_existing_ip_type", ["no_on_any_vrf", "only_on_other_vrf"])
    def test_config_syslog_non_existing_ip(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                                           non_existing_ip_type):
        """
        Validates that adding syslog config with non-existing ip will fail.
        non-existing is as follows:
            a) ip is not on any vrf
            b) ip is only on the other vrf
        1. Add syslog config with a non-existing ip
        2. Check adding syslog config fail
        """
        self.duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        if non_existing_ip_type == "no_on_any_vrf":
            non_existing_ip = "100.120.11.121"
            vrf = VRF_LIST[0]
        else:
            non_existing_ip = DEFAULT_VRF_IP_ADDRESSES["ipv4"]["source_ip"].split('/')[0]
            vrf = VRF_LIST[1]

        with allure.step("Add non-existing source ip {} into syslog config".format(non_existing_ip)):
            expected_msg = r'.*Error: Invalid value for \"-s\" \/ "--source": {} IP doesn\'t exist in Linux {} VRF' \
                .format(non_existing_ip, vrf)
            err_msg = add_syslog_server(
                self.duthost,
                syslog_server_ip=DEFAULT_VRF_IP_ADDRESSES["ipv4"]["syslog_server_ip"].split('/')[0],
                source=non_existing_ip,
                vrf=vrf)["stderr"]
            pytest_assert(re.search(expected_msg, err_msg),
                          "Error msg is not correct: Expectd msg:{}, actual msg:{}".format(expected_msg, err_msg))

    def test_config_syslog_with_non_existing_vrf(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """
        Validates that adding syslog config with non-existing vrf will fail

        1. Add syslog config with a non-existing vrf
        2. Verify adding syslog config fail
        """
        self.duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        non_existing_vrf = "Vrf_no_existing"
        with allure.step("Add non existing vrf {} into syslog config".format(non_existing_vrf)):
            expected_msg = r'.*Error: Invalid value for \"-r\" \/ "--vrf": invalid choice: {}. \(choose from.*'.format(
                non_existing_vrf)
            err_msg = add_syslog_server(self.duthost,
                                        syslog_server_ip=DEFAULT_VRF_IP_ADDRESSES["ipv4"]["syslog_server_ip"],
                                        vrf=non_existing_vrf)["stderr"]
            pytest_assert(re.search(expected_msg, err_msg),
                          "Error msg is not correct: Expectd msg:{}, actual msg:{}".format(expected_msg, err_msg))

    def test_syslog_config_work_after_reboot(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                                             enum_frontend_asic_index, routed_interfaces, mgmt_interface,
                                             localhost, request):
        """
        Validates that syslog config still work after reboot(reboot, fast-reboot, warm-reboot)

        1. Add syslog config for vrf(default, mgmt, Vrf-data)
        2. Check syslog config is configured successfully
        3. Check the related interface sends corresponding syslog msg
        4. Config save -y
        5. Do reboot according to the specified parameter of ssip_reboot_type
           (reboot/warm-reboot/fast-reboot/soft-reboot)
        6. Check syslog configuration still exist
        7. Check Syslog msg can be sent on the relevant interface
        """
        logger.info("Starting test_syslog_config_work_after_reboot .....")
        self.duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        skip_ssip_reboot_test_when_dut_mgmt_network_is_sub_network_forced_mgmt(self.duthost)
        self.asichost = self.duthost.asic_instance(enum_frontend_asic_index)
        syslog_config_data = SYSLOG_CONFIG_COMBINATION["vrf_set_source_set_800"]
        port = syslog_config_data["port"]
        vrf_list = syslog_config_data["vrf_list"]
        is_set_source = syslog_config_data["is_set_source"]
        is_set_vrf = syslog_config_data["is_set_vrf"]

        logger.info(
            "data vrf: port:{}, vrf_list:{}, is_set_source:{}, is_set_vrf:{}".format(port, vrf_list, is_set_source,
                                                                                     is_set_vrf))
        with allure.step("Add syslog config"):
            self.add_syslog_config(port, vrf_list=vrf_list, is_set_source=is_set_source, is_set_vrf=is_set_vrf)

        with allure.step("Check syslog config is configured successfully"):
            self.check_syslog_config_exist(port, vrf_list=vrf_list, is_set_source=is_set_source, is_set_vrf=is_set_vrf)

        with allure.step("Check interface send syslog msg before reboot "):
            self.check_syslog_msg_is_sent(routed_interfaces, mgmt_interface, port, vrf_list=vrf_list,
                                          is_set_source=is_set_source,
                                          logging_data=TEST_FORWARD_FLAGS_AND_MSGS.values(), rsyslog=True)

        with allure.step("Config save"):
            self.duthost.command("sudo config save -y")

        reboot_type = request.config.getoption("--ssip_reboot_type")
        if reboot_type == "random":
            reboot_type_list = ["cold", "warm", "fast", "soft"]
            reboot_type = random.choice(reboot_type_list)
        with allure.step("Do {}".format(reboot_type)):
            reboot(self.duthost, localhost, reboot_type=reboot_type, reboot_helper=None, reboot_kwargs=None)

        with allure.step("After boot,add ip neigh for tested interface"):
            for vrf in vrf_list:
                for k, v in list(SYSLOG_TEST_DATA[vrf].items()):
                    if vrf == "default":
                        dev = routed_interfaces[0]
                    else:
                        dev = vrf
                    replace_ip_neigh(self.duthost, neighbour=v["syslog_server_ip"],
                                     neigh_mac_addr=v["syslog_server_mac"],
                                     dev=dev)

        with allure.step("Check syslog config still exists after {}".format(reboot_type)):
            self.check_syslog_config_exist(port, vrf_list=vrf_list, is_set_source=is_set_source, is_set_vrf=is_set_vrf)

        with allure.step("Check interface send syslog msg "):
            self.check_syslog_msg_is_sent(routed_interfaces, mgmt_interface, port,
                                          vrf_list=vrf_list, is_set_source=is_set_source,
                                          logging_data=TEST_FORWARD_FLAGS_AND_MSGS.values(), rsyslog=True)

    @pytest.mark.parametrize("vrf", VRF_LIST[1:])
    def test_remove_vrf_exist_syslog_config(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                                            enum_frontend_asic_index, vrf):
        """
        Validates that disabling mgmt VRF or removing data VRF exists in syslog config, there will be an error prompt.
        1. Add syslog config with vrf
        2. Check adding syslog config succeeds
        3. Disable or remove vrf
        4. Check There is an error prompt
        """
        self.duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        expected_msg = r'.*Error: Failed to remove VRF device: {} is in use by SYSLOG_SERVER*'.format(
            vrf)

        with allure.step("Add vrf {} into syslog config".format(vrf)):
            self.add_syslog_config(port=SYSLOG_DEFAULT_PORT, vrf_list=[vrf], is_set_source=False, is_set_vrf=True)
        with allure.step("Check syslog config is configured successfully"):
            self.check_syslog_config_exist(port=SYSLOG_DEFAULT_PORT, vrf_list=[vrf], is_set_source=False,
                                           is_set_vrf=True)
        with allure.step("Remove vrf {}".format(vrf)):
            err_msg = remove_vrf(self.duthost, vrf)["stderr"]
            logger.info("Check there is an error prompt:{}".format(err_msg))
            pytest_assert(re.search(expected_msg, err_msg),
                          "Error msg is not correct: Expectd msg:{}, actual msg:{}".format(expected_msg, err_msg))

    def test_syslog_protocol_filter_severity(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                                             enum_frontend_asic_index, routed_interfaces, mgmt_interface):
        """
        Validates syslog protocol, filter and severity work

        1. Add syslog config
        2. Check adding syslog config succeeds
        3. Add protocol tcp and verify changes
        4. Send message with tcp protocol and verify packet send
        5. Send message with udp protocol and verify packet not send
        6. Configure include filter
        7. Send message with include filter and verify packet send
        8. Send message without include filter and verify packet not send
        9. Remove include filter
        10. Configure exclude filter
        11. Send message with exclude regex and verify packet not send
        12. Send message without exclude filter and verify packet send
        13. Remove exclude filter
        14. Send message with not default syslog severity and verify it not sent
        """
        syslog_config = {"is_set_vrf": False, "is_set_source": True, "port": 650, "vrf_list": 'default'}
        default_vrf_rsyslog_ip = '100.100.100.1'
        self.duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        self.asichost = self.duthost.asic_instance(enum_frontend_asic_index)
        port = syslog_config["port"]
        vrf_list = syslog_config["vrf_list"].split()
        is_set_source = syslog_config["is_set_source"]
        is_set_vrf = syslog_config["is_set_vrf"]

        with allure.step("Add syslog config"):
            self.add_syslog_config(port, vrf_list=vrf_list, is_set_source=is_set_source, is_set_vrf=is_set_vrf)

        with allure.step("Check syslog config is configured successfully"):
            self.check_syslog_config_exist(
                port, vrf_list=vrf_list, is_set_source=is_set_source, is_set_vrf=is_set_vrf)

        with allure.step("Configure protocol and verify"):
            self.duthost.shell('sonic-db-cli CONFIG_DB hset "SYSLOG_SERVER|{0}" "protocol" "tcp"'
                               .format(default_vrf_rsyslog_ip))

        with allure.step("Check interface of {} send syslog msg ".format(routed_interfaces[0])):
            logger_flags = '--protocol tcp'
            logging_data = [("--protocol tcp", "")]
            self.check_syslog_msg_is_sent(routed_interfaces, mgmt_interface, port, vrf_list=vrf_list,
                                          is_set_source=is_set_source, logging_data=logging_data)

        with allure.step("Check interface of {} will not send syslog msg ".format(routed_interfaces[0])):
            logger_flags = '--protocol udp'
            logging_data = [("--protocol udp", "")]
            self.check_syslog_msg_is_stopped(routed_interfaces, mgmt_interface, port, vrf_list=vrf_list,
                                             is_set_source=is_set_source, logging_data=logging_data)

        with allure.step("Configure include filter and verify"):
            filter_regex = 'sonic'
            logging_data = [(logger_flags, filter_regex)]
            self.duthost.shell(
                'sonic-db-cli CONFIG_DB hset "SYSLOG_SERVER|{0}" '
                '"filter_type" "include" "filter_regex" {1}'
                .format(default_vrf_rsyslog_ip, filter_regex)
            )

        with allure.step("Check interface of {} send syslog msg with include regex".format(routed_interfaces[0])):
            self.check_syslog_msg_is_sent(routed_interfaces, mgmt_interface, port, vrf_list=vrf_list,
                                          is_set_source=is_set_source, logging_data=logging_data)

        with allure.step("Check interface of {} will not send without include msg ".format(routed_interfaces[0])):
            logging_data = [(logger_flags, '')]
            self.check_syslog_msg_is_stopped(routed_interfaces, mgmt_interface, port, vrf_list=vrf_list,
                                             is_set_source=is_set_source, logging_data=logging_data)

        with allure.step("Remove include filter and verify"):
            self.duthost.shell('sonic-db-cli CONFIG_DB hdel '
                               '"SYSLOG_SERVER|{0}" "filter_type"'.format(default_vrf_rsyslog_ip))

        with allure.step("Configure exclude filter and verify"):
            filter_regex = 'aa'
            self.duthost.shell(
                'sonic-db-cli CONFIG_DB hset'
                ' "SYSLOG_SERVER|{0}" "filter_type" "exclude" "filter_regex" {1}'
                .format(default_vrf_rsyslog_ip, filter_regex)
            )

        with allure.step("Check interface of {} will not send syslog msg with exclude".format(routed_interfaces[0])):
            logging_data = [(logger_flags, filter_regex)]
            self.check_syslog_msg_is_stopped(routed_interfaces, mgmt_interface, port, vrf_list=vrf_list,
                                             is_set_source=is_set_source, logging_data=logging_data)

        with allure.step("Check interface of {} send syslog msg without exclude filter".format(routed_interfaces[0])):
            self.check_syslog_msg_is_sent(routed_interfaces, mgmt_interface, port, vrf_list=vrf_list,
                                          is_set_source=is_set_source, logging_data=logging_data)

        with allure.step("Remove exclude filter and verify"):
            self.duthost.shell('sonic-db-cli CONFIG_DB hdel '
                               '"SYSLOG_SERVER|{0}" "filter_type"'.format(default_vrf_rsyslog_ip))

        with allure.step("Change severity level to notice"):
            self.duthost.shell('sonic-db-cli CONFIG_DB hset'
                               ' "SYSLOG_SERVER|{0}" "severity" "notice"'.format(default_vrf_rsyslog_ip))

        with allure.step("Check interface of {} will not send syslog msg due to severity level".format(
                routed_interfaces[0])):
            logging_data = [(logger_flags, '')]
            self.check_syslog_msg_is_stopped(routed_interfaces, mgmt_interface, port, vrf_list=vrf_list,
                                             is_set_source=is_set_source, logging_data=logging_data)

        with allure.step("Remove syslog config"):
            self.remove_syslog_config(vrf_list=vrf_list)

        with allure.step("Check syslog config is removed"):
            self.check_syslog_config_nonexist(port, vrf_list=vrf_list, is_set_source=is_set_source,
                                              is_set_vrf=is_set_vrf)

        with allure.step("Check interface of {} will not send syslog msg ".format(routed_interfaces[0])):
            self.check_syslog_msg_is_stopped(routed_interfaces, mgmt_interface, port, vrf_list=vrf_list,
                                             is_set_source=is_set_source)
