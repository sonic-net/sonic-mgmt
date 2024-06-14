import logging
import pytest
import threading
import random
import allure
import re

from scapy.all import rdpcap
from .syslog_utils import create_vrf, remove_vrf, add_syslog_server, del_syslog_server, capture_syslog_packets,\
    replace_ip_neigh, is_mgmt_vrf_enabled, bind_interface_to_vrf, check_vrf, TCPDUMP_CAPTURE_TIME, DUT_PCAP_FILEPATH
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.reboot import reboot, SONIC_SSH_PORT, SONIC_SSH_REGEX
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network, IPv6Network
from tests.common.fixtures.duthost_utils import backup_and_restore_config_db_on_duts    # noqa F401
from tests.common.config_reload import config_reload

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
def restore_config_by_config_reload(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    yield
    config_reload(duthosts[enum_rand_one_per_hwsku_frontend_hostname])


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
                            backup_and_restore_config_db_on_duts, localhost):       # noqa F811
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
                               state='absent', delay=1, timeout=30)
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
            if all([syslog_config["server ip"] == syslog_server_ip,
                    syslog_config["source ip"] == source,
                    syslog_config["vrf"] == vrf,
                    syslog_config["port"] == port]):
                return True
        return False

    def verify_syslog_packets(self, tcpdump_file, syslog_server_ip, port, source):
        """
        verify syslog packets

        Args:
            tcpdump_file (str): tcpdump file
            syslog_server_ip (str): Syslog server address
            source (str): Source ip address
            port (str): Server udp port
        Return: True
        """
        packets = rdpcap(tcpdump_file)
        for data in packets:
            proto = "IPv6" if "IPv6" in data else "IP"
            if all([data[proto].dst == syslog_server_ip,
                    data[proto].dport == port,
                    data[proto].src == source if source else True]):
                return True
        return False

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

    def check_syslog_msg_is_sent(self, routed_interfaces, mgmt_interface, port, vrf_list, is_set_source):
        thread_pool = []
        for vrf in vrf_list:
            def check_syslog_one_vrf(routed_interfaces, port, vrf):
                tcpdump_file = self.gen_tcpdump_cmd_and_capture_syslog_packets(routed_interfaces, port, vrf)
                for k, v in list(SYSLOG_TEST_DATA[vrf].items()):
                    if self.is_link_local_ip(v["source_ip"]):
                        continue
                    source_ip = v["source_ip"].split("/")[0] if is_set_source else None
                    pytest_assert(
                        self.verify_syslog_packets(tcpdump_file,
                                                   syslog_server_ip=v["syslog_server_ip"],
                                                   port=800 if port else SYSLOG_DEFAULT_PORT,
                                                   source=source_ip),
                        "Syslog packet with dest_ip:{}, source_ip:{}, port:{}  is not sent on vrf of {}".format(
                            v["syslog_server_ip"], source_ip, port, vrf))
                    logger.info("Vrf {},{}: send syslog msg check pass".format(vrf, k))

            logger.info("Create thread for {} to check syslog msg is sent".format(vrf))
            th = threading.Thread(target=check_syslog_one_vrf, args=(routed_interfaces, port, vrf))
            thread_pool.append(th)
            th.start()

        for thread in thread_pool:
            thread.join(60)

    def is_link_local_ip(self, ip):
        if ip.startswith("fe80::"):
            logger.info("link_local address {} is not supported, the relevant case should be skipped".format(ip))
            return True
        return False

    def check_syslog_msg_is_stopped(self, routed_interfaces, mgmt_interface, port, vrf_list, is_set_source):
        thread_pool = []
        for vrf in vrf_list:
            def check_no_syslog_one_vrf(routed_interfaces, port, vrf):
                tcpdump_file = self.gen_tcpdump_cmd_and_capture_syslog_packets(routed_interfaces, port, vrf)
                for k, v in list(SYSLOG_TEST_DATA[vrf].items()):
                    source_ip = v["source_ip"].split("/")[0] if is_set_source else None
                    pytest_assert(
                        not self.verify_syslog_packets(tcpdump_file,
                                                       syslog_server_ip=v["syslog_server_ip"],
                                                       port=port,
                                                       source=source_ip),
                        "Syslog packet with dest_ip:{}, source_ip:{}, port:{}  is not stopped on vrf of {}".format(
                            v["syslog_server_ip"], source_ip, port, vrf))
                    logger.info("Vrf {},{}: stop syslog msg check pass".format(vrf, k))

            logger.info("Create thread for {} to check syslog msg is stopped".format(vrf))
            th = threading.Thread(target=check_no_syslog_one_vrf, args=(routed_interfaces, port, vrf))
            thread_pool.append(th)
            th.start()

        for thread in thread_pool:
            thread.join(60)

    def gen_tcpdump_cmd_and_capture_syslog_packets(self, routed_interfaces, port, vrf):
        if vrf == VRF_LIST[0]:
            tcpdump_interface = routed_interfaces[0]
        else:
            tcpdump_interface = vrf
        tcpdump_cmd = "sudo timeout {tcpdump_capture_time} tcpdump -i {interface} port {port} -w {dut_pcap_file}"\
            .format(tcpdump_capture_time=TCPDUMP_CAPTURE_TIME, interface=tcpdump_interface,
                    port=port if port else SYSLOG_DEFAULT_PORT,
                    dut_pcap_file=DUT_PCAP_FILEPATH.format(vrf=vrf))
        tcpdump_file = capture_syslog_packets(self.duthost, tcpdump_cmd)
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

        with allure.step("Check interface of {} send syslog msg ".format(routed_interfaces[0])):
            self.check_syslog_msg_is_sent(routed_interfaces, mgmt_interface, port, vrf_list=vrf_list,
                                          is_set_source=is_set_source)

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
            expected_msg = r'.*Error: Invalid value for \"-s\" \/ "--source": {} IP doesn\'t exist in Linux {} VRF'\
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
        self.asichost = self.duthost.asic_instance(enum_frontend_asic_index)
        syslog_config_data = SYSLOG_CONFIG_COMBINATION["vrf_set_source_set_800"]
        port = syslog_config_data["port"]
        vrf_list = syslog_config_data["vrf_list"]
        is_set_source = syslog_config_data["is_set_source"]
        is_set_vrf = syslog_config_data["is_set_vrf"]

        with allure.step("Add syslog config"):
            self.add_syslog_config(port, vrf_list=vrf_list, is_set_source=is_set_source, is_set_vrf=is_set_vrf)

        with allure.step("Check syslog config is configured successfully"):
            self.check_syslog_config_exist(port, vrf_list=vrf_list, is_set_source=is_set_source, is_set_vrf=is_set_vrf)

        with allure.step("Check interface send syslog msg before reboot "):
            self.check_syslog_msg_is_sent(routed_interfaces, mgmt_interface, port, vrf_list=vrf_list,
                                          is_set_source=is_set_source)

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
                                          vrf_list=vrf_list, is_set_source=is_set_source)

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
