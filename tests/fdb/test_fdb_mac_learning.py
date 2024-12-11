import logging
import pytest
import time
from tests.common import config_reload
from tests.common.utilities import wait_until

from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # noqa F401
from tests.ptf_runner import ptf_runner
from .utils import fdb_table_has_dummy_mac_for_interface
from tests.common.helpers.ptf_tests_helper import upstream_links    # noqa F401

pytestmark = [
    pytest.mark.topology('t0')
]
logger = logging.getLogger(__name__)


@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exception(loganalyzer, duthosts):

    ignore_errors = [
        r".*ERR swss#orchagent: :- update: Failed to get port by bridge port ID.*",
        r".* ERR swss#tunnel_packet_handler.py: All portchannels failed to come up within \d+ minutes, exiting.*"
        ]
    if loganalyzer:
        for duthost in duthosts:
            loganalyzer[duthost.hostname].ignore_regex.extend(ignore_errors)

    return None


class TestFdbMacLearning:
    """
    TestFdbMacLearning verifies that stale MAC entries are not present in MAC table after doing sonic-clear fdb all
    -shut down all ports
    -config save
    -config reload
    -bring up 1 port. populate fdb
    -bring up 3 more ports. populate fdb.
    -shut down 3 ports added in last step
    -verify that MAC entries connected to shutdown ports are gone from MAC table
    -sonic-clear fdb all
    -populate fdb for the UP port
    -verify that MAC entries connected to shutdown ports not present in MAC table
    """
    DUMMY_MAC_PREFIX = "00:11:22:33:55"
    TEST_MAC = "00:11:22:33:55:66"
    FDB_POPULATE_SLEEP_TIMEOUT = 5
    PTF_HOST_IP = "20.0.0.2"
    PTF_HOST_NETMASK = "24"
    DUT_INTF_IP = "20.0.0.1"
    DUT_INTF_NETMASK = "24"

    def configureInterfaceIp(self, duthost, dut_intf, action=None):
        """
            Configure interface IP address on the DUT

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                action (str): action to perform, add/remove interface IP

            Returns:
                None
        """

        logger.info("{0} an ip entry {1} for {2}".format(action, self.DUT_INTF_IP, dut_intf))
        interfaceIp = "{}/{}".format(self.DUT_INTF_IP, self.DUT_INTF_NETMASK)
        duthost.shell(argv=[
            "config",
            "interface",
            "ip",
            action,
            dut_intf,
            interfaceIp
        ])

    def configureNeighborIp(self, ptfhost, ptf_intf, action=None):
        """
            Configure interface and set IP address on the PTF host

            Args:
                ptfhost (PTF host): PTF instance used
                action (str): action to perform, add/remove interface IP

            Returns:
                None
        """
        ptfhost.shell("ip addr {} {}/{} dev {}".format(action, self.PTF_HOST_IP, self.PTF_HOST_NETMASK, ptf_intf))
        logger.info("{0} an ip entry {1}/{2} for {3} on ptf"
                    .format(action, self.PTF_HOST_IP, self.PTF_HOST_NETMASK, ptf_intf))

    def __runPtfTest(self, ptfhost, testCase='', testParams={}):
        """
            Runs FDB MAC Learning test case on PTF host

            Args:
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                testCase (str): FDB tests test case name
                testParams (dict): Map of test params required by testCase

            Returns:
                None

            Raises:
                RunAnsibleModuleFail if ptf test fails
        """
        logger.info("Running PTF test case '{0}' on '{1}'".format(testCase, ptfhost.hostname))
        ptf_runner(
            ptfhost,
            "ptftests",
            testCase,
            platform_dir="ptftests",
            params=testParams,
            log_file="/tmp/{0}".format(testCase),
            is_python3=True
        )

    @pytest.fixture(scope="class", autouse=True)
    def prepare_test(self, duthosts, rand_one_dut_hostname, ptfhost):
        """
            Select DUT ports which will be used for the testcase
            Get a mapping of selected DUT ports and ptf ports
            shut down all DUT ports, congit save and config reload the DUT before starting the testcases

            Args:
                duthosts: Devices under test
                rand_one_dut_hostname: selected device index
                ptfhost: PTF instance used

            Yields:
                DUT to PTF port mapping
                PTF ports available in topology
                conf_facts
        """
        duthost = duthosts[rand_one_dut_hostname]
        # Get 4 UP ports which will be used for the test
        up_interfaces = []
        ifs_status = duthost.get_interfaces_status()
        logging.info("ifs_status {} ".format(ifs_status))
        for _, interface_info in ifs_status.items():
            if (r'N\/A' != interface_info['alias']) and (r'N\/A' != interface_info['type']) \
                    and ('up' == interface_info['oper']) and (interface_info['vlan'] == 'trunk'):
                up_interfaces.append(interface_info['interface'])

        if len(up_interfaces) < 4:
            pytest.skip('Test FDB MAC Learning: cannot get enough target port to test: {}'.format(up_interfaces))
        up_interface_numbers = []
        for intf in up_interfaces:
            up_interface_numbers.append(int(intf[8:]))
        up_interface_numbers.sort()
        target_ports = []
        for i in range(0, 4):
            target_ports.append("Ethernet"+str(up_interface_numbers[i]))
        logging.info("DUT interfaces selected for running the test are {} ".format(target_ports))

        # Get a mapping between selected DUT ports and PTF ports
        conf_facts = duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']
        port_index_to_name = {v: k for k, v in list(conf_facts['port_index_map'].items())}
        ptf_ports_available_in_topo = ptfhost.host.options['variable_manager'].extra_vars.get("ifaces_map")
        target_ports_to_ptf_mapping = [[] for _ in range(len(target_ports))]
        for i in range(len(target_ports)):
            target_ports_to_ptf_mapping[i].append(target_ports[i])
        for idx, name in list(ptf_ports_available_in_topo.items()):
            if (idx in port_index_to_name and port_index_to_name[idx] in target_ports):
                target_ports_to_ptf_mapping[target_ports.index(port_index_to_name[idx])].append(idx)
        logging.info("DUT to PTF port mapping is {}".format(target_ports_to_ptf_mapping))

        # shut down all ports on DUT, config save and config reload
        dut_ports = conf_facts['port_index_map'].keys()
        logging.info("shutdown all interfaces on DUT")
        for port in dut_ports:
            duthost.shell("sudo config interface shutdown {}".format(port))
        duthost.command('sudo config save -y')
        config_reload(duthost, config_source='config_db', safe_reload=True)
        yield target_ports_to_ptf_mapping, ptf_ports_available_in_topo, conf_facts

    def dynamic_fdb_oper(self, duthost, tbinfo, ptfhost, dut_ptf_ports):
        """function to populate fdb for given dut/ptf ports"""
        testParams = {
           "testbed_type": tbinfo["topo"]["name"],
           "router_mac": duthost.facts["router_mac"],
           "dut_ptf_ports": dut_ptf_ports,
           "dummy_mac_prefix": self.DUMMY_MAC_PREFIX,
           "kvm_support": True
        }
        self.__runPtfTest(ptfhost, "fdb_mac_learning_test.FdbMacLearningTest", testParams)

        res = duthost.command('show mac')
        logging.info("show mac {}".format(res['stdout_lines']))

    def check_mux_status_consistency(self, duthost, ports):
        """
        For given ports, verify that muxcable status on duthost is consistent with muxcable server_status.
        """
        for port in ports:
            res = duthost.show_and_parse(f"show muxcable status {port}")
            if not res or res[0]['status'] != res[0]['server_status']:
                return False
        return True

    def wait_for_interfaces_ready(self, duthost, tbinfo, ports):
        """
        Make sure interfaces are ready for sending traffic.
        """
        if "dualtor" in tbinfo['topo']['name']:
            pytest_assert(wait_until(150, 5, 0, self.check_mux_status_consistency, duthost, ports))
        else:
            time.sleep(30)

    def bringup_uplink_ports(self, duthost, upstream_links): # noqa F811
        """
        For active-active dualtor NIC simulator doesn't install OVS flows for downlink ports until the link status
        becomes consistent which can happen in this case only if upstream connectivity is restored.
        """
        # Get one upstream port
        uplink_intf = list(upstream_links.keys())[0]
        # Check if it's a LAG member
        config_facts = duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']
        portChannels = config_facts['PORTCHANNEL_MEMBER']
        portChannel = None
        members = None
        for intf in portChannels:
            if uplink_intf in portChannels[intf]:
                portChannel = intf
                members = list(portChannels[intf].keys())
                break
        if portChannel:
            min_links = int(config_facts['PORTCHANNEL'][portChannel]['min_links'])
            # Bringup minimum ports for this port channel to be up
            for i in range(min_links):
                duthost.shell("sudo config interface startup {}".format(members[i]))
        else:
            duthost.shell("sudo config interface startup {}".format(uplink_intf))

    def testFdbMacLearning(self, ptfadapter, duthosts, rand_one_dut_hostname, ptfhost, tbinfo, request, prepare_test,
                           upstream_links, setup_standby_ports_on_rand_unselected_tor_unconditionally): # noqa F811
        """
            TestFdbMacLearning verifies stale MAC entries are not present in MAC table after doing sonic-clear fdb all
            -shut down all ports
            -config save
            -config reload
            -bring up 1 port. populate fdb
            -bring up 3 more ports. populate fdb.
            -shut down 3 ports added in last step
            -verify that MAC entries connected to shutdown ports are gone from MAC table
            -sonic-clear fdb all
            -populate fdb for the UP port
            -verify that MAC entries connected to shutdown ports not present in MAC table
        """
        target_ports_to_ptf_mapping, ptf_ports_available_in_topo, _ = prepare_test

        # Find MAC addresses for different PTF interfaces to be used in Testcase
        ptf_interfaces_mac_addresses = []
        for i in range(len(target_ports_to_ptf_mapping)):
            ptf_port = ptf_ports_available_in_topo[target_ports_to_ptf_mapping[i][1]]
            res = ptfhost.shell('cat /sys/class/net/{}/address'.format(ptf_port))
            ptf_interfaces_mac_addresses.append(res['stdout'].upper())

        # Bringup uplink connectivity for muxcable status consistency to happen.
        duthost = duthosts[rand_one_dut_hostname]
        if "dualtor-aa" in tbinfo['topo']['name']:
            self.bringup_uplink_ports(duthost, upstream_links)

        # unshut 1 port and populate fdb for that port. make sure fdb entry is populated in mac table
        target_ports = [target_ports_to_ptf_mapping[0][0]]
        duthost.shell("sudo config interface startup {}".format(target_ports[0]))
        self.wait_for_interfaces_ready(duthost, tbinfo, target_ports)
        self.dynamic_fdb_oper(duthost, tbinfo, ptfhost, [target_ports_to_ptf_mapping[0]])
        pytest_assert(wait_until(300, 2, 1, fdb_table_has_dummy_mac_for_interface, duthost,
                      target_ports_to_ptf_mapping[0][0], self.DUMMY_MAC_PREFIX), "After starting {}"
                      " and populating fdb, corresponding mac address entry not seen in mac table"
                      .format(target_ports_to_ptf_mapping[0][0]))

        # unshut 3 more ports and populate fdb for those ports
        target_ports = [
            target_ports_to_ptf_mapping[1][0],
            target_ports_to_ptf_mapping[2][0],
            target_ports_to_ptf_mapping[3][0]
        ]
        duthost.shell("sudo config interface startup {}-{}".format(target_ports[0], target_ports[2][8:]))
        self.wait_for_interfaces_ready(duthost, tbinfo, target_ports)
        self.dynamic_fdb_oper(duthost, tbinfo, ptfhost, target_ports_to_ptf_mapping[1:])
        for i in range(1, len(target_ports_to_ptf_mapping)):
            pytest_assert(wait_until(300, 2, 1, fdb_table_has_dummy_mac_for_interface, duthost,
                          target_ports_to_ptf_mapping[i][0], self.DUMMY_MAC_PREFIX),
                          "After starting {} and populating fdb, corresponding mac address entry"
                          "not seen in mac table".format(target_ports_to_ptf_mapping[i][0]))

        # shutdown last 3 ports and make sure corresponding entries are gone from MAC address table
        for i in range(1, len(target_ports_to_ptf_mapping)):
            duthost.shell("sudo config interface shutdown {}".format(target_ports_to_ptf_mapping[i][0]))
        time.sleep(30)
        for i in range(1, len(target_ports_to_ptf_mapping)):
            pytest_assert(not (fdb_table_has_dummy_mac_for_interface(duthost, target_ports_to_ptf_mapping[i][0])),
                          "mac entry present when interface {} is down"
                          .format(target_ports_to_ptf_mapping[i][0]))

        # clear all fdb entries on DUT
        duthost.shell("sonic-clear fdb all")

        # after clearing fdb, make sure that no stale entries are present in MAC address table
        self.dynamic_fdb_oper(duthost, tbinfo, ptfhost, [target_ports_to_ptf_mapping[0]])
        if wait_until(100, 1, 1, fdb_table_has_dummy_mac_for_interface, duthost, target_ports_to_ptf_mapping[0][0],
                      self.DUMMY_MAC_PREFIX):
            for i in range(1, len(target_ports_to_ptf_mapping)):
                pytest_assert(not (fdb_table_has_dummy_mac_for_interface(duthost, target_ports_to_ptf_mapping[i][0])),
                              "mac entry present when interface {} is down even after sonic-clear fdb all"
                              .format(target_ports_to_ptf_mapping[i][0]))

    def testARPCompleted(self, ptfadapter, duthosts, rand_one_dut_hostname, ptfhost, tbinfo, request, prepare_test):
        """
            Select a DUT interface and corresponding PTF interface
            If DUT interface is in VLAN, remove it from the vlan
            Configure ip addresses on DUT interface and PTF interface and do a ping test
            Check if the ARP entry on DUT has all details

        """
        target_ports_to_ptf_mapping, ptf_ports_available_in_topo, conf_facts = prepare_test
        duthost = duthosts[rand_one_dut_hostname]
        dut_interface, ptf_port_index = target_ports_to_ptf_mapping[0]
        duthost.shell("sudo config interface startup {}".format(dut_interface))
        for vlan in conf_facts['VLAN_MEMBER']:
            for member_interface in conf_facts['VLAN_MEMBER'][vlan]:
                if (member_interface == dut_interface):
                    duthost.shell("sudo config vlan member del {} {}".format(vlan[4:], member_interface))
        try:
            self.configureInterfaceIp(duthost, dut_interface, action="add")
            self.configureNeighborIp(ptfhost, ptf_ports_available_in_topo[ptf_port_index], action="add")
            ptfhost.shell("ping {} -c 3 -I {}".format(self.DUT_INTF_IP, self.PTF_HOST_IP), module_ignore_errors=True)

        finally:
            show_arp = duthost.command('show arp')
            arp_found = False
            for arp_entry in show_arp['stdout_lines']:
                items = arp_entry.split()
                if (items[0] == self.PTF_HOST_IP):
                    arp_found = True
                    pytest_assert(items[2] == dut_interface, "ARP entry for ip address {}"
                                  " is incomplete. Interface is missing".format(self.PTF_HOST_IP))
            pytest_assert(arp_found, "ARP entry not found for ip address {}".format(self.PTF_HOST_IP))
            self.configureInterfaceIp(duthost, dut_interface, action="remove")
            self.configureNeighborIp(ptfhost, ptf_ports_available_in_topo[ptf_port_index], action="del")
