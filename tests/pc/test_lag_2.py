import pytest

import time
import logging

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # lgtm[py/unused-import]
from tests.ptf_runner import ptf_runner
from tests.common.fixtures.conn_graph_facts import conn_graph_facts
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.assertions import pytest_require
from tests.common.helpers.dut_ports import decode_dut_port_name
from tests.common.fixtures.duthost_utils import disable_route_checker_module

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.usefixtures('disable_route_checker_module')
]

@pytest.fixture(scope="module")
def common_setup_teardown(ptfhost):
    logger.info("########### Setup for lag testing ###########")

    # Copy PTF test into PTF-docker for test LACP DU
    test_files = ['lag_test.py', 'acs_base_test.py', 'router_utils.py']
    for test_file in test_files:
        src = "../ansible/roles/test/files/acstests/%s" % test_file
        dst = "/tmp/%s" % test_file
        ptfhost.copy(src=src, dest=dst)

    yield ptfhost

class LagTest:
    def __init__(self, duthost, tbinfo, ptfhost, nbrhosts, fanouthosts, conn_graph_facts):
        self.duthost     = duthost
        self.tbinfo      = tbinfo
        self.ptfhost     = ptfhost
        self.nbrhosts    = nbrhosts
        self.fanouthosts = fanouthosts
        self.mg_facts         = duthost.get_extended_minigraph_facts(tbinfo)
        self.conn_graph_facts = conn_graph_facts
        self.vm_neighbors     = self.mg_facts['minigraph_neighbors']
        self.fanout_neighbors = self.conn_graph_facts['device_conn'][duthost.hostname] if 'device_conn' in self.conn_graph_facts else {}

    def __get_lag_facts(self):
        return self.duthost.lag_facts(host = self.duthost.hostname)['ansible_facts']['lag_facts']

    def __get_lag_intf_info(self, lag_facts, lag_name):
        # Figure out interface informations
        po_interfaces = lag_facts['lags'][lag_name]['po_config']['ports']
        intf          = lag_facts['lags'][lag_name]['po_config']['ports'].keys()[0]
        return intf, po_interfaces

    def __get_lag_intf_namespace_id(self, lag_facts, lag_name):
        return (lag_facts['lags'][lag_name]['po_namespace_id'])

    def __check_flap(self, lag_facts, lag_name):
        po_intf_num  = len(lag_facts['lags'][lag_name]['po_config']['ports'])
        po_min_links = lag_facts['lags'][lag_name]['po_config']['runner']['min_ports']
        return ((po_intf_num - 1) * 100 / po_min_links) < 75

    def __check_shell_output(self, host, command):
        out = host.shell(command)
        return out['stdout'] == 'True'

    def __check_intf_state(self, vm_host, intf, expect):
        return vm_host.check_intf_link_state(vm_host, intf) == expect

    def __verify_lag_lacp_timing(self, lacp_timer, exp_iface):
        if exp_iface is None:
            return

        # Check LACP timing
        params = {
            'exp_iface': exp_iface,
            'timeout': 35,
            'packet_timing': lacp_timer,
            'ether_type': 0x8809,
            'interval_count': 3
        }
        ptf_runner(self.ptfhost, '/tmp', "lag_test.LacpTimingTest", '/root/ptftests', params=params)

    def __verify_lag_minlink(
        self,
        host,
        lag_name,
        lag_facts,
        neighbor_intf, deselect_time, wait_timeout = 30):
        delay = 5

        try:
            host.shutdown(neighbor_intf)

            # Let PortalChannel react to neighbor interface shutdown
            time.sleep(deselect_time)
            intf, po_interfaces = self.__get_lag_intf_info(lag_facts, lag_name)
            po_flap             = self.__check_flap(lag_facts, lag_name)
            namespace_id        = self.__get_lag_intf_namespace_id(lag_facts, lag_name)
            namespace_prefix = '-n ' + str(namespace_id) if namespace_id else ''


            # Verify PortChannel interfaces are up correctly
            for po_intf in po_interfaces.keys():
                if po_intf != intf:
                    command = 'bash -c "teamdctl %s %s state dump" | python -c "import sys, json; print json.load(sys.stdin)[\'ports\'][\'%s\'][\'runner\'][\'selected\']"' \
                    % (namespace_prefix, lag_name, po_intf)
                    wait_until(wait_timeout, delay, self.__check_shell_output, self.duthost, command)

            # Refresh lag facts
            lag_facts = self.__get_lag_facts()

            # Verify lag member is marked deselected for the shutdown port and all other lag member interfaces are marked selected
            for po_intf in po_interfaces.keys():
                pytest_assert((po_intf != intf) == (lag_facts['lags'][lag_name]['po_stats']['ports'][po_intf]['runner']['selected']),
                              "Unexpected port channel {} member {} selected state: {}".format(lag_name, po_intf, (po_intf != intf)))

            # Verify PortChannel's interface are marked down/up correctly if it should down/up
            exp_state = 'Down' if po_flap else 'Up'
            found_state = lag_facts['lags'][lag_name]['po_intf_stat']
            pytest_assert(found_state == exp_state, "Expected lag {} state {} found {}.".format(lag_name, exp_state, found_state))
        finally:
            # Bring back port in case test error and left testbed in unknow stage
            # Bring up neighbor interface
            host.no_shutdown(neighbor_intf)

            # Verify PortChannel interfaces are up correctly
            for po_intf in po_interfaces.keys():
                if po_intf != intf:
                    command = 'bash -c "teamdctl %s %s state dump" | python -c "import sys, json; print json.load(sys.stdin)[\'ports\'][\'%s\'][\'link\'][\'up\']"'\
                              % (namespace_prefix, lag_name, po_intf)
                    wait_until(wait_timeout, delay, self.__check_shell_output, self.duthost, command)

    def run_single_lag_lacp_rate_test(self, lag_name, lag_facts):
        logger.info("Start checking single lag lacp rate for: %s" % lag_name)

        intf, po_interfaces = self.__get_lag_intf_info(lag_facts, lag_name)
        peer_device         = self.vm_neighbors[intf]['name']

        # Prepare for the remote VM interfaces that using PTF docker to check if the LACP DU packet rate is correct
        iface_behind_lag_member = []
        for neighbor_intf in self.vm_neighbors.keys():
            if peer_device == self.vm_neighbors[neighbor_intf]['name']:
                iface_behind_lag_member.append(self.mg_facts['minigraph_ptf_indices'][neighbor_intf])

        neighbor_lag_intfs = []
        for po_intf in po_interfaces:
            neighbor_lag_intfs.append(self.vm_neighbors[po_intf]['port'])

        try:
            lag_rate_current_setting = None

            # Get the vm host(veos) by it host name
            vm_host = self.nbrhosts[peer_device]['host']

            # Make sure all lag members on VM are set to fast
            for neighbor_lag_member in neighbor_lag_intfs:
                logger.info("Changing lacp rate to fast for %s in %s" % (neighbor_lag_member, peer_device))
                vm_host.set_interface_lacp_rate_mode(neighbor_lag_member, 'fast')
            lag_rate_current_setting = 'fast'
            time.sleep(5)
            for iface_behind_lag in iface_behind_lag_member:
                self.__verify_lag_lacp_timing(1, iface_behind_lag)

            # Make sure all lag members on VM are set to slow
            for neighbor_lag_member in neighbor_lag_intfs:
                logger.info("Changing lacp rate to slow for %s in %s" % (neighbor_lag_member, peer_device))
                vm_host.set_interface_lacp_rate_mode(neighbor_lag_member, 'normal')
            lag_rate_current_setting = 'slow'
            time.sleep(5)
            for iface_behind_lag in iface_behind_lag_member:
                self.__verify_lag_lacp_timing(30, iface_behind_lag)
        finally:
            # Restore lag rate setting on VM in case of failure
            if lag_rate_current_setting == 'fast':
                for neighbor_lag_member in neighbor_lag_intfs:
                    logger.info("Changing lacp rate to slow for %s in %s" % (neighbor_lag_member, peer_device))
                    vm_host.set_interface_lacp_rate_mode(neighbor_lag_member, 'normal')

    def run_single_lag_test(self, lag_name, lag_facts):
        logger.info("Start checking single lag for: %s" % lag_name)

        intf, _ = self.__get_lag_intf_info(lag_facts, lag_name)

        # Figure out fanout switches info if exists for the lag member and run minlink test
        if intf in self.fanout_neighbors.keys():
            peer_device   = self.fanout_neighbors[intf]['peerdevice']
            neighbor_intf = self.fanout_neighbors[intf]['peerport']
            self.__verify_lag_minlink(self.fanouthosts[peer_device], lag_name, lag_facts, neighbor_intf, deselect_time=5)

        # Figure out remote VM and interface info for the lag member and run minlink test
        peer_device   = self.vm_neighbors[intf]['name']
        neighbor_intf = self.vm_neighbors[intf]['port']
        self.__verify_lag_minlink(self.nbrhosts[peer_device]['host'], lag_name, lag_facts, neighbor_intf, deselect_time=95)

    def run_lag_fallback_test(self, lag_name, lag_facts):
        logger.info("Start checking lag fall back for: %s" % lag_name)

        intf, po_interfaces = self.__get_lag_intf_info(lag_facts, lag_name)
        po_fallback         = lag_facts['lags'][lag_name]['po_config']['runner']['fallback']

        # Figure out remote VM and interface info for the lag member and run lag fallback test
        peer_device   = self.vm_neighbors[intf]['name']
        neighbor_intf = self.vm_neighbors[intf]['port']
        vm_host       = self.nbrhosts[peer_device]['host']

        wait_timeout = 120
        delay        = 5
        try:
            # Shut down neighbor interface
            vm_host.shutdown(neighbor_intf)
            wait_until(wait_timeout, delay, self.__check_intf_state, vm_host, neighbor_intf, False)

            # Refresh lag facts
            lag_facts = self.__get_lag_facts()

            # Get teamshow result
            teamshow_result = self.duthost.shell('teamshow')
            logger.debug("Teamshow result: %s" % teamshow_result)

            # Verify lag members
            # 1. All other lag should keep selected state
            # 2. Shutdown port should keep selected state if fallback enabled
            # 3. Shutdown port should marded as deselected if fallback disabled
            #  is marked deselected for the shutdown port and all other lag member interfaces are marked selected
            for po_intf in po_interfaces.keys():
                pytest_assert((po_intf != intf or po_fallback) == (lag_facts['lags'][lag_name]['po_stats']['ports'][po_intf]['runner']['selected']),
                              "Unexpected port channel {} member {} selected state: {}".format(lag_name, po_intf, (po_intf != intf)))

            # The portchannel should marked Up/Down correctly according to po fallback setting
            exp_state = 'Up' if po_fallback else 'Down'
            found_state = lag_facts['lags'][lag_name]['po_intf_stat']
            pytest_assert(found_state == exp_state, "Expected lag {} state {} found {}.".format(lag_name, exp_state, found_state))

        finally:
            # Bring up neighbor interface
            vm_host.no_shutdown(neighbor_intf)
            wait_until(wait_timeout, delay, self.__check_intf_state, vm_host, neighbor_intf, True)

@pytest.mark.parametrize("testcase", ["single_lag",
                                      "lacp_rate",
                                      "fallback"])
def test_lag(common_setup_teardown, duthosts, tbinfo, nbrhosts, fanouthosts, conn_graph_facts, enum_dut_portchannel, testcase):
    ptfhost = common_setup_teardown

    dut_name, dut_lag = decode_dut_port_name(enum_dut_portchannel)

    some_test_ran = False
    for duthost in duthosts:
        if dut_name in [ 'unknown', duthost.hostname ]:
            lag_facts = duthost.lag_facts(host = duthost.hostname)['ansible_facts']['lag_facts']

            test_instance = LagTest(duthost, tbinfo, ptfhost, nbrhosts, fanouthosts, conn_graph_facts)

            # Test for each lag
            if dut_lag == "unknown":
                test_lags = lag_facts['names']
            else:
                pytest_require(dut_lag in lag_facts['names'], "No lag {} configuration found in {}".format(dut_lag, duthost.hostname))
                test_lags = [ dut_lag ]

            for lag_name in test_lags:
                if testcase in [ "single_lag",  "lacp_rate" ]:
                    try:
                        lag_facts['lags'][lag_name]['po_config']['runner']['min_ports']
                    except KeyError:
                        msg = "Skip {} for lag {} due to min_ports not exists".format(testcase, lag_name)
                        pytest_require(lag_name == "unknown", msg)
                        logger.info(msg)
                        continue
                    else:
                        some_test_ran = True
                        if testcase == "single_lag":
                            test_instance.run_single_lag_test(lag_name, lag_facts)
                        else:
                            test_instance.run_single_lag_lacp_rate_test(lag_name, lag_facts)
                else: # fallback testcase
                    try:
                        lag_facts['lags'][lag_name]['po_config']['runner']['fallback']
                    except KeyError:
                        msg = "Skip {} for lag {} due to fallback was not set for it".format(testcase, lag_name)
                        pytest_require(lag_name == "unknown", msg)
                        continue
                    else:
                        some_test_ran = True
                        test_instance.run_lag_fallback_test(lag_name, lag_facts)

    pytest_assert(some_test_ran, "Didn't run any test.")
