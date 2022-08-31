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
from tests.common.helpers.dut_ports import get_duthost_with_name
from tests.common.config_reload import config_reload

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
]

# The dir will be deleted from host, so be sure not to use system dir
TEST_DIR = "/tmp/acstests/"

@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exceptions(rand_one_dut_hostname, loganalyzer):
    """Ignore expected failures logs during test execution."""
    if loganalyzer:
        loganalyzer[rand_one_dut_hostname].ignore_regex.extend([".*missed_ROUTE_TABLE_routes.*"])

    return

@pytest.fixture(scope="module")
def common_setup_teardown(ptfhost):
    logger.info("########### Setup for lag testing ###########")

    ptfhost.shell("mkdir -p {}".format(TEST_DIR))
    # Copy PTF test into PTF-docker for test LACP DU
    test_files = ['lag_test.py', 'acs_base_test.py', 'router_utils.py']
    for test_file in test_files:
        src = "../ansible/roles/test/files/acstests/%s" % test_file
        dst = TEST_DIR + test_file
        ptfhost.copy(src=src, dest=dst)

    yield ptfhost

    ptfhost.file(path=TEST_DIR, state="absent")

def is_vtestbed(duthost):
    return duthost.facts['asic_type'].lower() == "vs"

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
        if is_vtestbed(duthost):
            self.fanout_neighbors = None
        else:
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
        ptf_runner(self.ptfhost, TEST_DIR, "lag_test.LacpTimingTest", '/root/ptftests', params=params)

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
                    command = 'bash -c "teamdctl %s %s state dump" | python -c "import sys, json; print(json.load(sys.stdin)[\'ports\'][\'%s\'][\'runner\'][\'selected\'])"' \
                    % (namespace_prefix, lag_name, po_intf)
                    wait_until(wait_timeout, delay, 0, self.__check_shell_output, self.duthost, command)

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
                    command = 'bash -c "teamdctl %s %s state dump" | python -c "import sys, json; print(json.load(sys.stdin)[\'ports\'][\'%s\'][\'link\'][\'up\'])"'\
                              % (namespace_prefix, lag_name, po_intf)
                    wait_until(wait_timeout, delay, 0, self.__check_shell_output, self.duthost, command)

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
            wait_until(wait_timeout, delay, 0, self.__check_intf_state, vm_host, neighbor_intf, False)

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
            wait_until(wait_timeout, delay, 0, self.__check_intf_state, vm_host, neighbor_intf, True)

@pytest.fixture(autouse=True, scope='module')
def skip_if_no_lags(duthosts):
    def has_lags(dut):
        lag_facts = dut.lag_facts(host = dut.hostname)['ansible_facts']['lag_facts']
        return len(lag_facts['names']) > 0
    some_dut_has_lags = any(has_lags(dut) for dut in duthosts)
    pytest_require(some_dut_has_lags, 'No LAGs found in any DUT')

@pytest.mark.parametrize("testcase", ["single_lag",
                                      "lacp_rate",
                                      "fallback"])
def test_lag(common_setup_teardown, duthosts, tbinfo, nbrhosts, fanouthosts, conn_graph_facts, enum_dut_portchannel_with_completeness_level, testcase):
    # We can't run single_lag test on vtestbed since there is no leaffanout
    if testcase == "single_lag" and is_vtestbed(duthosts[0]):
        pytest.skip("Skip single_lag test on vtestbed")

    ptfhost = common_setup_teardown

    dut_name, dut_lag = decode_dut_port_name(enum_dut_portchannel_with_completeness_level)

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

@pytest.fixture(scope='function')
def ignore_expected_loganalyzer_exceptions(duthosts, rand_one_dut_hostname, loganalyzer):
    """
        Ignore expected failures logs during test execution.

        LAG tests are triggering following orchagent complaints but the don't cause
        harm to DUT.
       Args:
            duthosts: list of DUTs.
            rand_one_dut_hostname: Hostname of a random chosen dut
            loganalyzer: Loganalyzer utility fixture
    """
    # When loganalyzer is disabled, the object could be None
    duthost = duthosts[rand_one_dut_hostname]
    if loganalyzer:
        ignoreRegex = [
            ".*ERR swss[0-9]*#orchagent: :- getPortOperSpeed.*",  # Valid test_lag_db_status and test_lag_db_status_with_po_update
        ]
        loganalyzer[duthost.hostname].ignore_regex.extend(ignoreRegex)

@pytest.fixture(scope='function')
def teardown(duthost):
    """Recover testbed if case of test_lag_db_status_with_po_update failed"""
    original_lag_facts = {}

    original_lag_facts[duthost.hostname] = duthost.lag_facts(host = duthost.hostname)['ansible_facts']['lag_facts']
    yield
    # After test, compare lag_facts to check if port status is unchanged,
    # otherwise recover DUT by reloading minigraph
    try:
        original_data = original_lag_facts[duthost.hostname]
        lag_facts = duthost.lag_facts(host = duthost.hostname)['ansible_facts']['lag_facts']
        for lag_name in original_data['lags'].keys():
            for po_intf, port_info in original_data['lags'][lag_name]['po_stats']['ports'].items():
                if port_info['link']['up'] == lag_facts['lags'][lag_name]['po_stats']['ports'][po_intf]['link']['up']:
                    logger.info("{} of {} is up, ignore it.".format(po_intf, lag_name))
                    continue
                else:
                    logger.info("{}'s lag_facts is changed, original_data {}\n, lag_facts {}".format(duthost.hostname, original_data, lag_facts))
                    raise Exception("Raise exception for config_reload in next step.")
    except Exception as e:
        # If port was removed from portchannel, it will throw KeyError exception, or catch exception in previous steps,
        # reload DUT to recover it
        logger.info("{}'s lag_facts is changed, comparison failed with exception: {}".format(duthost.hostname, repr(e)))
        config_reload(duthost, config_source="minigraph")
    return


def get_oper_status_from_db(duthost, port_name):
    """Get netdev_oper_status from state_db for interface"""
    cmd = "redis-cli -n 6 hget \"PORT_TABLE|{}\" netdev_oper_status".format(port_name)
    status = duthost.shell(cmd, module_ignore_errors=False)['stdout']
    # If PORT_TABLE in STATE_DB doesn't have key netdev_oper_status,
    # check oper_status in APPL_DB instead. This scenario happens on 202012.
    if not status:
        cmd = "redis-cli -n 0 hget \"PORT_TABLE:{}\" oper_status".format(port_name)
        status = duthost.shell(cmd, module_ignore_errors=False)['stdout']
    return status

def get_admin_status_from_db(duthost, port_name):
    """Get netdev_oper_status from state_db for interface"""
    cmd = "redis-cli -n 6 hget \"PORT_TABLE|{}\" admin_status".format(port_name)
    status = duthost.shell(cmd, module_ignore_errors=False)['stdout']
    # If PORT_TABLE in STATE_DB doesn't have key admin_status,
    # check admin_status in APPL_DB instead. This scenario happens on 202012.
    if not status:
        cmd = "redis-cli -n 0 hget \"PORT_TABLE:{}\" admin_status".format(port_name)
        status = duthost.shell(cmd, module_ignore_errors=False)['stdout']
    return status

def check_status_is_syncd(duthost, po_intf, port_info, lag_name):
    """Check if interface's status is synced with the netdev_oper_status in state_db"""
    port_status = port_info['link']['up'] if port_info['link'] else False
    status_from_db = True if str(get_oper_status_from_db(duthost, po_intf)) == 'up' else False
    return status_from_db == port_status

def check_link_is_up(duthost, po_intf, port_info, lag_name):
    """Check if interface's status and the netdev_oper_status in state_db are both up"""
    new_lag_facts = duthost.lag_facts(host = duthost.hostname)['ansible_facts']['lag_facts']
    port_info = new_lag_facts['lags'][lag_name]['po_stats']['ports'][po_intf]
    port_status = port_info['link']['up'] if port_info['link'] else False
    oper_status_from_db = True if str(get_oper_status_from_db(duthost, po_intf)) == 'up' else False
    admin_status_from_db = True if str(get_admin_status_from_db(duthost, po_intf)) == 'up' else False
    return port_status and oper_status_from_db and admin_status_from_db

def check_link_is_down(duthost, po_intf):
    """Check if interface's status and the netdev_oper_status in state_db are both up"""
    oper_status = get_oper_status_from_db(duthost, po_intf)
    admin_status = get_admin_status_from_db(duthost, po_intf)

    return str(oper_status) == 'down' and str(admin_status) == 'down'

def test_lag_db_status(duthosts, enum_dut_portchannel_with_completeness_level, ignore_expected_loganalyzer_exceptions):
    # Test state_db status for lag interfaces
    dut_name, dut_lag = decode_dut_port_name(enum_dut_portchannel_with_completeness_level)
    logger.info("Start test_lag_db_status test on dut {} for lag {}".format(dut_name, dut_lag))
    duthost = get_duthost_with_name(duthosts, dut_name)
    if duthost is None:
        pytest.fail("Failed with duthost is not found for dut name {}.".format(dut_name))

    test_lags = []
    try:
        lag_facts = duthost.lag_facts(host = duthost.hostname)['ansible_facts']['lag_facts']

        # Test for each lag
        if dut_lag == "unknown":
            test_lags = lag_facts['names']
        else:
            pytest_require(dut_lag in lag_facts['names'], "No lag {} configuration found in {}".format(dut_lag, duthost.hostname))
            test_lags = [ dut_lag ]
        # 1. Check if status of interface is in sync with state_db after bootup.
        for lag_name in test_lags:
            for po_intf, port_info in lag_facts['lags'][lag_name]['po_stats']['ports'].items():
                if not check_status_is_syncd(duthost, po_intf, port_info, lag_name):
                    pytest.fail("{} member {}'s status is not synced with oper_status in state_db.".format(lag_name, po_intf))

        # 2. Check if status of interface is in sync with state_db after shutdown/no shutdown.
        for lag_name in test_lags:
            for po_intf, port_info in lag_facts['lags'][lag_name]['po_stats']['ports'].items():
                duthost.shutdown(po_intf)
                # Retrieve lag_facts after shutdown interface
                new_lag_facts = duthost.lag_facts(host = duthost.hostname)['ansible_facts']['lag_facts']
                port_info =  new_lag_facts['lags'][lag_name]['po_stats']['ports'][po_intf]
                pytest_assert(wait_until(15, 1, 0, check_link_is_down, duthost, po_intf),
                "{} member {}'s admin_status or oper_status in state_db is not down.".format(lag_name, po_intf))

                # Retrieve lag_facts after no shutdown interface
                duthost.no_shutdown(po_intf)
                # Sometimes, it has to wait seconds for booting up interface
                pytest_assert(wait_until(15, 1, 0, check_link_is_up, duthost, po_intf, port_info, lag_name),
                    "{} member {}'s status or netdev_oper_status in state_db is not up.".format(lag_name, po_intf))
    finally:
        # Recover interfaces in case of failure
        lag_facts = duthost.lag_facts(host = duthost.hostname)['ansible_facts']['lag_facts']
        for lag_name in test_lags:
            for po_intf, port_info in lag_facts['lags'][lag_name]['po_stats']['ports'].items():
                if port_info['link']['up']:
                        logger.info("{} of {} is up, ignore it.".format(po_intf, lag_name))
                        continue
                else:
                    logger.info("Interface {} of {} is down, no shutdown to recover it.".format(po_intf, lag_name))
                    duthost.no_shutdown(po_intf)

def test_lag_db_status_with_po_update(duthosts, enum_frontend_asic_index, teardown, enum_dut_portchannel_with_completeness_level, ignore_expected_loganalyzer_exceptions):
    """
    test port channel add/deletion and check interface status in state_db
    """
    dut_name, dut_lag = decode_dut_port_name(enum_dut_portchannel_with_completeness_level)
    logger.info("Start test_lag_db_status test on dut {} for lag {}".format(dut_name, dut_lag))
    duthost = get_duthost_with_name(duthosts, dut_name)
    if duthost is None:
        pytest.fail("Failed with duthost is not found for dut name {}.".format(dut_name))

    lag_facts = duthost.lag_facts(host = duthost.hostname)['ansible_facts']['lag_facts']
    asichost = duthost.asic_instance(enum_frontend_asic_index)
    # Test for each lag
    if dut_lag == "unknown":
        test_lags = lag_facts['names']
    else:
        pytest_require(dut_lag in lag_facts['names'], "No lag {} configuration found in {}".format(dut_lag, duthost.hostname))
        test_lags = [ dut_lag ]

    # Check if status of interface is in sync with state_db after removing/adding member.
    for lag_name in test_lags:
        for po_intf, port_info in lag_facts['lags'][lag_name]['po_stats']['ports'].items():
            # 1 Remove port member from portchannel
            asichost.config_portchannel_member(lag_name, po_intf, "del")

            # 2 Shutdown this port to check if status is down
            duthost.shutdown(po_intf)
            pytest_assert(wait_until(15, 1, 0, check_link_is_down, duthost, po_intf),
                "{} member {}'s admin_status or oper_status in state_db is not down.".format(lag_name, po_intf))

            # 3 Add this port back into portchannel and check if status is synced
            asichost.config_portchannel_member(lag_name, po_intf, "add")

            # 4 Retrieve lag_facts after shutdown interface and check if status is synced
            new_lag_facts = duthost.lag_facts(host = duthost.hostname)['ansible_facts']['lag_facts']
            port_info =  new_lag_facts['lags'][lag_name]['po_stats']['ports'][po_intf]
            pytest_assert(wait_until(15, 1, 0, check_status_is_syncd, duthost, po_intf, port_info, lag_name), 
                "{} member {}'s status is not synced with oper_status in state_db.".format(lag_name, po_intf))

            # 5 No shutdown this port to check if status is up
            duthost.no_shutdown(po_intf)
            # Sometimes, it has to wait seconds for booting up interface
            pytest_assert(wait_until(15, 1, 0, check_link_is_up, duthost, po_intf, port_info, lag_name),
                "{} member {}'s admin_status or oper_status in state_db is not up.".format(lag_name, po_intf))
