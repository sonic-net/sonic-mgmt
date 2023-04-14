import pytest

import time
import logging

from tests.ptf_runner import ptf_runner
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('wan-pub', 'wan-pub-cisco'),
]

# The dir will be deleted from host, so be sure not to use system dir
TEST_DIR = "/tmp/acstests/"


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


@pytest.fixture(scope="function")
def add_member_back_to_ch_grp(duthost, nbrhosts, tbinfo):
    logger.info("########### Recover channel group configuration ###########")

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    vm_neighbors = mg_facts['minigraph_neighbors']

    yield
    for _, neighbor in list(vm_neighbors.items()):
        nbrhosts[neighbor['name']]['host'].add_member_to_channel_grp(neighbor['port'], 1)


def verify_lag_lacp_timing(runner, lacp_timer, exp_iface):
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
    ptf_runner(runner, TEST_DIR, "lag_test.LacpTimingTest", '/root/ptftests', params=params)


def check_intf_state_down(duthost, intf):
    cmd = "show ip int|grep {}|awk \'{{print $3}}\'".format(intf)
    status = duthost.shell(cmd, module_ignore_errors=False)['stdout']
    return status == 'up/down'


def check_intf_state_up(duthost, intf):
    cmd = "show ip int|grep {}|awk \'{{print $3}}\'".format(intf)
    status = duthost.shell(cmd, module_ignore_errors=False)['stdout']
    return status == 'up/up'


def get_lag_intf_info(lag_facts, lag_name):
    # Figure out interface informations
    po_interfaces = lag_facts['lags'][lag_name]['po_config']['ports']
    intf = list(lag_facts['lags'][lag_name]['po_config']['ports'].keys())[0]
    return intf, po_interfaces


def set_lacp_to_slow_mode(duthost, lag_facts, tbinfo):
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    for lag_name in lag_facts['names']:
        for intf in list(lag_facts['lags'][lag_name]['po_config']['ports'].keys()):
            cmd = "sudo config portchannel member del {} {}".format(lag_name, intf)
            duthost.shell(cmd, module_ignore_errors=False)
        cmd = "sudo config portchannel del {}".format(lag_name)
        duthost.shell(cmd, module_ignore_errors=False)

    for lag_name in lag_facts['names']:
        cmd = "sudo config portchannel add {} --fast-rate=false".format(lag_name)
        duthost.shell(cmd, module_ignore_errors=False)

        for intf in list(lag_facts['lags'][lag_name]['po_config']['ports'].keys()):
            cmd = "sudo config portchannel member add {} {}".format(lag_name, intf)
            duthost.shell(cmd, module_ignore_errors=False)

            for neighbor in mg_facts['minigraph_portchannel_interfaces']:
                if neighbor['attachto'] == lag_name:
                    cmd = "sudo config interface ip add {} {}".format(
                          lag_name,  neighbor['subnet'])
                    duthost.shell(cmd, module_ignore_errors=False)


def set_lacp_to_fast_mode(duthost, lag_facts, tbinfo):
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    for lag_name in lag_facts['names']:
        for intf in list(lag_facts['lags'][lag_name]['po_config']['ports'].keys()):
            cmd = "sudo config portchannel member del {} {}".format(lag_name, intf)
            duthost.shell(cmd, module_ignore_errors=False)
        cmd = "sudo config portchannel del {}".format(lag_name)
        duthost.shell(cmd, module_ignore_errors=False)

    for lag_name in lag_facts['names']:
        cmd = "sudo config portchannel add {} --fast-rate=true".format(lag_name)
        duthost.shell(cmd, module_ignore_errors=False)

        for intf in list(lag_facts['lags'][lag_name]['po_config']['ports'].keys()):
            cmd = "sudo config portchannel member add {} {}".format(lag_name, intf)
            duthost.shell(cmd, module_ignore_errors=False)

            for neighbor in mg_facts['minigraph_portchannel_interfaces']:
                if neighbor['attachto'] == lag_name:
                    cmd = "sudo config interface ip add {} {}".format(
                          lag_name,  neighbor['subnet'])
                    duthost.shell(cmd, module_ignore_errors=False)


def test_slow_mode_link_down_check(common_setup_teardown, duthost, tbinfo, nbrhosts):
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    vm_neighbors = mg_facts['minigraph_neighbors']
    lag_facts = duthost.lag_facts(host=duthost.hostname)['ansible_facts']['lag_facts']

    set_lacp_to_slow_mode(duthost, lag_facts, tbinfo)

    time.sleep(5)
    """
    #check lacp pdu with slow mode
    for lag_name in lag_facts['names']:
        intf, _ = get_lag_intf_info(lag_facts, lag_name)
        peer_device = vm_neighbors[intf]['name']

        iface_behind_lag_member = []
        for neighbor_intf in vm_neighbors.keys():
            if peer_device == vm_neighbors[neighbor_intf]['name']:
                iface_behind_lag_member.append(mg_facts['minigraph_ptf_indices'][neighbor_intf])

            for iface_behind_lag in iface_behind_lag_member:
                verify_lag_lacp_timing(ptfhost, 30, iface_behind_lag)
    """
    # check portchannel status, after shutdown/unconfigure portchannel on peer device
    for _, neighbor in list(vm_neighbors.items()):
        nbrhosts[neighbor['name']]['host'].shutdown(neighbor['port'])

    for lag_name in lag_facts['names']:
        pytest_assert(wait_until(91, 3, 1, check_intf_state_down, duthost, lag_name),
                      "After all of peer port channel member interface shutdown,\
                       interface {} is not down".format(lag_name))


def test_slow_mode_rm_member_check(common_setup_teardown, duthost, tbinfo, nbrhosts, add_member_back_to_ch_grp):
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    vm_neighbors = mg_facts['minigraph_neighbors']
    lag_facts = duthost.lag_facts(host=duthost.hostname)['ansible_facts']['lag_facts']

    set_lacp_to_slow_mode(duthost, lag_facts, tbinfo)

    time.sleep(5)

    """
    #check lacp pdu with slow mode
    for lag_name in lag_facts['names']:
        intf, _ = get_lag_intf_info(lag_facts, lag_name)
        peer_device = vm_neighbors[intf]['name']

        iface_behind_lag_member = []
        for neighbor_intf in vm_neighbors.keys():
            if peer_device == vm_neighbors[neighbor_intf]['name']:
                iface_behind_lag_member.append(mg_facts['minigraph_ptf_indices'][neighbor_intf])

            for iface_behind_lag in iface_behind_lag_member:
                verify_lag_lacp_timing(ptfhost, 30, iface_behind_lag)
    """

    # check portchannel status, after shutdown/unconfigure portchannel on peer device
    for _, neighbor in list(vm_neighbors.items()):
        nbrhosts[neighbor['name']]['host'].rm_member_from_channel_grp(neighbor['port'], 1)

    for lag_name in lag_facts['names']:
        pytest_assert(wait_until(30, 3, 1, check_intf_state_down, duthost, lag_name),
                      "After all of peer port channel member interface shutdown,\
                       interface {} is not down".format(lag_name))


def test_slow_mode_link_up_check(common_setup_teardown, duthost, tbinfo, nbrhosts):
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    vm_neighbors = mg_facts['minigraph_neighbors']
    lag_facts = duthost.lag_facts(host=duthost.hostname)['ansible_facts']['lag_facts']

    set_lacp_to_slow_mode(duthost, lag_facts, tbinfo)

    """
    #check lacp pdu with slow mode
    for lag_name in lag_facts['names']:
        intf, _ = get_lag_intf_info(lag_facts, lag_name)
        peer_device = vm_neighbors[intf]['name']

        iface_behind_lag_member = []
        for neighbor_intf in vm_neighbors.keys():
            if peer_device == vm_neighbors[neighbor_intf]['name']:
                iface_behind_lag_member.append(mg_facts['minigraph_ptf_indices'][neighbor_intf])

            for iface_behind_lag in iface_behind_lag_member:
                verify_lag_lacp_timing(ptfhost, 30, iface_behind_lag)
    """

    # check portchannel status, after shutdown/unconfigure portchannel on peer device
    for _, neighbor in list(vm_neighbors.items()):
        nbrhosts[neighbor['name']]['host'].no_shutdown(neighbor['port'])

    for lag_name in lag_facts['names']:
        pytest_assert(wait_until(180, 3, 0, check_intf_state_up, duthost, lag_name),
                      "After all of peer port channel member interface\
                       no shutdown, interface {} is not up".format(lag_name))


def test_fast_mode_link_down_check(common_setup_teardown, duthost, tbinfo, nbrhosts):
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    vm_neighbors = mg_facts['minigraph_neighbors']
    lag_facts = duthost.lag_facts(host=duthost.hostname)['ansible_facts']['lag_facts']

    set_lacp_to_fast_mode(duthost, lag_facts, tbinfo)

    time.sleep(5)

    """
    #check lacp pdu with fast mode
    for lag_name in lag_facts['names']:
        intf, _ = get_lag_intf_info(lag_facts, lag_name)
        peer_device = vm_neighbors[intf]['name']

        iface_behind_lag_member = []
        for neighbor_intf in vm_neighbors.keys():
            if peer_device == vm_neighbors[neighbor_intf]['name']:
                iface_behind_lag_member.append(mg_facts['minigraph_ptf_indices'][neighbor_intf])

            for iface_behind_lag in iface_behind_lag_member:
                verify_lag_lacp_timing(ptfhost, 1, iface_behind_lag)
    """

    # check portchannel status, after shutdown/unconfigure portchannel on peer device
    for _, neighbor in list(vm_neighbors.items()):
        nbrhosts[neighbor['name']]['host'].shutdown(neighbor['port'])

    for lag_name in lag_facts['names']:
        pytest_assert(wait_until(1, 1, 0, check_intf_state_down, duthost, lag_name),
                      "After all of peer port channel member interface\
                       shutdown, interface {} is not down".format(lag_name))


def test_fast_mode_link_up_check(common_setup_teardown, duthost, tbinfo, nbrhosts):
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    vm_neighbors = mg_facts['minigraph_neighbors']
    lag_facts = duthost.lag_facts(host=duthost.hostname)['ansible_facts']['lag_facts']
    set_lacp_to_fast_mode(duthost, lag_facts, tbinfo)

    time.sleep(5)

    """
    # check lacp pdu with fast mode
    for lag_name in lag_facts['names']:
        intf, _ = get_lag_intf_info(lag_facts, lag_name)
        peer_device = vm_neighbors[intf]['name']

        iface_behind_lag_member = []
        for neighbor_intf in vm_neighbors.keys():
            if peer_device == vm_neighbors[neighbor_intf]['name']:
                iface_behind_lag_member.append(mg_facts['minigraph_ptf_indices'][neighbor_intf])

            for iface_behind_lag in iface_behind_lag_member:
                verify_lag_lacp_timing(ptfhost, 1, iface_behind_lag)
    """

    # check portchannel status, after shutdown/unconfigure portchannel on peer device
    for _, neighbor in list(vm_neighbors.items()):
        nbrhosts[neighbor['name']]['host'].no_shutdown(neighbor['port'])

    for lag_name in lag_facts['names']:
        pytest_assert(wait_until(1, 1, 1, check_intf_state_up, duthost, lag_name),
                      "After all of peer port channel member interface\
                      no shutdown, interface {} is not up".format(lag_name))
