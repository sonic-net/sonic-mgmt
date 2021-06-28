import logging
import os
import pytest
import random
import time

from qos_fixtures import lossless_prio_dscp_map
from qos_helpers import ansible_stdout_to_str, get_phy_intfs, get_addrs_in_subnet, get_active_vlan_members, get_vlan_subnet, natural_keys
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # lgtm[py/unused-import]
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.pfc_storm import PFCStorm

pytestmark = [
    pytest.mark.topology('t0')
]

logger = logging.getLogger(__name__)

PFC_PKT_COUNT = 1000000000

PTF_FILE_REMOTE_PATH = '~/ptftests/pfc_pause_test.py'
PTF_PKT_COUNT = 50
PTF_PKT_INTVL_SEC = 0.1
PTF_PASS_RATIO_THRESH = 0.6

""" Maximum number of interfaces to test on a DUT """
MAX_TEST_INTFS_COUNT = 4

@pytest.fixture(scope="module", autouse=True)
def pfc_test_setup(duthosts, rand_one_dut_hostname, tbinfo):
    """
    Generate configurations for the tests

    Args:
        duthosts(AnsibleHost) : multi dut instance
        rand_one_dut_hostname(string) : one of the dut instances from the multi dut

    Yields:
        setup(dict): DUT interfaces, PTF interfaces, PTF IP addresses, and PTF MAC addresses
    """

    """ Get all the active physical interfaces enslaved to the Vlan """
    """ These interfaces are actually server-faced interfaces at T0 """
    duthost = duthosts[rand_one_dut_hostname]
    vlan_members = get_active_vlan_members(duthost)

    """ Get Vlan subnet """
    vlan_subnet = get_vlan_subnet(duthost)

    """ Generate IP addresses for servers in the Vlan """
    vlan_ip_addrs = get_addrs_in_subnet(vlan_subnet, len(vlan_members))

    """ Generate MAC addresses 00:00:00:00:00:XX for servers in the Vlan """
    vlan_mac_addrs = [5 * '00:' + format(k, '02x') for k in random.sample(range(1, 256), len(vlan_members))]

    """ Find correspoinding interfaces on PTF """
    phy_intfs = get_phy_intfs(duthost)
    phy_intfs.sort(key=natural_keys)
    vlan_members.sort(key=natural_keys)
    vlan_members_index = [phy_intfs.index(intf) for intf in vlan_members]
    ptf_intfs = ['eth' + str(i) for i in vlan_members_index]

    """ Disable DUT's PFC wd """
    duthost.shell('sudo pfcwd stop')

    yield {
                  'vlan_members': vlan_members,
                  'ptf_intfs': ptf_intfs,
                  'vlan_ip_addrs': vlan_ip_addrs,
                  'vlan_mac_addrs':  vlan_mac_addrs
                }

    """ Enable DUT's PFC wd """
    if 'dualtor' not in tbinfo['topo']['name']:
        duthost.shell('sudo pfcwd start_default')

def run_test(pfc_test_setup, fanouthosts, duthost, ptfhost, conn_graph_facts,
             fanout_info, traffic_params, pause_prio=None, queue_paused=True,
             send_pause=True, pfc_pause=True, max_test_intfs_count=128):
    """
    Run the test

    Args:
        pfc_test_setup(fixture) : setup fixture
        fanouthosts(AnsibleHost) : fanout instance
        duthost(AnsibleHost) : dut instance
        ptfhost(AnsibleHost) : ptf instance
        conn_graph_facts(fixture) : Testbed topology
        fanout_info(fixture) : fanout graph info
        traffic_params(dict) : dict containing the dscp of test dscp and background dscp
        pause_prio(string) : priority of PFC franme
        queue_paused(bool) : if the queue is expected to be paused
        send_pause(bool) : send pause frames or not
        pfc_pause(bool) : send PFC pause frames or not
        max_test_intfs_count(int) : maximum count of interfaces to test. By default, it is a very large value to cover all the interfaces

    Return:
        Number of iterations and number of passed iterations for each tested interface.
    """

    setup = pfc_test_setup
    dut_intfs = setup['vlan_members']
    ptf_intfs = setup['ptf_intfs']
    ptf_ip_addrs = setup['vlan_ip_addrs']
    ptf_mac_addrs = setup['vlan_mac_addrs']
    """ Clear DUT's PFC counters """
    duthost.sonic_pfc_counters(method="clear")


    results = dict()

    all_peer_dev = set()
    storm_handle = None
    for i in range(min(max_test_intfs_count, len(ptf_intfs))):
        src_index = i
        dst_index = (i + 1) % len(ptf_intfs)

        src_intf = ptf_intfs[src_index]
        dst_intf = ptf_intfs[dst_index]

        src_ip = ptf_ip_addrs[src_index]
        dst_ip = ptf_ip_addrs[dst_index]

        src_mac = ptf_mac_addrs[src_index]
        dst_mac = ptf_mac_addrs[dst_index]

        """ DUT interface to pause """
        dut_intf_paused = dut_intfs[dst_index]

        """ Clear MAC table in DUT """
        duthost.shell('sonic-clear fdb all')
        time.sleep(2)

        if send_pause:
            peer_device = conn_graph_facts['device_conn'][duthost.hostname][dut_intf_paused]['peerdevice']
            peer_port = conn_graph_facts['device_conn'][duthost.hostname][dut_intf_paused]['peerport']
            peer_info = { 'peerdevice': peer_device,
                          'pfc_fanout_interface': peer_port
                        }

            if not pfc_pause:
                pause_prio = None

            if not storm_handle:
                storm_handle = PFCStorm(duthost, fanout_info, fanouthosts,
                                        pfc_queue_idx=pause_prio,
                                        pfc_frames_number=PFC_PKT_COUNT,
                                        peer_info=peer_info)

            storm_handle.update_peer_info(peer_info)
            if not all_peer_dev or peer_device not in all_peer_dev:
                storm_handle.deploy_pfc_gen()
            all_peer_dev.add(peer_device)
            storm_handle.start_storm()
            """ Wait for PFC pause frame generation """
            time.sleep(1)

        """ Run PTF test """
        logger.info("Running test: src intf: {} dest intf: {}".format(dut_intfs[src_index], dut_intfs[dst_index]))
        intf_info = '--interface %d@%s --interface %d@%s' % (src_index, src_intf, dst_index, dst_intf)

        test_params = ("mac_src=\'%s\';" % src_mac
                       + "mac_dst=\'%s\';" % dst_mac
                       + "ip_src=\'%s\';" % src_ip
                       + "ip_dst=\'%s\';" % dst_ip
                       + "dscp=%d;" % traffic_params['dscp']
                       + "dscp_bg=%d;" % traffic_params['dscp_bg']
                       + "pkt_count=%d;" % PTF_PKT_COUNT
                       + "pkt_intvl=%f;" % PTF_PKT_INTVL_SEC
                       + "port_src=%d;" % src_index
                       + "port_dst=%d;" % dst_index
                       + "queue_paused=%s;" % queue_paused
                       + "dut_has_mac=False")

        cmd = 'ptf --test-dir %s pfc_pause_test %s --test-params="%s"' % (os.path.dirname(PTF_FILE_REMOTE_PATH), intf_info, test_params)
        print cmd
        stdout = ansible_stdout_to_str(ptfhost.shell(cmd)['stdout'])
        words = stdout.split()

        """
        Expected format: "Passes: a / b"
        where a is # of passed iterations and b is total # of iterations
        """
        if len(words) != 4:
            print 'Unknown PTF test result format'
            results[dut_intf_paused] = [0, 0]

        else:
            results[dut_intf_paused] = [int(words[1]), int(words[3])]
        time.sleep(1)

        if send_pause:
            """ Stop PFC / FC storm """
            storm_handle.stop_storm()
            time.sleep(1)

    return results

# For this test, we use the fanout connected to the DUT to send PFC pause frames.
# The fanout needs to send PFC frames fast enough so that the queue remains completely paused for the entire duration of the test.
# The inter packet interval between PFC frames to completely block a queue vary based on link speed and we have seen flakiness in our test runs.
# Since this test is already covered under the 'ixia' folder where we use a traffic generator to generate pause frames, skipping this here.
@pytest.mark.skip(reason="Fanout needs to send PFC frames fast enough to completely pause the queue")
def test_pfc_pause_lossless(pfc_test_setup, fanouthosts, duthost, ptfhost,
                            conn_graph_facts, fanout_graph_facts,
                            lossless_prio_dscp_map, enum_dut_lossless_prio):

    """
    Test if PFC pause frames can pause a lossless priority without affecting the other priorities

    Args:
        pfc_test_setup(fixture) : setup fixture
        fanouthosts(AnsibleHost) : fanout instance
        duthost(AnsibleHost) : dut instance
        ptfhost(AnsibleHost) : ptf instance
        conn_graph_facts(fixture) : Testbed topology
        fanout_graph_facts(fixture) : fanout graph info
        lossless_prio_dscp_map(dict) : lossless priorities and their DSCP values
        enum_dut_lossless_prio (str): name of lossless priority to test
    """

    test_errors = ""
    errors = []
    prio = int(enum_dut_lossless_prio.split('|')[-1])
    dscp = lossless_prio_dscp_map[prio]
    other_lossless_prio = 4 if prio == 3 else 3


    """ DSCP values for other lossless priority """
    other_lossless_dscps = lossless_prio_dscp_map[other_lossless_prio]
    """ DSCP values for lossy priorities """
    lossy_dscps = list(set(range(64)) - set(other_lossless_dscps) - set(dscp))

    """ We also need to test some DSCP values for lossy priorities """
    other_dscps = other_lossless_dscps + lossy_dscps[0:2]

    for dscp_bg in other_dscps:
        logger.info("Testing dscp: {} and background dscp: {}".format(dscp, dscp_bg))
        traffic_params = {'dscp': dscp[0], 'dscp_bg': dscp_bg}
        results = run_test(pfc_test_setup,
                           fanouthosts,
                           duthost,
                           ptfhost,
                           conn_graph_facts,
                           fanout_graph_facts,
                           traffic_params,
                           queue_paused=True,
                           send_pause=True,
                           pfc_pause=True,
                           pause_prio=prio,
                           max_test_intfs_count=MAX_TEST_INTFS_COUNT)

        """ results should not be none """
        if results is None:
            test_errors += "Dscp: {}, Background Dscp: {}, Result is empty\n".format(dscp, dscp_bg)

        errors = dict()
        for intf in results:
            if len(results[intf]) != 2:
                continue

            pass_count = results[intf][0]
            total_count = results[intf][1]

            if total_count == 0:
                continue

            if pass_count < total_count * PTF_PASS_RATIO_THRESH:
                errors[intf] = results[intf]

        if len(errors) > 0:
            test_errors += "Dscp: {}, Background Dscp: {}, errors occured: {}\n"\
                           .format(dscp, dscp_bg, " ".join(["{}:{}".format(k,v) for k, v in errors.items()]))

    pytest_assert(len(test_errors) == 0, test_errors)

def test_no_pfc(pfc_test_setup, fanouthosts, duthost, ptfhost, conn_graph_facts,
                fanout_graph_facts, lossless_prio_dscp_map, enum_dut_lossless_prio):

    """
    Test if lossless and lossy priorities can forward packets in the absence of PFC pause frames

    Args:
        pfc_test_setup(fixture) : setup fixture
        fanouthosts(AnsibleHost) : fanout instance
        duthost(AnsibleHost) : dut instance
        ptfhost(AnsibleHost) : ptf instance
        conn_graph_facts(fixture) : Testbed topology
        fanout_graph_facts(fixture) : fanout graph info
        lossless_prio_dscp_map(dict) : lossless priorities and their DSCP values
        enum_dut_lossless_prio (str): name of lossless priority to test
    """

    test_errors = ""
    errors = []
    prio = int(enum_dut_lossless_prio.split('|')[-1])
    dscp = lossless_prio_dscp_map[prio]
    other_lossless_prio = 4 if prio == 3 else 3

    """ DSCP values for other lossless priority """
    other_lossless_dscps = lossless_prio_dscp_map[other_lossless_prio]
    """ DSCP values for lossy priorities """
    lossy_dscps = list(set(range(64)) - set(other_lossless_dscps) - set(dscp))

    """ We also need to test some DSCP values for lossy priorities """
    other_dscps = other_lossless_dscps + lossy_dscps[0:2]

    for dscp_bg in other_dscps:
        logger.info("Testing dscp: {} and background dscp: {}".format(dscp, dscp_bg))
        traffic_params = {'dscp': dscp[0], 'dscp_bg': dscp_bg}
        results = run_test(pfc_test_setup,
                           fanouthosts,
                           duthost,
                           ptfhost,
                           conn_graph_facts,
                           fanout_graph_facts,
                           traffic_params,
                           queue_paused=False,
                           send_pause=False,
                           pfc_pause=None,
                           pause_prio=None,
                           max_test_intfs_count=MAX_TEST_INTFS_COUNT)

        """ results should not be none """
        if results is None:
            test_errors += "Dscp: {}, Background Dscp: {}, Result is empty\n".format(dscp, dscp_bg)

        errors = dict()
        for intf in results:
            if len(results[intf]) != 2:
                continue

            pass_count = results[intf][0]
            total_count = results[intf][1]

            if total_count == 0:
                continue

            if pass_count < total_count * PTF_PASS_RATIO_THRESH:
                errors[intf] = results[intf]

        if len(errors) > 0:
            test_errors += "Dscp: {}, Background Dscp: {}, errors occured: {}\n"\
                           .format(dscp, dscp_bg, " ".join(["{}:{}".format(k,v) for k, v in errors.items()]))

    pytest_assert(len(test_errors) == 0, test_errors)
