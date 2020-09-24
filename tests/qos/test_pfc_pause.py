
import pytest
import os
import time
import re
import struct
import random
from tests.common.fixtures.conn_graph_facts import conn_graph_facts
from qos_fixtures import lossless_prio_dscp_map, leaf_fanouts
from qos_helpers import ansible_stdout_to_str, eos_to_linux_intf, start_pause, stop_pause, setup_testbed, gen_testbed_t0, PFC_GEN_FILE, PFC_GEN_REMOTE_PATH

pytestmark = [
    pytest.mark.topology('t0')
]

PFC_PKT_COUNT = 1000000000

PTF_FILE_LOCAL_PATH = '../../ansible/roles/test/files/ptftests/pfc_pause_test.py'
PTF_FILE_REMOTE_PATH = '~/pfc_pause_test.py'
PTF_PKT_COUNT = 50
PTF_PKT_INTVL_SEC = 0.1
PTF_PASS_RATIO_THRESH = 0.6

""" Maximum number of interfaces to test on a DUT """
MAX_TEST_INTFS_COUNT = 4

def run_test_t0(fanouthosts,
                duthost,
                ptfhost,
                conn_graph_facts,
                leaf_fanouts,
                dscp,
                dscp_bg,
                queue_paused,
                send_pause,
                pfc_pause,
                pause_prio,
                pause_time=65535,
                max_test_intfs_count=128):
    """
    @Summary: Run a series of tests on a T0 topology.
    For the T0 topology, we only test Vlan (server-faced) interfaces.
    @param conn_graph_facts: Testbed topology
    @param leaf_fanouts: Leaf fanout switches
    @param dscp: DSCP value of test data packets
    @param dscp_bg: DSCP value of background data packets
    @param queue_paused: if the queue is expected to be paused
    @param send_pause: send pause frames or not
    @param pfc_pause: send PFC pause frames or not
    @param pause_prio: priority of PFC franme
    @param pause_time: pause time quanta. It is 65535 (maximum pause time quanta) by default.
    @param max_test_intfs_count: maximum count of interfaces to test. By default, it is a very large value to cover all the interfaces.
    return: Return # of iterations and # of passed iterations for each tested interface.
    """

    """ Clear DUT's PFC counters """
    duthost.sonic_pfc_counters(method="clear")

    """ Disable DUT's PFC wd """
    duthost.shell('sudo pfcwd stop')

    """ Generate a T0 testbed configuration """
    dut_intfs, ptf_intfs, ptf_ip_addrs, ptf_mac_addrs = gen_testbed_t0(duthost)
    results = dict()

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
            peer_device = conn_graph_facts['device_conn'][dut_intf_paused]['peerdevice']
            peer_port = conn_graph_facts['device_conn'][dut_intf_paused]['peerport']
            peer_port_name = eos_to_linux_intf(peer_port)
            peerdev_ans = fanouthosts[peer_device]

            if not pfc_pause:
                pause_prio = None

            start_pause(host_ans=peerdev_ans,
                        pkt_gen_path=PFC_GEN_REMOTE_PATH,
                        intf=peer_port_name,
                        pkt_count=PFC_PKT_COUNT,
                        pause_duration=pause_time,
                        pause_priority=pause_prio)

            """ Wait for PFC pause frame generation """
            time.sleep(1)

        """ Run PTF test """
        intf_info = '--interface %d@%s --interface %d@%s' % (src_index, src_intf, dst_index, dst_intf)

        test_params = ("mac_src=\'%s\';" % src_mac
                       + "mac_dst=\'%s\';" % dst_mac
                       + "ip_src=\'%s\';" % src_ip
                       + "ip_dst=\'%s\';" % dst_ip
                       + "dscp=%d;" % dscp
                       + "dscp_bg=%d;" % dscp_bg
                       + "pkt_count=%d;" % PTF_PKT_COUNT
                       + "pkt_intvl=%f;" % PTF_PKT_INTVL_SEC
                       + "port_src=%d;" % src_index
                       + "port_dst=%d;" % dst_index
                       + "queue_paused=%s;" % queue_paused
                       + "dut_has_mac=False")

        cmd = 'ptf --test-dir %s %s --test-params="%s"' % (os.path.dirname(PTF_FILE_REMOTE_PATH), intf_info, test_params)
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
            stop_pause(peerdev_ans, PFC_GEN_FILE)
            time.sleep(1)

    return results


def run_test(fanouthosts,
             duthost,
             ptfhost,
             tbinfo,
             conn_graph_facts,
             leaf_fanouts,
             dscp,
             dscp_bg,
             queue_paused,
             send_pause,
             pfc_pause,
             pause_prio,
             pause_time=65535,
             max_test_intfs_count=128):
    """
    @Summary: Run a series of tests (only support T0 topology)
    @param tbinfo: Testbed information
    @param conn_graph_facts: Testbed topology
    @param leaf_fanouts: Leaf fanout switches
    @param dscp: DSCP value of test data packets
    @param dscp_bg: DSCP value of background data packets
    @param queue_paused: if the queue is expected to be paused
    @param send_pause: send pause frames or not
    @param pfc_pause: send PFC pause frames or not
    @param pause_prio: priority of PFC franme
    @param pause_time: pause time quanta. It is 65535 (maximum pause time quanta) by default.
    @param max_test_intfs_count: maximum count of interfaces to test. By default, it is a very large value to cover all the interfaces.
    return: Return # of iterations and # of passed iterations for each tested interface.
    """

    print tbinfo
    if tbinfo['topo']['name'].startswith('t0'):
        return run_test_t0(fanouthosts=fanouthosts,
                           duthost=duthost,
                           ptfhost=ptfhost,
                           conn_graph_facts=conn_graph_facts, leaf_fanouts=leaf_fanouts,
                           dscp=dscp,
                           dscp_bg=dscp_bg,
                           queue_paused=queue_paused,
                           send_pause=send_pause,
                           pfc_pause=pfc_pause,
                           pause_prio=pause_prio,
                           pause_time=pause_time,
                           max_test_intfs_count=max_test_intfs_count)

    else:
        return None

def test_pfc_pause_lossless(fanouthosts,
                            duthost,
                            ptfhost,
                            tbinfo,
                            conn_graph_facts,
                            leaf_fanouts,
                            lossless_prio_dscp_map):

    """
    @Summary: Test if PFC pause frames can pause a lossless priority without affecting the other priorities
    @param tbinfo: Testbed information
    @param conn_graph_facts: Testbed topology
    @param lossless_prio_dscp_map: lossless priorities and their DSCP values
    """
    setup_testbed(fanouthosts=fanouthosts,
                  ptfhost=ptfhost,
                  leaf_fanouts=leaf_fanouts,
                  ptf_local_path=PTF_FILE_LOCAL_PATH,
                  ptf_remote_path=PTF_FILE_REMOTE_PATH)

    errors = []

    """ DSCP vlaues for lossless priorities """
    lossless_dscps = [int(dscp) for prio in lossless_prio_dscp_map for dscp in lossless_prio_dscp_map[prio]]
    """ DSCP values for lossy priorities """
    lossy_dscps = list(set(range(64)) - set(lossless_dscps))

    for prio in lossless_prio_dscp_map:
        """ DSCP values of the other lossless priorities """
        other_lossless_dscps = list(set(lossless_dscps) - set(lossless_prio_dscp_map[prio]))
        """ We also need to test some DSCP values for lossy priorities """
        other_dscps = other_lossless_dscps + lossy_dscps[0:2]

        for dscp in lossless_prio_dscp_map[prio]:
            for dscp_bg in other_dscps:
                results = run_test(fanouthosts=fanouthosts,
                                   duthost=duthost,
                                   ptfhost=ptfhost,
                                   tbinfo=tbinfo,
                                   conn_graph_facts=conn_graph_facts,
                                   leaf_fanouts=leaf_fanouts,
                                   dscp=dscp,
                                   dscp_bg=dscp_bg,
                                   queue_paused=True,
                                   send_pause=True,
                                   pfc_pause=True,
                                   pause_prio=prio,
                                   pause_time=65535,
                                   max_test_intfs_count=MAX_TEST_INTFS_COUNT)

                """ results should not be none """
                if results is None:
                    assert 0

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
                    print "errors occured:\n{}".format("\n".join(errors))
                    assert 0

def test_no_pfc(fanouthosts,
                duthost,
                ptfhost,
                tbinfo,
                conn_graph_facts,
                leaf_fanouts,
                lossless_prio_dscp_map):

    """
    @Summary: Test if lossless and lossy priorities can forward packets in the absence of PFC pause frames
    @param fanouthosts: Fixture for fanout hosts
    @param tbinfo: Testbed information
    @param conn_graph_facts: Testbed topology
    @param lossless_prio_dscp_map: lossless priorities and their DSCP values
    """
    setup_testbed(fanouthosts=fanouthosts,
                  ptfhost=ptfhost,
                  leaf_fanouts=leaf_fanouts,
                  ptf_local_path=PTF_FILE_LOCAL_PATH,
                  ptf_remote_path=PTF_FILE_REMOTE_PATH)

    errors = []

    """ DSCP vlaues for lossless priorities """
    lossless_dscps = [int(dscp) for prio in lossless_prio_dscp_map for dscp in lossless_prio_dscp_map[prio]]
    """ DSCP values for lossy priorities """
    lossy_dscps = list(set(range(64)) - set(lossless_dscps))

    for prio in lossless_prio_dscp_map:
        """ DSCP values of the other lossless priorities """
        other_lossless_dscps = list(set(lossless_dscps) - set(lossless_prio_dscp_map[prio]))
        """ We also need to test some DSCP values for lossy priorities """
        other_dscps = other_lossless_dscps + lossy_dscps[0:2]

        for dscp in lossless_prio_dscp_map[prio]:
            for dscp_bg in other_dscps:
                results = run_test(fanouthosts=fanouthosts,
                                   duthost=duthost,
                                   ptfhost=ptfhost,
                                   tbinfo=tbinfo,
                                   conn_graph_facts=conn_graph_facts,
                                   leaf_fanouts=leaf_fanouts,
                                   dscp=dscp,
                                   dscp_bg=dscp_bg,
                                   queue_paused=False,
                                   send_pause=False,
                                   pfc_pause=None,
                                   pause_prio=None,
                                   pause_time=None,
                                   max_test_intfs_count=MAX_TEST_INTFS_COUNT)

                """ results should not be none """
                if results is None:
                    assert 0

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
                    print "errors occured:\n{}".format("\n".join(errors))
                    assert 0
