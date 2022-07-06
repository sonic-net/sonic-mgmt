import pytest
import collections

from tests.common.helpers.assertions import pytest_require, pytest_assert
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts
from tests.common.ixia.ixia_fixtures import ixia_api_serv_ip, ixia_api_serv_port,\
    ixia_api_serv_user, ixia_api_serv_passwd, ixia_api, ixia_testbed_config
from tests.common.ixia.qos_fixtures import prio_dscp_map, lossless_prio_list

from files.helper import run_ecn_test, is_ecn_marked
from tests.common.cisco_data import get_ecn_markings_dut, setup_ecn_markings_dut

pytestmark = [ pytest.mark.topology('tgen') ]

def test_red_accuracy(request,
                      ixia_api,
                      ixia_testbed_config,
                      conn_graph_facts,
                      fanout_graph_facts,
                      duthosts,
                      localhost,
                      rand_one_dut_hostname,
                      rand_one_dut_portname_oper_up,
                      rand_one_dut_lossless_prio,
                      prio_dscp_map):
    """
    Measure RED/ECN marking accuracy of the device under test (DUT).
    Dump queue length vs. ECN marking probability results into a file.

    Args:
        request (pytest fixture): pytest request object
        ixia_api (pytest fixture): IXIA session
        ixia_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_hostname (str): hostname of DUT
        rand_one_dut_portname_oper_up (str): name of port to test, e.g., 's6100-1|Ethernet0'
        rand_one_dut_lossless_prio (str): name of lossless priority to test, e.g., 's6100-1|3'
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).

    Returns:
        N/A
    """
    disable_test = request.config.getoption("--disable_ecn_test")
    if disable_test:
        pytest.skip("test_red_accuracy is disabled")

    dut_hostname, dut_port = rand_one_dut_portname_oper_up.split('|')
    dut_hostname2, lossless_prio = rand_one_dut_lossless_prio.split('|')
    pytest_require(rand_one_dut_hostname == dut_hostname == dut_hostname2,
                   "Priority and port are not mapped to the expected DUT")

    testbed_config, port_config_list = ixia_testbed_config
    duthost = duthosts[rand_one_dut_hostname]
    lossless_prio = int(lossless_prio)
    cisco_platform = (duthost.facts['asic_type'] == "cisco-8000")

    kmin = 500000
    kmax = 2000000
    pmax = 5
    pkt_size = 1024
    pkt_cnt = 2100
    iters = 100
    result_file_name = 'result.txt'

    if cisco_platform:
        original_ecn_markings = get_ecn_markings_dut(duthost)
        setup_ecn_markings_dut(duthost, localhost, dequeue = True, latency = False)

    try:
        ip_pkts_list = run_ecn_test(api=ixia_api,
                                testbed_config=testbed_config,
                                port_config_list=port_config_list,
                                conn_data=conn_graph_facts,
                                fanout_data=fanout_graph_facts,
                                duthost=duthost,
                                dut_port=dut_port,
                                kmin=kmin,
                                kmax=kmax,
                                pmax=pmax,
                                pkt_size=pkt_size,
                                pkt_cnt=pkt_cnt,
                                lossless_prio=lossless_prio,
                                prio_dscp_map=prio_dscp_map,
                                iters=iters)

        """ Check if we capture packets of all the rounds """
        pytest_assert(len(ip_pkts_list) == iters,
                      'Only capture {}/{} rounds of packets'.format(len(ip_pkts_list), iters))

        queue_mark_cnt = {}
        for i in range(pkt_cnt):
            queue_len = (pkt_cnt - i) * pkt_size
            queue_mark_cnt[queue_len] = 0

        for i in range(iters):
            ip_pkts = ip_pkts_list[i]
            """ Check if we capture all the packets in each round """
            pytest_assert(len(ip_pkts) == pkt_cnt,
                          'Only capture {}/{} packets in round {}'.format(len(ip_pkts), pkt_cnt, i))

            for j in range(pkt_cnt):
                ip_pkt = ip_pkts[j]
                queue_len = (pkt_cnt - j) * pkt_size

                if is_ecn_marked(ip_pkt):
                    queue_mark_cnt[queue_len] += 1

        """ Dump queue length vs. ECN marking probability into a file """
        queue_mark_cnt = collections.OrderedDict(sorted(queue_mark_cnt.items()))
        f = open(result_file_name, 'w')
        for queue, mark_cnt in queue_mark_cnt.iteritems():
            f.write('{} {}\n'.format(queue, float(mark_cnt)/iters))
        f.close()
    finally:
        if cisco_platform:
            setup_ecn_markings_dut(duthost, localhost, **original_ecn_markings)

