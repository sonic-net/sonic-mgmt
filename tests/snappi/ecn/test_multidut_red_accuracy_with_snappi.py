import pytest
import collections

from tests.common.helpers.assertions import pytest_require, pytest_assert
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts
from tests.common.snappi.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port,\
    snappi_api, snappi_dut_base_config, get_tgen_peer_ports, get_multidut_snappi_ports
from tests.common.snappi.qos_fixtures import prio_dscp_map_dut_base,\
             lossless_prio_list_dut_base
import random

from files.multidut_helper import run_ecn_test, is_ecn_marked

pytestmark = [ pytest.mark.topology('snappi') ]

def test_red_accuracy(request,
                     snappi_api,
                     conn_graph_facts,
                     fanout_graph_facts,
                     duthosts,
                     rand_select_two_dut,
                     get_multidut_snappi_ports):
    """
    Measure RED/ECN marking accuracy of the device under test (DUT).
    Dump queue length vs. ECN marking probability results into a file.

    Args:
        request (pytest fixture): pytest request object
        snappi_api (pytest fixture): SNAPPI session
        snappi_testbed_config (pytest fixture): testbed configuration information
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
    disable_test = request.config.getoption("--disable_ecn_snappi_test")
    if disable_test:
        pytest.skip("test_red_accuracy is disabled")

    #duts = rand_select_two_dut
    duthost1 = duthosts[0]
    duthost2 = duthosts[1]
    snappi_ports = get_multidut_snappi_ports
    #port_set1 = random.sample(get_tgen_peer_ports(snappi_ports, duthost1.hostname), 1)[0]
    #port_set2 = get_tgen_peer_ports(snappi_ports, duthost2.hostname)
    port_set1 = get_tgen_peer_ports(snappi_ports, duthost1.hostname)[0]
    port_set2 = get_tgen_peer_ports(snappi_ports, duthost2.hostname)[0]
    tgen_ports = [port_set1[0], port_set2[0]]
    dut_port = port_set1[1]
    testbed_config, port_config_list, snappi_ports = snappi_dut_base_config([duthost1, duthost2],
                                                              tgen_ports,
                                                              snappi_ports,
                                                              snappi_api)
    prio_dscp_map = prio_dscp_map_dut_base(duthost1)
    lossless_prio = int(lossless_prio_list_dut_base(duthost1)[0])
    kmin = 500000
    kmax = 2000000
    pmax = 5
    pkt_size = 1024
    pkt_cnt = 2100
    iters = 100
    result_file_name = 'result.txt'

    ip_pkts_list = run_ecn_test(api=snappi_api,
                                testbed_config=testbed_config,
                                port_config_list=port_config_list,
                                conn_data=conn_graph_facts,
                                fanout_data=fanout_graph_facts,
                                duthost1=duthost1,
                                rx_port_id=snappi_ports[0]["port_id"],
                                duthost2=duthost2,
                                tx_port_id=snappi_ports[1]["port_id"],
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