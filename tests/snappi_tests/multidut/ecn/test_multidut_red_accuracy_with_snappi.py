import pytest
import collections
import random
from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts         # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port,\
    snappi_api, snappi_dut_base_config, get_tgen_peer_ports, get_multidut_snappi_ports,\
    get_multidut_tgen_peer_port_set, cleanup_config                                             # noqa: F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map_dut_base,\
    lossless_prio_list_dut_base
from tests.snappi_tests.variables import config_set, line_card_choice
from tests.snappi_tests.multidut.ecn.files.multidut_helper import run_ecn_test, is_ecn_marked   # noqa: F401
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams

pytestmark = [pytest.mark.topology('snappi')]


@pytest.mark.parametrize('line_card_choice', [line_card_choice])
@pytest.mark.parametrize('linecard_configuration_set', [config_set])
def test_red_accuracy(request,
                      snappi_api,                       # noqa: F811
                      conn_graph_facts,                 # noqa: F811
                      fanout_graph_facts,               # noqa: F811
                      duthosts,
                      line_card_choice,
                      linecard_configuration_set,
                      get_multidut_snappi_ports         # noqa: F811
                      ):
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
        line_card_choice: Line card choice to be mentioned in the variable.py file
        linecard_configuration_set : Line card classification, (min 1 or max 2  hostnames and asics to be given)

    Returns:
        N/A
    """
    disable_test = request.config.getoption("--disable_ecn_snappi_test")
    if disable_test:
        pytest.skip("test_red_accuracy is disabled")

    if line_card_choice not in linecard_configuration_set.keys():
        assert False, "Invalid line_card_choice value passed in parameter"

    if (len(linecard_configuration_set[line_card_choice]['hostname']) == 2):
        dut_list = random.sample(duthosts, 2)
        duthost1, duthost2 = dut_list
    elif (len(linecard_configuration_set[line_card_choice]['hostname']) == 1):
        dut_list = [dut for dut in duthosts if linecard_configuration_set[line_card_choice]['hostname'] == [dut.hostname]]      # noqa: E501
        duthost1, duthost2 = dut_list[0], dut_list[0]
    else:
        assert False, "Hostname can't be an empty list"

    snappi_port_list = get_multidut_snappi_ports(line_card_choice=line_card_choice,
                                                 line_card_info=linecard_configuration_set[line_card_choice])
    if len(snappi_port_list) < 2:
        assert False, "Need Minimum of 2 ports for the test"

    snappi_ports = get_multidut_tgen_peer_port_set(line_card_choice, snappi_port_list, config_set, 2)
    tgen_ports = [port['location'] for port in snappi_ports]

    testbed_config, port_config_list, snappi_ports = snappi_dut_base_config(dut_list,
                                                                            tgen_ports,
                                                                            snappi_ports,
                                                                            snappi_api)
    prio_dscp_map = prio_dscp_map_dut_base(duthost1)
    lossless_prio = int(lossless_prio_list_dut_base(duthost1)[0])

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.duthost1 = duthost1
    snappi_extra_params.rx_port = snappi_ports[0]
    snappi_extra_params.rx_port_id = snappi_ports[0]["port_id"]
    snappi_extra_params.duthost2 = duthost2
    snappi_extra_params.tx_port = snappi_ports[1]
    snappi_extra_params.tx_port_id = snappi_ports[1]["port_id"]
    snappi_extra_params.kmin = 500000
    snappi_extra_params.kmax = 2000000
    snappi_extra_params.pmax = 5
    snappi_extra_params.pkt_size = 1024
    snappi_extra_params.pkt_cnt = 2100

    result_file_name = 'result.txt'

    ip_pkts_list = run_ecn_test(api=snappi_api,
                                testbed_config=testbed_config,
                                port_config_list=port_config_list,
                                conn_data=conn_graph_facts,
                                fanout_data=fanout_graph_facts,
                                dut_port=snappi_ports[0]['peer_port'],
                                lossless_prio=lossless_prio,
                                prio_dscp_map=prio_dscp_map,
                                snappi_extra_params=snappi_extra_params)

    """ Check if we capture packets of all the rounds """
    pytest_assert(len(ip_pkts_list) == snappi_extra_params.iters,
                  'Only capture {}/{} rounds of packets'.format(len(ip_pkts_list), snappi_extra_params.iters))

    queue_mark_cnt = {}
    for i in range(snappi_extra_params.pkt_cnt):
        queue_len = (snappi_extra_params.pkt_cnt - i) * snappi_extra_params.pkt_size
        queue_mark_cnt[queue_len] = 0

    for i in range(snappi_extra_params.iters):
        ip_pkts = ip_pkts_list[i]
        """ Check if we capture all the packets in each round """
        pytest_assert(len(ip_pkts) == snappi_extra_params.pkt_cnt,
                      'Only capture {}/{} packets in round {}'.format(len(ip_pkts), snappi_extra_params.pkt_cnt, i))

        for j in range(snappi_extra_params.pkt_cnt):
            ip_pkt = ip_pkts[j]
            queue_len = (snappi_extra_params.pkt_cnt - j) * snappi_extra_params.pkt_size

            if is_ecn_marked(ip_pkt):
                queue_mark_cnt[queue_len] += 1

    """ Dump queue length vs. ECN marking probability into a file """
    queue_mark_cnt = collections.OrderedDict(sorted(queue_mark_cnt.items()))
    f = open(result_file_name, 'w')
    for queue, mark_cnt in queue_mark_cnt.iteritems():
        f.write('{} {}\n'.format(queue, float(mark_cnt) / snappi_extra_params.iters))
    f.close()
    cleanup_config(dut_list, snappi_ports)
