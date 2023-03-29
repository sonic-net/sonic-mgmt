import pytest
import random
from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts             # noqa: F401
from tests.common.snappi.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port,\
    snappi_api, snappi_dut_base_config, get_tgen_peer_ports, get_multidut_snappi_ports,\
    get_multidut_tgen_peer_port_set, cleanup_config                                                 # noqa: F401
from tests.common.snappi.qos_fixtures import prio_dscp_map_dut_base, lossless_prio_list_dut_base    # noqa: F401

from tests.snappi.variables import config_set, line_card_choice
from files.multidut_helper import run_ecn_test, is_ecn_marked

pytestmark = [pytest.mark.topology('snappi')]


@pytest.mark.parametrize('line_card_choice', [line_card_choice])
@pytest.mark.parametrize('linecard_configuration_set', [config_set])
def test_dequeue_ecn(request,
                     snappi_api,                    # noqa: F811
                     conn_graph_facts,              # noqa: F811
                     fanout_graph_facts,            # noqa: F811
                     duthosts,
                     line_card_choice,
                     linecard_configuration_set,
                     get_multidut_snappi_ports      # noqa: F811
                     ):
    """
    Test if the device under test (DUT) performs ECN marking at the egress

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
        pytest.skip("test_dequeue_ecn is disabled")

    if line_card_choice not in linecard_configuration_set.keys():
        assert False, "Invalid line_card_choice value passed in parameter"

    if (len(linecard_configuration_set[line_card_choice]['hostname']) == 2):
        dut_list = random.sample(duthosts, 2)
        duthost1, duthost2 = dut_list
    elif (len(linecard_configuration_set[line_card_choice]['hostname']) == 1):
        dut_list = [dut for dut in duthosts if
                    linecard_configuration_set[line_card_choice]['hostname'] == [dut.hostname]]
        duthost1, duthost2 = dut_list[0], dut_list[0]
    else:
        assert False, "Hostname can't be an empty list"

    snappi_port_list = get_multidut_snappi_ports(line_card_choice=line_card_choice,
                                                 line_card_info=linecard_configuration_set[line_card_choice])
    if len(snappi_port_list) < 2:
        assert False, "Need Minimum of 2 ports for the test"

    snappi_ports = get_multidut_tgen_peer_port_set(line_card_choice, snappi_port_list, config_set, 2)
    tgen_ports = [port['location'] for port in snappi_ports]

    snappi_port_list = get_multidut_snappi_ports(line_card_choice=line_card_choice,
                                                 line_card_info=linecard_configuration_set[line_card_choice])
    if len(snappi_port_list) < 2:
        assert False, "Need Minimum of 2 ports for the test"

    testbed_config, port_config_list, snappi_ports = snappi_dut_base_config(dut_list,
                                                                            tgen_ports,
                                                                            snappi_ports,
                                                                            snappi_api)
    prio_dscp_map = prio_dscp_map_dut_base(duthost1)
    lossless_prio = int(lossless_prio_list_dut_base(duthost1)[0])

    kmin = 500000
    kmax = 510000
    pmax = 100
    pkt_size = 1024
    pkt_cnt = 1000

    ip_pkts = run_ecn_test(api=snappi_api,
                           testbed_config=testbed_config,
                           port_config_list=port_config_list,
                           conn_data=conn_graph_facts,
                           fanout_data=fanout_graph_facts,
                           duthost1=duthost1,
                           rx_port=snappi_ports[0],
                           rx_port_id=snappi_ports[0]["port_id"],
                           duthost2=duthost2,
                           tx_port=snappi_ports[1],
                           tx_port_id=snappi_ports[1]["port_id"],
                           dut_port=snappi_ports[0]['peer_port'],
                           kmin=kmin,
                           kmax=kmax,
                           pmax=pmax,
                           pkt_size=pkt_size,
                           pkt_cnt=pkt_cnt,
                           lossless_prio=lossless_prio,
                           prio_dscp_map=prio_dscp_map,
                           iters=1)[0]

    """ Check if we capture all the packets """
    pytest_assert(len(ip_pkts) == pkt_cnt,
                  'Only capture {}/{} IP packets'.format(len(ip_pkts), pkt_cnt))

    """ Check if the first packet is marked """
    pytest_assert(is_ecn_marked(ip_pkts[0]), "The first packet should be marked")

    """ Check if the last packet is not marked """
    pytest_assert(not is_ecn_marked(ip_pkts[-1]),
                  "The last packet should not be marked")
    cleanup_config(dut_list, snappi_ports)
