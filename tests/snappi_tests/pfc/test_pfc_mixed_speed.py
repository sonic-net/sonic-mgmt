import pytest
import random
from tests.common.helpers.assertions import pytest_require, pytest_assert                   # noqa: F401
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts_multidut     # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
    snappi_api, cleanup_config, get_snappi_ports_for_rdma, snappi_multi_base_config, \
    get_snappi_ports, get_snappi_ports_multi_dut, clear_fabric_counters, check_fabric_counters      # noqa: F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map, lossless_prio_list, \
    lossy_prio_list, all_prio_list                                                                  # noqa: F401
from tests.snappi_tests.variables import MIXED_SPEED_PORT_INFO, MULTIDUT_TESTBED
from tests.snappi_tests.pfc.files.mixed_speed_multidut_helper import run_pfc_test
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams

import logging
logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology('multidut-tgen')]

port_map = [[1, 100, 1, 400]]
# Testplan: docs/testplan/PFC_Snappi_Additional_Testcases.md
# This test-script covers testcase#03: DETECT CONGESTION WITH MISMATCHED INGRESS AND EGRESS


@pytest.mark.parametrize('port_map', port_map)
@pytest.mark.parametrize("multidut_port_info", MIXED_SPEED_PORT_INFO[MULTIDUT_TESTBED])
def test_mixed_speed_diff_dist_over(snappi_api,                   # noqa: F811
                                    conn_graph_facts,             # noqa: F811
                                    fanout_graph_facts_multidut,  # noqa: F811
                                    duthosts,
                                    prio_dscp_map,                # noqa: F811
                                    lossless_prio_list,           # noqa: F811
                                    lossy_prio_list,              # noqa: F811
                                    tbinfo,
                                    get_snappi_ports,             # noqa: F811
                                    port_map,
                                    multidut_port_info):          # noqa: F811

    """
    Majority traffic is lossless priority traffic.
    DUT responds to congestion on ingress side by sending PFCs to IXIA transmitter.
    IXIA transmitter slows down lossless traffic.
    No Lossy traffic is dropped.
    Lossy traffic makes through without any drop. Lossless traffic is adjusted.
    Total egress link speed is 100Gbps.

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        lossless_prio_list(list): list of lossless priorities
        lossy_prio_list(list): list of lossy priorities.
        tbinfo(key): element to identify testbed info name.
        get_snappi_ports(pytest fixture): returns list of ports based on linecards selected.
        port_map(list): list for port-speed combination.
        multidut_port_info : Line card classification along with ports selected as Rx and Tx port.
    Returns:
        N/A

    """

    # port_map is defined as port-speed combination.
    # first two parameters are count of egress links and its speed.
    # last two parameters are count of ingress links and its speed.

    # pkt_size of 1024B will be used unless imix flag is set.
    # With imix flag set, the traffic_generation.py uses IMIX profile.
    pkt_size = 1024

    for testbed_subtype, rdma_ports in MIXED_SPEED_PORT_INFO[MULTIDUT_TESTBED].items():
        tx_port_count = port_map[0]
        rx_port_count = port_map[2]
        snappi_port_list = get_snappi_ports
        pytest_require(MULTIDUT_TESTBED == tbinfo['conf-name'],
                       "The testbed name from testbed file doesn't match with MULTIDUT_TESTBED in variables.py ")
        pytest_require(len(snappi_port_list) >= tx_port_count + rx_port_count,
                       "Need Minimum of 2 ports defined in ansible/files/*links.csv file")

        pytest_require(len(rdma_ports['tx_ports']) >= tx_port_count,
                       'MULTIDUT_PORT_INFO doesn\'t have the required Tx ports defined for \
                       testbed {}, subtype {} in variables.py'.
                       format(MULTIDUT_TESTBED, testbed_subtype))

        pytest_require(len(rdma_ports['rx_ports']) >= rx_port_count,
                       'MULTIDUT_PORT_INFO doesn\'t have the required Rx ports defined for \
                       testbed {}, subtype {} in variables.py'.
                       format(MULTIDUT_TESTBED, testbed_subtype))
        logger.info('Running test for testbed subtype: {}'.format(testbed_subtype))

        snappi_ports = get_snappi_ports_for_rdma(snappi_port_list, rdma_ports,
                                                 tx_port_count, rx_port_count, MULTIDUT_TESTBED)

        testbed_config, port_config_list, snappi_ports = snappi_multi_base_config(duthosts,
                                                                                  snappi_ports,
                                                                                  snappi_api)

    # Percentage drop expected for lossless and lossy traffic.
    # speed_tol is speed tolerance between egress link speed and actual speed.
    # loss_expected to check losses on DUT and TGEN.
    test_check = {'lossless': 0, 'lossy': 0, 'speed_tol': 3, 'loss_expected': False, 'pfc': True}
    test_def = {'TEST_FLOW_AGGR_RATE_PERCENT': 88,
                'BG_FLOW_AGGR_RATE_PERCENT': 12,
                'data_flow_pkt_size': pkt_size,
                'DATA_FLOW_DURATION_SEC': 300,
                'data_flow_delay_sec': 0,
                'SNAPPI_POLL_DELAY_SEC': 60,
                'test_type': '/tmp/Single_400Gbps_Ingress_Single_100Gbps_Egress_diff_dist_',
                'line_card_choice': testbed_subtype,
                'port_map': port_map,
                'enable_pfcwd': True,
                'enable_credit_wd': True,
                'stats_interval': 60,
                'background_traffic': True,
                'imix': False,
                'test_check': test_check,
                'verify_flows': False}

    test_prio_list = lossless_prio_list
    pause_prio_list = test_prio_list
    bg_prio_list = random.sample(lossy_prio_list, 3)
    logger.info('Selected lossless :{} and lossy priorities:{} for the test'.format(test_prio_list, bg_prio_list))

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.duthost1 = snappi_ports[0]['duthost']
    snappi_extra_params.multi_dut_params.duthost2 = snappi_ports[-1]['duthost']

    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports
    if (snappi_ports[0]['peer_device'] == snappi_ports[-1]['peer_device']):
        dut_list = [snappi_ports[0]['duthost']]
    else:
        dut_list = [snappi_ports[0]['duthost'], snappi_ports[-1]['duthost']]

    for dut in duthosts:
        clear_fabric_counters(dut)

    try:
        run_pfc_test(api=snappi_api,
                     testbed_config=testbed_config,
                     port_config_list=port_config_list,
                     conn_data=conn_graph_facts,
                     fanout_data=fanout_graph_facts_multidut,
                     global_pause=False,
                     pause_prio_list=pause_prio_list,
                     test_prio_list=test_prio_list,
                     bg_prio_list=bg_prio_list,
                     prio_dscp_map=prio_dscp_map,
                     test_traffic_pause=False,
                     test_def=test_def,
                     snappi_extra_params=snappi_extra_params)

        # Check the fabric counter for the line-cards.
        for dut in duthosts:
            check_fabric_counters(dut)

    finally:
        cleanup_config(dut_list, snappi_ports)


@pytest.mark.parametrize('port_map', port_map)
@pytest.mark.parametrize("multidut_port_info", MIXED_SPEED_PORT_INFO[MULTIDUT_TESTBED])
def test_mixed_speed_uni_dist_over(snappi_api,                   # noqa: F811
                                   conn_graph_facts,             # noqa: F811
                                   fanout_graph_facts_multidut,  # noqa: F811
                                   duthosts,
                                   prio_dscp_map,                # noqa: F811
                                   lossless_prio_list,           # noqa: F811
                                   lossy_prio_list,              # noqa: F811
                                   tbinfo,
                                   get_snappi_ports,             # noqa: F811
                                   port_map,
                                   multidut_port_info):          # noqa: F811

    """
    Traffic is sent to IXIA receiver in equal amount.
    DUT responds to congestion on ingress side by sending PFCs to IXIA transmitter.
    IXIA transmitter slows down lossless traffic.
    Lossy traffic is dropped.
    Equal amount of lossless and lossy priority traffic is sent to IXIA receiver.
    Total egress link speed is 100Gbps.

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        lossless_prio_list(list): list of lossless priorities
        lossy_prio_list(list): list of lossy priorities.
        tbinfo(key): element to identify testbed info name.
        get_snappi_ports(pytest fixture): returns list of ports based on linecards selected.
        port_map(list): list for port-speed combination.
        multidut_port_info : Line card classification along with ports selected as Rx and Tx port.
    Returns:
        N/A

    """

    # port_map is defined as port-speed combination.
    # first two parameters are count of egress links and its speed.
    # last two parameters are count of ingress links and its speed.

    # pkt_size of 1024B will be used unless imix flag is set.
    # With imix flag set, the traffic_generation.py uses IMIX profile.
    pkt_size = 1024

    for testbed_subtype, rdma_ports in MIXED_SPEED_PORT_INFO[MULTIDUT_TESTBED].items():
        tx_port_count = port_map[0]
        rx_port_count = port_map[2]
        snappi_port_list = get_snappi_ports
        pytest_require(MULTIDUT_TESTBED == tbinfo['conf-name'],
                       "The testbed name from testbed file doesn't match with MULTIDUT_TESTBED in variables.py ")
        pytest_require(len(snappi_port_list) >= tx_port_count + rx_port_count,
                       "Need Minimum of 2 ports defined in ansible/files/*links.csv file")

        pytest_require(len(rdma_ports['tx_ports']) >= tx_port_count,
                       'MULTIDUT_PORT_INFO doesn\'t have the required Tx ports defined for \
                       testbed {}, subtype {} in variables.py'.
                       format(MULTIDUT_TESTBED, testbed_subtype))

        pytest_require(len(rdma_ports['rx_ports']) >= rx_port_count,
                       'MULTIDUT_PORT_INFO doesn\'t have the required Rx ports defined for \
                       testbed {}, subtype {} in variables.py'.
                       format(MULTIDUT_TESTBED, testbed_subtype))
        logger.info('Running test for testbed subtype: {}'.format(testbed_subtype))

        snappi_ports = get_snappi_ports_for_rdma(snappi_port_list, rdma_ports,
                                                 tx_port_count, rx_port_count, MULTIDUT_TESTBED)

        testbed_config, port_config_list, snappi_ports = snappi_multi_base_config(duthosts,
                                                                                  snappi_ports,
                                                                                  snappi_api)
    # Percentage drop expected for lossless and lossy traffic.
    # speed_tol is speed tolerance between egress link speed and actual speed.
    # loss_expected to check losses on DUT and TGEN.
    test_check = {'lossless': 0, 'lossy': 77, 'speed_tol': 3, 'loss_expected': True, 'pfc': True}
    test_def = {'TEST_FLOW_AGGR_RATE_PERCENT': 40,
                'BG_FLOW_AGGR_RATE_PERCENT': 60,
                'data_flow_pkt_size': pkt_size,
                'DATA_FLOW_DURATION_SEC': 300,
                'data_flow_delay_sec': 0,
                'SNAPPI_POLL_DELAY_SEC': 60,
                'test_type': '/tmp/Single_400Gbps_Ingress_Single_100Gbps_Egress_uni_dist_',
                'line_card_choice': testbed_subtype,
                'port_map': port_map,
                'enable_pfcwd': True,
                'enable_credit_wd': True,
                'stats_interval': 60,
                'background_traffic': True,
                'imix': False,
                'test_check': test_check,
                'verify_flows': False}

    test_prio_list = lossless_prio_list
    pause_prio_list = test_prio_list
    bg_prio_list = random.sample(lossy_prio_list, 3)
    logger.info('Selected lossless :{} and lossy priorities:{} for the test'.format(test_prio_list, bg_prio_list))

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.duthost1 = snappi_ports[0]['duthost']
    snappi_extra_params.multi_dut_params.duthost2 = snappi_ports[-1]['duthost']

    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports
    if (snappi_ports[0]['peer_device'] == snappi_ports[-1]['peer_device']):
        dut_list = [snappi_ports[0]['duthost']]
    else:
        dut_list = [snappi_ports[0]['duthost'], snappi_ports[-1]['duthost']]

    for dut in duthosts:
        clear_fabric_counters(dut)

    try:
        run_pfc_test(api=snappi_api,
                     testbed_config=testbed_config,
                     port_config_list=port_config_list,
                     conn_data=conn_graph_facts,
                     fanout_data=fanout_graph_facts_multidut,
                     global_pause=False,
                     pause_prio_list=pause_prio_list,
                     test_prio_list=test_prio_list,
                     bg_prio_list=bg_prio_list,
                     prio_dscp_map=prio_dscp_map,
                     test_traffic_pause=False,
                     test_def=test_def,
                     snappi_extra_params=snappi_extra_params)

        for dut in duthosts:
            check_fabric_counters(dut)

    finally:
        cleanup_config(dut_list, snappi_ports)


@pytest.mark.parametrize('port_map', port_map)
@pytest.mark.parametrize("multidut_port_info", MIXED_SPEED_PORT_INFO[MULTIDUT_TESTBED])
def test_mixed_speed_no_congestion(snappi_api,                   # noqa: F811
                                   conn_graph_facts,             # noqa: F811
                                   fanout_graph_facts_multidut,  # noqa: F811
                                   duthosts,
                                   prio_dscp_map,                # noqa: F811
                                   lossless_prio_list,           # noqa: F811
                                   lossy_prio_list,              # noqa: F811
                                   tbinfo,
                                   get_snappi_ports,             # noqa: F811
                                   port_map,
                                   multidut_port_info):          # noqa: F811

    """
    Test to have mixed speed ingress and egress without oversubscribing the egress.
    Since the total ingress traffic on 400Gbps is less than 100Gbps,
    there should be no congestion experienced by DUT.
    No packet drops experienced by the DUT.

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        lossless_prio_list(list): list of lossless priorities
        lossy_prio_list(list): list of lossy priorities.
        tbinfo(key): element to identify testbed info name.
        get_snappi_ports(pytest fixture): returns list of ports based on linecards selected.
        port_map(list): list for port-speed combination.
        multidut_port_info : Line card classification along with ports selected as Rx and Tx port.



    """

    # port_map is defined as port-speed combination.
    # first two parameters are count of egress links and its speed.
    # last two parameters are count of ingress links and its speed.

    # pkt_size of 1024B will be used unless imix flag is set.
    # With imix flag set, the traffic_generation.py uses IMIX profile.
    pkt_size = 1024

    for testbed_subtype, rdma_ports in MIXED_SPEED_PORT_INFO[MULTIDUT_TESTBED].items():
        tx_port_count = port_map[0]
        rx_port_count = port_map[2]
        snappi_port_list = get_snappi_ports
        pytest_require(MULTIDUT_TESTBED == tbinfo['conf-name'],
                       "The testbed name from testbed file doesn't match with MULTIDUT_TESTBED in variables.py ")
        pytest_require(len(snappi_port_list) >= tx_port_count + rx_port_count,
                       "Need Minimum of 2 ports defined in ansible/files/*links.csv file")

        pytest_require(len(rdma_ports['tx_ports']) >= tx_port_count,
                       'MULTIDUT_PORT_INFO doesn\'t have the required Tx ports defined for \
                       testbed {}, subtype {} in variables.py'.
                       format(MULTIDUT_TESTBED, testbed_subtype))

        pytest_require(len(rdma_ports['rx_ports']) >= rx_port_count,
                       'MULTIDUT_PORT_INFO doesn\'t have the required Rx ports defined for \
                       testbed {}, subtype {} in variables.py'.
                       format(MULTIDUT_TESTBED, testbed_subtype))
        logger.info('Running test for testbed subtype: {}'.format(testbed_subtype))

        snappi_ports = get_snappi_ports_for_rdma(snappi_port_list, rdma_ports,
                                                 tx_port_count, rx_port_count, MULTIDUT_TESTBED)

        testbed_config, port_config_list, snappi_ports = snappi_multi_base_config(duthosts,
                                                                                  snappi_ports,
                                                                                  snappi_api)

    # Percentage drop expected for lossless and lossy traffic.
    # speed_tol is speed tolerance between egress link speed and actual speed.
    # loss_expected to check losses on DUT and TGEN.
    test_check = {'lossless': 0, 'lossy': 0, 'speed_tol': 10, 'loss_expected': False, 'pfc': False}
    test_def = {'TEST_FLOW_AGGR_RATE_PERCENT': 14,
                'BG_FLOW_AGGR_RATE_PERCENT': 9,
                'data_flow_pkt_size': pkt_size,
                'DATA_FLOW_DURATION_SEC': 300,
                'data_flow_delay_sec': 0,
                'SNAPPI_POLL_DELAY_SEC': 60,
                'test_type': '/tmp/Single_400Gbps_Ingress_Single_100Gbps_Egress_no_cong_',
                'line_card_choice': testbed_subtype,
                'port_map': port_map,
                'enable_pfcwd': True,
                'enable_credit_wd': True,
                'stats_interval': 60,
                'background_traffic': True,
                'imix': False,
                'test_check': test_check,
                'verify_flows': False}

    test_prio_list = lossless_prio_list
    pause_prio_list = test_prio_list
    bg_prio_list = random.sample(lossy_prio_list, 3)
    logger.info('Selected lossless :{} and lossy priorities:{} for the test'.format(test_prio_list, bg_prio_list))

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.duthost1 = snappi_ports[0]['duthost']
    snappi_extra_params.multi_dut_params.duthost2 = snappi_ports[-1]['duthost']

    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports
    if (snappi_ports[0]['peer_device'] == snappi_ports[-1]['peer_device']):
        dut_list = [snappi_ports[0]['duthost']]
    else:
        dut_list = [snappi_ports[0]['duthost'], snappi_ports[-1]['duthost']]

    for dut in duthosts:
        clear_fabric_counters(dut)

    try:
        run_pfc_test(api=snappi_api,
                     testbed_config=testbed_config,
                     port_config_list=port_config_list,
                     conn_data=conn_graph_facts,
                     fanout_data=fanout_graph_facts_multidut,
                     global_pause=False,
                     pause_prio_list=pause_prio_list,
                     test_prio_list=test_prio_list,
                     bg_prio_list=bg_prio_list,
                     prio_dscp_map=prio_dscp_map,
                     test_traffic_pause=False,
                     test_def=test_def,
                     snappi_extra_params=snappi_extra_params)

        for dut in duthosts:
            check_fabric_counters(dut)

    finally:
        cleanup_config(dut_list, snappi_ports)
