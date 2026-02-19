import pytest
import random
from tests.common.helpers.assertions import pytest_require, pytest_assert                           # noqa: F401
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts_multidut, \
    fanout_graph_facts                                                                              # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
    snappi_api, snappi_dut_base_config, get_snappi_ports_for_rdma, cleanup_config, \
    snappi_testbed_config, get_snappi_ports_single_dut, snappi_port_selection, \
    get_snappi_ports, tgen_port_info, tgen_testbed_subtype, is_snappi_multidut, get_snappi_ports_multi_dut, \
    clear_fabric_counters, check_fabric_counters, snappi_multi_base_config                          # noqa: F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map, lossless_prio_list, \
    lossy_prio_list, all_prio_list, disable_pfcwd                                                   # noqa: F401
from tests.snappi_tests.pfc.files.pfc_congestion_helper import run_pfc_test
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.snappi_tests.cisco.helper import disable_voq_watchdog                                    # noqa: F401

import logging
logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology('multidut-tgen')]


@pytest.fixture(autouse=True, scope='module')
def number_of_tx_rx_ports():
    yield (1, 2)


def create_port_map(snappi_ports):
    return ([1,
             int(snappi_ports[0]['snappi_speed_type'].split('_')[1]),
             len(snappi_ports) - 1,
             int(snappi_ports[-1]['snappi_speed_type'].split('_')[1])])

# Testplan: docs/testplan/PFC_Snappi_Additional_Testcases.md
# This test-script covers following testcases:
# testcase#04: DETECT CONGESTION WITH REAL-LIFE TRAFFIC PATTERN - 90% LOSSLESS and 10% LOSSY
# testcase#05: DETECT CONGESTION WITH EQUAL DISTRIBUTION OF LOSSLESS AND LOSSY TRAFFIC


def test_multiple_prio_diff_dist(snappi_api,                   # noqa: F811
                                 conn_graph_facts,             # noqa: F811
                                 fanout_graph_facts_multidut,  # noqa: F811
                                 duthosts,
                                 prio_dscp_map,                # noqa: F811
                                 lossless_prio_list,           # noqa: F811
                                 lossy_prio_list,              # noqa: F811
                                 tbinfo,
                                 tgen_testbed_subtype,         # noqa: F811
                                 tgen_port_info,               # noqa: F811
                                 disable_pfcwd):               # noqa: F811

    """
    Purpose of the test case is to test oversubscription with two ingresses and single ingress.
    Traffic pattern has 90% lossless priority and 10% lossy priority traffic.
    No losses for both lossless and lossy priority traffic.

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut_multidut (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        lossless_prio_list(list): list of lossless priorities
        lossy_prio_list(list): list of lossy priorities.
        tbinfo(key): element to identify testbed info name.
        tgen_port_info(pytest fixture): returns list of ports based on linecards selected.
        tgen_testbed_subtype(pytest_fixture): returns test_subtype for the test.
    Returns:
        N/A

    """

    # port_map is defined as port-speed combination.
    # first two parameters are count of egress links and its speed.
    # last two parameters are count of ingress links and its speed.

    # pkt_size of 1024B will be used unless imix flag is set.
    # With imix flag set, the traffic_generation.py uses IMIX profile.
    pkt_size = 1024

    testbed_config, port_config_list, snappi_ports = tgen_port_info
    logger.info("Snappi Ports : {}".format(snappi_ports))

    # port_map = [1 egress port, speed of egress port, remaining ingress ports, speed of ingress port]
    port_map = create_port_map(snappi_ports)

    enable_pfcwd = True
    if duthosts[0].facts["platform_asic"] == 'cisco-8000' and duthosts[0].get_facts().get("modular_chassis"):
        enable_pfcwd = False

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
                'test_type': 'logs/snappi_tests/pfc/Two_Ingress_Single_Egress_diff_dist_'+str(port_map[1])+'Gbps',
                'line_card_choice': tgen_testbed_subtype,
                'port_map': port_map,
                'enable_pfcwd': enable_pfcwd,
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

    for dut in duthosts:
        clear_fabric_counters(dut)

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


def test_multiple_prio_uni_dist(snappi_api,                   # noqa: F811
                                conn_graph_facts,             # noqa: F811
                                fanout_graph_facts_multidut,  # noqa: F811
                                duthosts,
                                prio_dscp_map,                # noqa: F811
                                lossless_prio_list,           # noqa: F811
                                lossy_prio_list,              # noqa: F811
                                tbinfo,
                                tgen_testbed_subtype,         # noqa: F811
                                tgen_port_info,               # noqa: F811
                                disable_pfcwd):               # noqa: F811
    """
    Purpose of the test case is to test oversubscription with two ingresses and single ingress.
    Traffic pattern has 24% lossless priority and 36% lossy priority traffic.
    Each priority carries equal 12% of traffic.
    No losses for lossless priority traffic. Some loss expected for lossy priority traffic.
    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        lossless_prio_list(list): list of lossless priorities
        lossy_prio_list(list): list of lossy priorities.
        tbinfo(key): element to identify testbed info name.
        tgen_port_info(pytest fixture): returns list of ports based on linecards selected.
        tgen_testbed_subtype(pytest_fixture): returns test_subtype for the test.

    Returns:
        N/A
    """
    # port_map is defined as port-speed combination.
    # first two parameters are count of egress links and its speed.
    # last two parameters are count of ingress links and its speed.

    # pkt_size of 1024B will be used unless imix flag is set.
    # With imix flag set, the traffic_generation.py uses IMIX profile.
    pkt_size = 1024

    testbed_config, port_config_list, snappi_ports = tgen_port_info
    logger.info("Snappi Ports : {}".format(snappi_ports))

    # port_map = [1 egress port, speed of egress port, remaining ingress ports, speed of ingress port]
    port_map = create_port_map(snappi_ports)

    enable_pfcwd = True
    if duthosts[0].facts["platform_asic"] == 'cisco-8000' and duthosts[0].get_facts().get("modular_chassis"):
        enable_pfcwd = False

    # Percentage drop expected for lossless and lossy traffic.
    # speed_tol is speed tolerance between egress link speed and actual speed.
    # loss_expected to check losses on DUT and TGEN.
    test_check = {'lossless': 0, 'lossy': 51, 'speed_tol': 3, 'loss_expected': True, 'pfc': True}

    test_def = {'TEST_FLOW_AGGR_RATE_PERCENT': 40,
                'BG_FLOW_AGGR_RATE_PERCENT': 60,
                'data_flow_pkt_size': pkt_size,
                'DATA_FLOW_DURATION_SEC': 300,
                'data_flow_delay_sec': 0,
                'SNAPPI_POLL_DELAY_SEC': 60,
                'test_type': 'logs/snappi_tests/pfc/Two_Ingress_Single_Egress_uni_dist_full'+str(port_map[1])+'Gbps',
                'line_card_choice': tgen_testbed_subtype,
                'port_map': port_map,
                'enable_pfcwd': enable_pfcwd,
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

    for dut in duthosts:
        clear_fabric_counters(dut)

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


def test_multiple_prio_equal_dist(snappi_api,                   # noqa: F811
                                  conn_graph_facts,             # noqa: F811
                                  fanout_graph_facts_multidut,  # noqa: F811
                                  duthosts,
                                  prio_dscp_map,                # noqa: F811
                                  lossless_prio_list,           # noqa: F811
                                  lossy_prio_list,              # noqa: F811
                                  tbinfo,
                                  tgen_testbed_subtype,         # noqa: F811
                                  tgen_port_info,               # noqa: F811
                                  disable_pfcwd):               # noqa: F811

    """
    Purpose of the test case is to test oversubscription with two ingresses and single ingress.
    Traffic pattern has 24% lossless priority and 36% lossy priority traffic.
    Each priority carries equal 12% of traffic.
    No losses for lossless priority traffic. Some loss expected for lossy priority traffic.

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        lossless_prio_list(list): list of lossless priorities
        lossy_prio_list(list): list of lossy priorities.
        tbinfo(key): element to identify testbed info name.
        tgen_port_info(pytest fixture): returns list of ports based on linecards selected.
        tgen_testbed_subtype(pytest_fixture): returns test_subtype for the test.

    Returns:
        N/A
    """
    # port_map is defined as port-speed combination.
    # first two parameters are count of egress links and its speed.
    # last two parameters are count of ingress links and its speed.

    # pkt_size of 1024B will be used unless imix flag is set.
    # With imix flag set, the traffic_generation.py uses IMIX profile.
    pkt_size = 1024

    testbed_config, port_config_list, snappi_ports = tgen_port_info
    logger.info("Snappi Ports : {}".format(snappi_ports))

    # port_map = [1 egress port, speed of egress port, remaining ingress ports, speed of ingress port]
    port_map = create_port_map(snappi_ports)

    enable_pfcwd = True
    if duthosts[0].facts["platform_asic"] == 'cisco-8000' and duthosts[0].get_facts().get("modular_chassis"):
        enable_pfcwd = False

    # Percentage drop expected for lossless and lossy traffic.
    # speed_tol is speed tolerance between egress link speed and actual speed.
    # loss_expected to check losses on DUT and TGEN.
    test_check = {'lossless': 0, 'lossy': 20, 'speed_tol': 3, 'loss_expected': True, 'pfc': True}

    test_def = {'TEST_FLOW_AGGR_RATE_PERCENT': 30,
                'BG_FLOW_AGGR_RATE_PERCENT': 30,
                'data_flow_pkt_size': pkt_size,
                'DATA_FLOW_DURATION_SEC': 300,
                'data_flow_delay_sec': 0,
                'SNAPPI_POLL_DELAY_SEC': 60,
                'test_type': 'logs/snappi_tests/pfc/Two_Ingress_Single_Egress_equal_dist'+str(port_map[1])+'Gbps',
                'line_card_choice': tgen_testbed_subtype,
                'port_map': port_map,
                'enable_pfcwd': enable_pfcwd,
                'enable_credit_wd': True,
                'stats_interval': 60,
                'background_traffic': True,
                'imix': False,
                'test_check': test_check,
                'verify_flows': False}

    test_prio_list = lossless_prio_list
    pause_prio_list = test_prio_list
    bg_prio_list = random.sample(lossy_prio_list, 2)
    logger.info('Selected lossless :{} and lossy priorities:{} for the test'.format(test_prio_list, bg_prio_list))

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.duthost1 = snappi_ports[0]['duthost']
    snappi_extra_params.multi_dut_params.duthost2 = snappi_ports[-1]['duthost']

    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    for dut in duthosts:
        clear_fabric_counters(dut)

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


def test_multiple_prio_non_cngtn(snappi_api,                   # noqa: F811
                                 conn_graph_facts,             # noqa: F811
                                 fanout_graph_facts_multidut,  # noqa: F811
                                 duthosts,
                                 prio_dscp_map,                # noqa: F811
                                 lossless_prio_list,           # noqa: F811
                                 lossy_prio_list,              # noqa: F811
                                 tbinfo,
                                 tgen_testbed_subtype,         # noqa: F811
                                 tgen_port_info,               # noqa: F811
                                 disable_pfcwd):               # noqa: F811

    """
    Purpose of the test case is to test oversubscription with two ingresses and single ingress.
    Traffic pattern has 18% lossless priority and 27% lossy priority traffic.
    Total ingress link is sending only 45% link capacity and hence egress will not be congested.
    No losses for both lossless and lossy priority traffic.

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        lossless_prio_list(list): list of lossless priorities
        lossy_prio_list(list): list of lossy priorities.
        tbinfo(key): element to identify testbed info name.
        tgen_port_info(pytest fixture): returns list of ports based on linecards selected.
        tgen_testbed_subtype(pytest_fixture): returns test_subtype for the test.

    Returns:
        N/A

    """

    # port_map is defined as port-speed combination.
    # first two parameters are count of egress links and its speed.
    # last two parameters are count of ingress links and its speed.

    # pkt_size of 1024B will be used unless imix flag is set.
    # With imix flag set, the traffic_generation.py uses IMIX profile.
    pkt_size = 1024

    testbed_config, port_config_list, snappi_ports = tgen_port_info
    logger.info("Snappi Ports : {}".format(snappi_ports))

    # port_map = [1 egress port, speed of egress port, remaining ingress ports, speed of ingress port]
    port_map = create_port_map(snappi_ports)

    enable_pfcwd = True
    if duthosts[0].facts["platform_asic"] == 'cisco-8000' and duthosts[0].get_facts().get("modular_chassis"):
        enable_pfcwd = False

    # Percentage drop expected for lossless and lossy traffic.
    # speed_tol is speed tolerance between egress link speed and actual speed.
    # loss_expected to check losses on DUT and TGEN.
    test_check = {'lossless': 0, 'lossy': 0, 'speed_tol': 14, 'loss_expected': False, 'pfc': False}

    test_def = {'TEST_FLOW_AGGR_RATE_PERCENT': 18,
                'BG_FLOW_AGGR_RATE_PERCENT': 27,
                'data_flow_pkt_size': pkt_size,
                'DATA_FLOW_DURATION_SEC': 300,
                'data_flow_delay_sec': 0,
                'SNAPPI_POLL_DELAY_SEC': 60,
                'test_type': 'logs/snappi_tests/pfc/Two_Ingress_Single_Egress_non_cngstn_'+str(port_map[1])+'Gbps',
                'line_card_choice': tgen_testbed_subtype,
                'port_map': port_map,
                'enable_pfcwd': enable_pfcwd,
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

    for dut in duthosts:
        clear_fabric_counters(dut)

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
