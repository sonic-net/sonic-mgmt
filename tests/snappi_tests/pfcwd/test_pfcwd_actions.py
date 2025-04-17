import pytest
import logging
import random
from tests.common.helpers.assertions import pytest_require, pytest_assert                   # noqa: F401
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts_multidut     # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
    snappi_api, snappi_multi_base_config, cleanup_config, get_snappi_ports_for_rdma, \
    get_snappi_ports, get_snappi_ports_multi_dut, clear_fabric_counters, check_fabric_counters      # noqa: F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map, lossless_prio_list, \
    lossy_prio_list, all_prio_list                                                                  # noqa: F401
from tests.common.snappi_tests.common_helpers import get_pfcwd_stats
from tests.snappi_tests.pfcwd.files.pfcwd_actions_helper import run_pfc_test
from tests.common.config_reload import config_reload
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.snappi_tests.variables import MULTIDUT_PORT_INFO, MULTIDUT_TESTBED

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology('multidut-tgen')]

port_map = [[1, 100, 1, 100], [1, 400, 1, 400]]
over_subs_port_map = [[1, 100, 2, 100], [1, 400, 2, 400]]

# Testplan: docs/testplan/PFC_Snappi_Additional_Testcases.md
# This test-script covers testcase#10: PFCWD-enabled DROP mode test.
# This test-script also covers testcase#11: PFCWD-enabled FWD mode test.


@pytest.mark.parametrize('port_map', port_map)
@pytest.mark.parametrize("multidut_port_info", MULTIDUT_PORT_INFO[MULTIDUT_TESTBED])
def test_pfcwd_drop_90_10(snappi_api,                  # noqa: F811
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
    Purpose of the test case is to enable PFCWD in drop mode and send 90% lossless traffic and 10%
    lossy traffic and check the behavior. DUT is receiving pause storm on the egress port. DUT should
    drop the lossless packets without generating any pause towards IXIA transmitter. No loss for lossy traffic.

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut_multidut (pytest fixture): fanout graph
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

    pkt_size = 1024
    # port_map is defined as port-speed combination.
    # first two parameters are count of egress links and its speed.
    # last two parameters are count of ingress links and its speed.

    for testbed_subtype, rdma_ports in multidut_port_info.items():
        tx_port_count = port_map[0]
        rx_port_count = port_map[2]
        tmp_snappi_port_list = get_snappi_ports
        snappi_port_list = []
        for item in tmp_snappi_port_list:
            if (int(item['speed']) == (port_map[1] * 1000)):
                snappi_port_list.append(item)
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
    test_check = {'lossless': 100, 'lossy': 0, 'speed_tol': 91, 'loss_expected': True, 'pfc': True}

    test_def = {'TEST_FLOW_AGGR_RATE_PERCENT': 90,
                'BG_FLOW_AGGR_RATE_PERCENT': 10,
                'data_flow_pkt_size': pkt_size,
                'DATA_FLOW_DURATION_SEC': 300,
                'data_flow_delay_sec': 1,
                'SNAPPI_POLL_DELAY_SEC': 60,
                'test_type': '/tmp/One_Ingress_Egress_pfcwd_drop_90_10_dist'+str(port_map[1])+'Gbps',
                'line_card_choice': testbed_subtype,
                'port_map': port_map,
                'enable_pfcwd_drop': True,
                'enable_pfcwd_fwd': False,
                'enable_credit_wd': True,
                'stats_interval': 60,
                'background_traffic': True,
                'verify_flows': False,
                'imix': False,
                'test_check': test_check}

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

    logger.info('PFC-WD stats at the start of the test:')
    for prio in test_prio_list:
        for port in snappi_ports:
            if len(dut_list) == 1:
                if dut_list[0].hostname == port['peer_device']:
                    logger.info('PFCWD stats for dut:{}, port:{},prio:{}'.
                                format(dut_list[0].hostname, port['peer_port'], prio))
                    pfcwd_stats = get_pfcwd_stats(dut_list[0], port['peer_port'], prio)
                    logger.info('PFCWD Stats:{}'.format(pfcwd_stats))
            else:
                for dut in dut_list:
                    if dut.hostname == port['peer_device']:
                        logger.info('PFCWD stats for dut:{}, port:{},prio:{}'.
                                    format(dut.hostname, port['peer_port'], prio))
                        pfcwd_stats = get_pfcwd_stats(dut, port['peer_port'], prio)
                        logger.info('PFCWD Stats::{}'.format(pfcwd_stats))

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
                     test_traffic_pause=True,
                     test_def=test_def,
                     snappi_extra_params=snappi_extra_params)

        logger.info('PFC-WD stats at the end of the test:')
        for prio in test_prio_list:
            for port in snappi_ports:
                if len(dut_list) == 1:
                    if dut_list[0].hostname == port['peer_device']:
                        pfcwd_stats = get_pfcwd_stats(dut_list[0], port['peer_port'], prio)
                        logger.info('PFCWD Stats:for dut:{}, port:{},prio:{}, stats::{}'.
                                    format(dut_list[0].hostname, port['peer_port'], prio, pfcwd_stats))
                else:
                    for dut in dut_list:
                        if dut.hostname == port['peer_device']:
                            pfcwd_stats = get_pfcwd_stats(dut, port['peer_port'], prio)
                            logger.info('PFCWD Stats:for dut:{}, port:{},prio:{}, stats::{}'.
                                        format(dut.hostname, port['peer_port'], prio, pfcwd_stats))

        for dut in duthosts:
            check_fabric_counters(dut)

    finally:
        for duthost in dut_list:
            config_reload(sonic_host=duthost, config_source='config_db', safe_reload=True)


@pytest.mark.parametrize('port_map', port_map)
@pytest.mark.parametrize("multidut_port_info", MULTIDUT_PORT_INFO[MULTIDUT_TESTBED])
def test_pfcwd_drop_uni(snappi_api,                  # noqa: F811
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
    Purpose of the test case is to enable PFCWD in drop mode and send 90% lossless traffic and 10%
    lossy traffic and check the behavior. DUT is receiving pause storm on the egress port. DUT should
    drop the lossless packets without generating any pause towards IXIA transmitter. No loss for lossy traffic.

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut_multidut (pytest fixture): fanout graph
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

    pkt_size = 1024
    # port_map is defined as port-speed combination.
    # first two parameters are count of egress links and its speed.
    # last two parameters are count of ingress links and its speed.

    for testbed_subtype, rdma_ports in multidut_port_info.items():
        tx_port_count = port_map[0]
        rx_port_count = port_map[2]
        tmp_snappi_port_list = get_snappi_ports
        snappi_port_list = []
        for item in tmp_snappi_port_list:
            if (int(item['speed']) == (port_map[1] * 1000)):
                snappi_port_list.append(item)
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
    test_check = {'lossless': 100, 'lossy': 0, 'speed_tol': 50, 'loss_expected': True, 'pfc': True}

    test_def = {'TEST_FLOW_AGGR_RATE_PERCENT': 40,
                'BG_FLOW_AGGR_RATE_PERCENT': 60,
                'data_flow_pkt_size': pkt_size,
                'DATA_FLOW_DURATION_SEC': 300,
                'data_flow_delay_sec': 1,
                'SNAPPI_POLL_DELAY_SEC': 60,
                'test_type': '/tmp/One_Ingress_Egress_pfcwd_drop_uni_dist'+str(port_map[1])+'Gbps',
                'line_card_choice': testbed_subtype,
                'port_map': port_map,
                'enable_pfcwd_drop': True,
                'enable_pfcwd_fwd': False,
                'enable_credit_wd': True,
                'stats_interval': 60,
                'background_traffic': True,
                'verify_flows': False,
                'imix': False,
                'test_check': test_check}

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

    logger.info('PFC-WD stats at the start of the test:')
    for prio in test_prio_list:
        for port in snappi_ports:
            if len(dut_list) == 1:
                if dut_list[0].hostname == port['peer_device']:
                    logger.info('PFCWD stats for dut:{}, port:{},prio:{}'.
                                format(dut_list[0].hostname, port['peer_port'], prio))
                    pfcwd_stats = get_pfcwd_stats(dut_list[0], port['peer_port'], prio)
                    logger.info('PFCWD Stats:{}'.format(pfcwd_stats))
            else:
                for dut in dut_list:
                    if dut.hostname == port['peer_device']:
                        logger.info('PFCWD stats for dut:{}, port:{},prio:{}'.
                                    format(dut.hostname, port['peer_port'], prio))
                        pfcwd_stats = get_pfcwd_stats(dut, port['peer_port'], prio)
                        logger.info('PFCWD Stats::{}'.format(pfcwd_stats))

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
                     test_traffic_pause=True,
                     test_def=test_def,
                     snappi_extra_params=snappi_extra_params)

        logger.info('PFC-WD stats at the end of the test:')
        for prio in test_prio_list:
            for port in snappi_ports:
                if len(dut_list) == 1:
                    if dut_list[0].hostname == port['peer_device']:
                        pfcwd_stats = get_pfcwd_stats(dut_list[0], port['peer_port'], prio)
                        logger.info('PFCWD Stats:for dut:{}, port:{},prio:{}, stats::{}'.
                                    format(dut_list[0].hostname, port['peer_port'], prio, pfcwd_stats))
                else:
                    for dut in dut_list:
                        if dut.hostname == port['peer_device']:
                            pfcwd_stats = get_pfcwd_stats(dut, port['peer_port'], prio)
                            logger.info('PFCWD Stats:for dut:{}, port:{},prio:{}, stats::{}'.
                                        format(dut.hostname, port['peer_port'], prio, pfcwd_stats))

        for dut in duthosts:
            check_fabric_counters(dut)

    finally:
        for duthost in dut_list:
            config_reload(sonic_host=duthost, config_source='config_db', safe_reload=True)


@pytest.mark.parametrize('port_map', port_map)
@pytest.mark.parametrize("multidut_port_info", MULTIDUT_PORT_INFO[MULTIDUT_TESTBED])
def test_pfcwd_frwd_90_10(snappi_api,                  # noqa: F811
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
    Purpose of the test case is to check behavior of the DUT when PFCWD is enabled in FORWARD mode and egress port
    is congested with PAUSE storm. DUT in this mode should forward the lossless packets irrespective of the pause
    storm and not send any PAUSE frames towards IXIA transmitter. No effect on lossy traffic.

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

    for testbed_subtype, rdma_ports in multidut_port_info.items():
        tx_port_count = port_map[0]
        rx_port_count = port_map[2]
        tmp_snappi_port_list = get_snappi_ports
        snappi_port_list = []
        for item in tmp_snappi_port_list:
            if (int(item['speed']) == (port_map[1] * 1000)):
                snappi_port_list.append(item)
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

    test_def = {'TEST_FLOW_AGGR_RATE_PERCENT': 90,
                'BG_FLOW_AGGR_RATE_PERCENT': 10,
                'data_flow_pkt_size': pkt_size,
                'DATA_FLOW_DURATION_SEC': 300,
                'data_flow_delay_sec': 1,
                'SNAPPI_POLL_DELAY_SEC': 60,
                'test_type': '/tmp/One_Ingress_Egress_pfcwd_frwd_90_10_dist'+str(port_map[1])+'Gbps',
                'line_card_choice': testbed_subtype,
                'port_map': port_map,
                'enable_pfcwd_drop': False,
                'enable_pfcwd_fwd': True,
                'enable_credit_wd': True,
                'stats_interval': 60,
                'background_traffic': True,
                'verify_flows': False,
                'imix': False,
                'test_check': test_check}

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

    logger.info('PFC-WD stats at the start of the test:')
    for prio in test_prio_list:
        for port in snappi_ports:
            if len(dut_list) == 1:
                if dut_list[0].hostname == port['peer_device']:
                    logger.info('PFCWD stats for dut:{}, port:{},prio:{}'.
                                format(dut_list[0].hostname, port['peer_port'], prio))
                    pfcwd_stats = get_pfcwd_stats(dut_list[0], port['peer_port'], prio)
                    logger.info('PFCWD Stats:{}'.format(pfcwd_stats))
            else:
                for dut in dut_list:
                    if dut.hostname == port['peer_device']:
                        logger.info('PFCWD stats for dut:{}, port:{},prio:{}'.
                                    format(dut.hostname, port['peer_port'], prio))
                        pfcwd_stats = get_pfcwd_stats(dut, port['peer_port'], prio)
                        logger.info('PFCWD Stats::{}'.format(pfcwd_stats))

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
                     test_traffic_pause=True,
                     test_def=test_def,
                     snappi_extra_params=snappi_extra_params)

        logger.info('PFC-WD stats at the end of the test:')
        for prio in test_prio_list:
            for port in snappi_ports:
                if len(dut_list) == 1:
                    if dut_list[0].hostname == port['peer_device']:
                        pfcwd_stats = get_pfcwd_stats(dut_list[0], port['peer_port'], prio)
                        logger.info('PFCWD Stats:for dut:{}, port:{},prio:{}, stats::{}'.
                                    format(dut_list[0].hostname, port['peer_port'], prio, pfcwd_stats))
                else:
                    for dut in dut_list:
                        if dut.hostname == port['peer_device']:
                            pfcwd_stats = get_pfcwd_stats(dut, port['peer_port'], prio)
                            logger.info('PFCWD Stats:for dut:{}, port:{},prio:{}, stats::{}'.
                                        format(dut.hostname, port['peer_port'], prio, pfcwd_stats))

        for dut in duthosts:
            check_fabric_counters(dut)

    finally:
        for duthost in dut_list:
            config_reload(sonic_host=duthost, config_source='config_db', safe_reload=True)


@pytest.mark.parametrize('port_map', over_subs_port_map)
@pytest.mark.parametrize("multidut_port_info", MULTIDUT_PORT_INFO[MULTIDUT_TESTBED])
def test_pfcwd_drop_over_subs_40_09(snappi_api,                  # noqa: F811
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
    Purpose of the testcase is to check PFCWD behavior in DROP mode with over-subscription.
    Each ingress is sending 49% of link capacity traffic and DUT is receiving PAUSE storm on egress link.
    DUT should drop lossless packets. No drop for lossy traffic.

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

    for testbed_subtype, rdma_ports in multidut_port_info.items():
        tx_port_count = port_map[0]
        rx_port_count = port_map[2]
        tmp_snappi_port_list = get_snappi_ports
        snappi_port_list = []
        for item in tmp_snappi_port_list:
            if (int(item['speed']) == (port_map[1] * 1000)):
                snappi_port_list.append(item)
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
    test_check = {'lossless': 100, 'lossy': 0, 'speed_tol': 83, 'loss_expected': True, 'pfc': True}

    test_def = {}
    test_def = {'TEST_FLOW_AGGR_RATE_PERCENT': 40,
                'BG_FLOW_AGGR_RATE_PERCENT': 9,
                'data_flow_pkt_size': pkt_size,
                'DATA_FLOW_DURATION_SEC': 300,
                'data_flow_delay_sec': 1,
                'SNAPPI_POLL_DELAY_SEC': 60,
                'test_type': '/tmp/Two_Ingress_Single_Egress_pfcwd_drop_40_9_dist'+str(port_map[1])+'Gbps',
                'line_card_choice': testbed_subtype,
                'port_map': port_map,
                'enable_pfcwd_drop': True,
                'enable_pfcwd_fwd': False,
                'enable_credit_wd': True,
                'stats_interval': 60,
                'background_traffic': True,
                'verify_flows': False,
                'imix': False,
                'test_check': test_check}

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

    logger.info('PFC-WD stats at the start of the test:')
    for prio in test_prio_list:
        for port in snappi_ports:
            if len(dut_list) == 1:
                if dut_list[0].hostname == port['peer_device']:
                    logger.info('PFCWD stats for dut:{}, port:{},prio:{}'.
                                format(dut_list[0].hostname, port['peer_port'], prio))
                    pfcwd_stats = get_pfcwd_stats(dut_list[0], port['peer_port'], prio)
                    logger.info('PFCWD Stats:{}'.format(pfcwd_stats))
            else:
                for dut in dut_list:
                    if dut.hostname == port['peer_device']:
                        logger.info('PFCWD stats for dut:{}, port:{},prio:{}'.
                                    format(dut.hostname, port['peer_port'], prio))
                        pfcwd_stats = get_pfcwd_stats(dut, port['peer_port'], prio)
                        logger.info('PFCWD Stats::{}'.format(pfcwd_stats))

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
                     test_traffic_pause=True,
                     test_def=test_def,
                     snappi_extra_params=snappi_extra_params)

        logger.info('PFC-WD stats at the end of the test:')
        for prio in test_prio_list:
            for port in snappi_ports:
                if len(dut_list) == 1:
                    if dut_list[0].hostname == port['peer_device']:
                        pfcwd_stats = get_pfcwd_stats(dut_list[0], port['peer_port'], prio)
                        logger.info('PFCWD Stats:for dut:{}, port:{},prio:{}, stats::{}'.
                                    format(dut_list[0].hostname, port['peer_port'], prio, pfcwd_stats))
                else:
                    for dut in dut_list:
                        if dut.hostname == port['peer_device']:
                            pfcwd_stats = get_pfcwd_stats(dut, port['peer_port'], prio)
                            logger.info('PFCWD Stats:for dut:{}, port:{},prio:{}, stats::{}'.
                                        format(dut.hostname, port['peer_port'], prio, pfcwd_stats))

        for dut in duthosts:
            check_fabric_counters(dut)

    finally:
        for duthost in dut_list:
            config_reload(sonic_host=duthost, config_source='config_db', safe_reload=True)


@pytest.mark.parametrize('port_map', over_subs_port_map)
@pytest.mark.parametrize("multidut_port_info", MULTIDUT_PORT_INFO[MULTIDUT_TESTBED])
def test_pfcwd_frwd_over_subs_40_09(snappi_api,                  # noqa: F811
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
    Purpose of testcase is to test behavior of DUT in PFCWD-FORWARD mode in oversubscription mode.
    Each ingress is sending 49% of link capacity traffic and DUT is receiving PAUSE storm on egress link.
    DUT should forward for both lossy and lossless traffic without generating PAUSE frames towards IXIA
    transmitter.

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

    for testbed_subtype, rdma_ports in multidut_port_info.items():
        tx_port_count = port_map[0]
        rx_port_count = port_map[2]
        tmp_snappi_port_list = get_snappi_ports
        snappi_port_list = []
        for item in tmp_snappi_port_list:
            if (int(item['speed']) == (port_map[1] * 1000)):
                snappi_port_list.append(item)
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

    test_def = {'TEST_FLOW_AGGR_RATE_PERCENT': 40,
                'BG_FLOW_AGGR_RATE_PERCENT': 9,
                'data_flow_pkt_size': pkt_size,
                'DATA_FLOW_DURATION_SEC': 300,
                'data_flow_delay_sec': 1,
                'SNAPPI_POLL_DELAY_SEC': 60,
                'test_type': '/tmp/Two_Ingress_Single_Egress_pfcwd_frwd_40_9_dist'+str(port_map[1])+'Gbps',
                'line_card_choice': testbed_subtype,
                'port_map': port_map,
                'enable_pfcwd_drop': False,
                'enable_pfcwd_fwd': True,
                'enable_credit_wd': True,
                'stats_interval': 60,
                'background_traffic': True,
                'verify_flows': False,
                'imix': False,
                'test_check': test_check}

    # Selecting only one lossless priority for the test.
    test_prio_list = random.sample(lossless_prio_list, 1)
    pause_prio_list = test_prio_list
    bg_prio_list = random.sample(lossy_prio_list, 3)
    logger.info('Selected lossless priority:{} for the test'.format(test_prio_list))

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

    logger.info('PFC-WD stats at the start of the test:')
    for prio in test_prio_list:
        for port in snappi_ports:
            if len(dut_list) == 1:
                if dut_list[0].hostname == port['peer_device']:
                    logger.info('PFCWD stats for dut:{}, port:{},prio:{}'.
                                format(dut_list[0].hostname, port['peer_port'], prio))
                    pfcwd_stats = get_pfcwd_stats(dut_list[0], port['peer_port'], prio)
                    logger.info('PFCWD Stats:{}'.format(pfcwd_stats))
            else:
                for dut in dut_list:
                    if dut.hostname == port['peer_device']:
                        logger.info('PFCWD stats for dut:{}, port:{},prio:{}'.
                                    format(dut.hostname, port['peer_port'], prio))
                        pfcwd_stats = get_pfcwd_stats(dut, port['peer_port'], prio)
                        logger.info('PFCWD Stats::{}'.format(pfcwd_stats))

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
                     test_traffic_pause=True,
                     test_def=test_def,
                     snappi_extra_params=snappi_extra_params)

        logger.info('PFC-WD stats at the end of the test:')
        for prio in test_prio_list:
            for port in snappi_ports:
                if len(dut_list) == 1:
                    if dut_list[0].hostname == port['peer_device']:
                        pfcwd_stats = get_pfcwd_stats(dut_list[0], port['peer_port'], prio)
                        logger.info('PFCWD Stats:for dut:{}, port:{},prio:{}, stats::{}'.
                                    format(dut_list[0].hostname, port['peer_port'], prio, pfcwd_stats))
                else:
                    for dut in dut_list:
                        if dut.hostname == port['peer_device']:
                            pfcwd_stats = get_pfcwd_stats(dut, port['peer_port'], prio)
                            logger.info('PFCWD Stats:for dut:{}, port:{},prio:{}, stats::{}'.
                                        format(dut.hostname, port['peer_port'], prio, pfcwd_stats))
        for dut in duthosts:
            check_fabric_counters(dut)

    finally:
        for duthost in dut_list:
            config_reload(sonic_host=duthost, config_source='config_db', safe_reload=True)


@pytest.mark.parametrize('port_map', port_map)
@pytest.mark.parametrize("multidut_port_info", MULTIDUT_PORT_INFO[MULTIDUT_TESTBED])
def test_pfcwd_disable_pause_cngtn(snappi_api,                  # noqa: F811
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

    for testbed_subtype, rdma_ports in multidut_port_info.items():
        tx_port_count = port_map[0]
        rx_port_count = port_map[2]
        tmp_snappi_port_list = get_snappi_ports
        snappi_port_list = []
        for item in tmp_snappi_port_list:
            if (int(item['speed']) == (port_map[1] * 1000)):
                snappi_port_list.append(item)
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
    test_check = {'lossless': 0, 'lossy': 0, 'speed_tol': 41, 'loss_expected': False, 'pfc': True}

    test_def = {'TEST_FLOW_AGGR_RATE_PERCENT': 40,
                'BG_FLOW_AGGR_RATE_PERCENT': 60,
                'data_flow_pkt_size': pkt_size,
                'DATA_FLOW_DURATION_SEC': 300,
                'data_flow_delay_sec': 1,
                'SNAPPI_POLL_DELAY_SEC': 60,
                'test_type': '/tmp/Single_Ingress_Single_Egress_pause_cngstn_'+str(port_map[1])+'Gbps',
                'line_card_choice': testbed_subtype,
                'port_map': port_map,
                'enable_pfcwd_drop': False,
                'enable_pfcwd_fwd': False,
                'enable_credit_wd': False,
                'stats_interval': 60,
                'background_traffic': True,
                'verify_flows': False,
                'imix': False,
                'test_check': test_check}
    # Selecting only one lossless priority for the test.
    test_prio_list = random.sample(lossless_prio_list, 1)
    pause_prio_list = test_prio_list
    bg_prio_list = random.sample(lossy_prio_list, 3)
    logger.info('Selected lossless priority:{} for the test'.format(test_prio_list))

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
                     test_traffic_pause=True,
                     test_def=test_def,
                     snappi_extra_params=snappi_extra_params)

        for dut in duthosts:
            check_fabric_counters(dut)

    finally:
        for duthost in dut_list:
            config_reload(sonic_host=duthost, config_source='config_db', safe_reload=True)
