import pytest
from tests.common.helpers.assertions import pytest_require, pytest_assert                   # noqa: F401
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts     # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
    snappi_api, snappi_dut_base_config, get_multidut_snappi_ports, \
    new_get_multidut_tgen_peer_port_set, cleanup_config    # noqa: F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map        # noqa: F401
from tests.snappi_tests.variables import config_set, line_card_choice
from files.sys_multidut_helper import run_pfc_test
from tests.common.snappi_tests.snappi_systest_params import SnappiSysTestParams

import logging
logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology('multidut-tgen')]


@pytest.mark.parametrize('linecard_configuration_set', [config_set])
@pytest.mark.parametrize('line_card_choice', line_card_choice)
def test_multiple_prio_diff_dist(snappi_api,                  # noqa: F811
                                 conn_graph_facts,            # noqa: F811
                                 fanout_graph_facts,          # noqa: F811
                                 duthosts,
                                 prio_dscp_map,                # noqa: F811
                                 line_card_choice,
                                 linecard_configuration_set,
                                 get_multidut_snappi_ports):    # noqa: F811

    """
    Test if PFC can pause multiple lossless priorities for 100Gbps line-rate

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        line_card_choice: Line card choice to be mentioned in the variable.py file
        linecard_configuration_set : Line card classification, (min 1 or max 2  hostnames and asics to be given)
    Returns:
        N/A
    """

    # port_map is defined as port-speed combination.
    # first two parameters are count of egress links and its speed.
    # last two parameters are count of ingress links and its speed.
    if '100Gbps' in line_card_choice:
        port_map = [1, 100, 1, 100]
    else:
        port_map = [1, 400, 1, 400]

    # pkt_size of 1024B will be used unless imix flag is set.
    # With imix flag set, the traffic_generation.py uses IMIX profile.
    pkt_size = 1024

    # Percentage drop expected for lossless and lossy traffic.
    # speed_tol is speed tolerance between egress link speed and actual speed.
    # loss_expected to check losses on DUT and TGEN.
    test_check = {'lossless': 0, 'lossy': 0, 'speed_tol': 3, 'loss_expected': False}
    test_def = {'TEST_FLOW_AGGR_RATE_PERCENT': 88,
                'BG_FLOW_AGGR_RATE_PERCENT': 12,
                'data_flow_pkt_size': pkt_size,
                'DATA_FLOW_DURATION_SEC': 300,
                'data_flow_delay_sec': 0,
                'SNAPPI_POLL_DELAY_SEC': 60,
                'test_type': '/tmp/Single_Ingress_Egress_diff_dist_'+str(port_map[1])+'Gbps',
                'line_card_choice': line_card_choice,
                'port_map': port_map,
                'enable_pfcwd': True,
                'enable_credit_wd': True,
                'stats_interval': 60,
                'background_traffic': True,
                'imix': True,
                'test_check': test_check,
                'verify_flows': True}

    logger.info('Starting the test for line_card_choice : {}'.format(line_card_choice))
    if line_card_choice not in linecard_configuration_set.keys():
        assert False, "Invalid line_card_choice value passed in parameter"

    if (len(linecard_configuration_set[line_card_choice]['hostname']) >= 2):
        dut_list = [dut for dut in duthosts
                    if dut.hostname in linecard_configuration_set[line_card_choice]['hostname']]
        duthost1, duthost2 = dut_list
    elif (len(linecard_configuration_set[line_card_choice]['hostname']) == 1):
        dut_list = [dut for dut in duthosts
                    if linecard_configuration_set[line_card_choice]['hostname'] == [dut.hostname]]
        duthost1 = duthost2 = dut_list[0]
    else:
        assert False, "Hostname can't be an empty list"

    snappi_port_list = get_multidut_snappi_ports(line_card_choice=line_card_choice,
                                                 line_card_info=linecard_configuration_set[line_card_choice])

    if len(snappi_port_list) < 2:
        assert False, "Need Minimum of 2 ports for the test"

    snappi_ports = new_get_multidut_tgen_peer_port_set(line_card_choice, snappi_port_list, config_set, port_map)

    if len(snappi_ports) < 2:
        assert False, "Need Minimum of 2 ports for the test"

    logger.info("Snappi Ports : {}".format(snappi_ports))

    testbed_config, port_config_list, snappi_ports = snappi_dut_base_config(dut_list,
                                                                            snappi_ports,
                                                                            snappi_api)

    test_prio_list = [3, 4]
    pause_prio_list = test_prio_list
    bg_prio_list = [0, 1, 2]

    snappi_extra_params = SnappiSysTestParams()
    snappi_extra_params.multi_dut_params.duthost1 = duthost1
    snappi_extra_params.multi_dut_params.duthost2 = duthost2
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    try:
        run_pfc_test(api=snappi_api,
                     testbed_config=testbed_config,
                     port_config_list=port_config_list,
                     conn_data=conn_graph_facts,
                     fanout_data=fanout_graph_facts,
                     global_pause=False,
                     pause_prio_list=pause_prio_list,
                     test_prio_list=test_prio_list,
                     bg_prio_list=bg_prio_list,
                     prio_dscp_map=prio_dscp_map,
                     test_traffic_pause=False,
                     test_def=test_def,
                     snappi_extra_params=snappi_extra_params)
    finally:
        cleanup_config(dut_list, snappi_ports)


@pytest.mark.parametrize('linecard_configuration_set', [config_set])
@pytest.mark.parametrize('line_card_choice', line_card_choice)
def test_multiple_prio_uni_dist(snappi_api,                  # noqa: F811
                                conn_graph_facts,            # noqa: F811
                                fanout_graph_facts,          # noqa: F811
                                duthosts,
                                prio_dscp_map,                # noqa: F811
                                line_card_choice,
                                linecard_configuration_set,
                                get_multidut_snappi_ports):    # noqa: F811

    """
    Test with single ingress and egress with uniform traffic across  multiple lossless priorities for 100Gbps line-rate

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        line_card_choice: Line card choice to be mentioned in the variable.py file
        linecard_configuration_set : Line card classification, (min 1 or max 2  hostnames and asics to be given)
    Returns:
        N/A
    """

    # port_map is defined as port-speed combination.
    # first two parameters are count of egress links and its speed.
    # last two parameters are count of ingress links and its speed.
    if '100Gbps' in line_card_choice:
        port_map = [1, 100, 1, 100]
    else:
        port_map = [1, 400, 1, 400]

    # pkt_size of 1024B will be used unless imix flag is set.
    # With imix flag set, the traffic_generation.py uses IMIX profile.
    pkt_size = 1024

    # Percentage drop expected for lossless and lossy traffic.
    # speed_tol is speed tolerance between egress link speed and actual speed.
    # loss_expected to check losses on DUT and TGEN.
    test_check = {'lossless': 0, 'lossy': 0, 'speed_tol': 3, 'loss_expected': False}

    test_def = {'TEST_FLOW_AGGR_RATE_PERCENT': 40,
                'BG_FLOW_AGGR_RATE_PERCENT': 60,
                'data_flow_pkt_size': pkt_size,
                'DATA_FLOW_DURATION_SEC': 300,
                'data_flow_delay_sec': 0,
                'SNAPPI_POLL_DELAY_SEC': 60,
                'test_type': '/tmp/Single_Ingress_Egress_uni_dist_'+str(port_map[1])+'Gbps',
                'line_card_choice': line_card_choice,
                'port_map': port_map,
                'enable_pfcwd': True,
                'enable_credit_wd': True,
                'stats_interval': 60,
                'background_traffic': True,
                'imix': True,
                'test_check': test_check,
                'verify_flows': True}

    logger.info('Starting the test for line_card_choice : {}'.format(line_card_choice))
    if line_card_choice not in linecard_configuration_set.keys():
        assert False, "Invalid line_card_choice value passed in parameter"

    if (len(linecard_configuration_set[line_card_choice]['hostname']) >= 2):
        dut_list = [dut for dut in duthosts
                    if dut.hostname in linecard_configuration_set[line_card_choice]['hostname']]
        duthost1, duthost2 = dut_list
    elif (len(linecard_configuration_set[line_card_choice]['hostname']) == 1):
        dut_list = [dut for dut in duthosts
                    if linecard_configuration_set[line_card_choice]['hostname'] == [dut.hostname]]
        duthost1 = duthost2 = dut_list[0]
    else:
        assert False, "Hostname can't be an empty list"

    snappi_port_list = get_multidut_snappi_ports(line_card_choice=line_card_choice,
                                                 line_card_info=linecard_configuration_set[line_card_choice])

    if len(snappi_port_list) < 2:
        assert False, "Need Minimum of 2 ports for the test"

    # port_map is read as egress port_map[0] links of port_map[1] speed
    # and ingress port_map[2] links of port_map[3] speed
    port_map = test_def['port_map']

    snappi_ports = new_get_multidut_tgen_peer_port_set(line_card_choice, snappi_port_list, config_set, port_map)

    if len(snappi_ports) < 2:
        assert False, "Need Minimum of 2 ports for the test"

    testbed_config, port_config_list, snappi_ports = snappi_dut_base_config(dut_list,
                                                                            snappi_ports,
                                                                            snappi_api)

    test_prio_list = [3, 4]
    pause_prio_list = test_prio_list
    bg_prio_list = [0, 1, 2]
    logger.info("Snappi Ports : {}".format(snappi_ports))

    snappi_extra_params = SnappiSysTestParams()
    snappi_extra_params.multi_dut_params.duthost1 = duthost1
    snappi_extra_params.multi_dut_params.duthost2 = duthost2
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    try:
        run_pfc_test(api=snappi_api,
                     testbed_config=testbed_config,
                     port_config_list=port_config_list,
                     conn_data=conn_graph_facts,
                     fanout_data=fanout_graph_facts,
                     global_pause=False,
                     pause_prio_list=pause_prio_list,
                     test_prio_list=test_prio_list,
                     bg_prio_list=bg_prio_list,
                     prio_dscp_map=prio_dscp_map,
                     test_traffic_pause=False,
                     test_def=test_def,
                     snappi_extra_params=snappi_extra_params)
    finally:
        cleanup_config(dut_list, snappi_ports)


@pytest.mark.parametrize('linecard_configuration_set', [config_set])
@pytest.mark.parametrize('line_card_choice', line_card_choice)
def test_single_lossless_prio(snappi_api,                  # noqa: F811
                              conn_graph_facts,            # noqa: F811
                              fanout_graph_facts,          # noqa: F811
                              duthosts,
                              prio_dscp_map,                # noqa: F811
                              line_card_choice,
                              linecard_configuration_set,
                              get_multidut_snappi_ports):    # noqa: F811

    """
    Test for single ingress and egress with single lossless priority for 100Gbps line-rate

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        line_card_choice: Line card choice to be mentioned in the variable.py file
        linecard_configuration_set : Line card classification, (min 1 or max 2  hostnames and asics to be given)
    Returns:
        N/A
    """

    # port_map is defined as port-speed combination.
    # first two parameters are count of egress links and its speed.
    # last two parameters are count of ingress links and its speed.
    if '100Gbps' in line_card_choice:
        port_map = [1, 100, 1, 100]
    else:
        port_map = [1, 400, 1, 400]

    # pkt_size of 1024B will be used unless imix flag is set.
    # With imix flag set, the traffic_generation.py uses IMIX profile.
    pkt_size = 1024

    # Percentage drop expected for lossless and lossy traffic.
    # speed_tol is speed tolerance between egress link speed and actual speed.
    # loss_expected to check losses on DUT and TGEN.
    test_check = {'lossless': 0, 'lossy': 0, 'speed_tol': 3, 'loss_expected': False}
    test_def = {'TEST_FLOW_AGGR_RATE_PERCENT': 100,
                'BG_FLOW_AGGR_RATE_PERCENT': 50,
                'data_flow_pkt_size': pkt_size,
                'DATA_FLOW_DURATION_SEC': 300,
                'data_flow_delay_sec': 0,
                'SNAPPI_POLL_DELAY_SEC': 60,
                'test_type': '/tmp/Single_Ingress_Egress_1Prio_linerate_'+str(port_map[1])+'Gbps',
                'line_card_choice': line_card_choice,
                'port_map': port_map,
                'enable_pfcwd': True,
                'enable_credit_wd': True,
                'stats_interval': 60,
                'background_traffic': False,
                'imix': True,
                'test_check': test_check,
                'verify_flows': True}

    logger.info('Starting the test for line_card_choice : {}'.format(line_card_choice))

    if line_card_choice not in linecard_configuration_set.keys():
        assert False, "Invalid line_card_choice value passed in parameter"
    if (len(linecard_configuration_set[line_card_choice]['hostname']) >= 2):
        dut_list = [dut for dut in duthosts
                    if dut.hostname in linecard_configuration_set[line_card_choice]['hostname']]
        duthost1, duthost2 = dut_list
    elif (len(linecard_configuration_set[line_card_choice]['hostname']) == 1):
        dut_list = [dut for dut in duthosts
                    if linecard_configuration_set[line_card_choice]['hostname'] == [dut.hostname]]
        duthost1 = duthost2 = dut_list[0]
    else:
        assert False, "Hostname can't be an empty list"

    snappi_port_list = get_multidut_snappi_ports(line_card_choice=line_card_choice,
                                                 line_card_info=linecard_configuration_set[line_card_choice])

    if len(snappi_port_list) < 2:
        assert False, "Need Minimum of 2 ports for the test"

    # port_map is read as egress port_map[0] links of port_map[1] speed
    # and ingress port_map[2] links of port_map[3] speed
    port_map = test_def['port_map']

    snappi_ports = new_get_multidut_tgen_peer_port_set(line_card_choice, snappi_port_list, config_set, port_map)

    if len(snappi_ports) < 2:
        assert False, "Need Minimum of 2 ports for the test"

    testbed_config, port_config_list, snappi_ports = snappi_dut_base_config(dut_list,
                                                                            snappi_ports,
                                                                            snappi_api)

    test_prio_list = [3]
    logger.info('Selected Test Prio:{}'.format(test_prio_list))
    pause_prio_list = test_prio_list
    bg_prio_list = [0, 1, 2]
    logger.info("Pkt Size:{}, Current port_map:{} and Snappi Ports : {}".format(pkt_size, port_map, snappi_ports))

    snappi_extra_params = SnappiSysTestParams()
    snappi_extra_params.multi_dut_params.duthost1 = duthost1
    snappi_extra_params.multi_dut_params.duthost2 = duthost2
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    try:
        run_pfc_test(api=snappi_api,
                     testbed_config=testbed_config,
                     port_config_list=port_config_list,
                     conn_data=conn_graph_facts,
                     fanout_data=fanout_graph_facts,
                     global_pause=False,
                     pause_prio_list=pause_prio_list,
                     test_prio_list=test_prio_list,
                     bg_prio_list=bg_prio_list,
                     prio_dscp_map=prio_dscp_map,
                     test_traffic_pause=False,
                     test_def=test_def,
                     snappi_extra_params=snappi_extra_params)
    finally:
        cleanup_config(dut_list, snappi_ports)
