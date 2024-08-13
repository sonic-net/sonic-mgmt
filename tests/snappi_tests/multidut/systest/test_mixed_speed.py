import pytest
from tests.common.helpers.assertions import pytest_require, pytest_assert                   # noqa: F401
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts     # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
    snappi_api, snappi_dut_base_config, get_multidut_snappi_ports, \
    new_get_multidut_tgen_peer_port_set, cleanup_config, clear_fabric_counters, check_fabric_counters    # noqa: F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map        # noqa: F401
from tests.snappi_tests.variables import config_set, line_card_choice
from tests.snappi_tests.multidut.systest.files.mixed_speed_multidut_helper import run_pfc_test
from tests.common.snappi_tests.snappi_systest_params import SnappiSysTestParams

import logging
logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology('multidut-tgen')]


@pytest.mark.parametrize('linecard_configuration_set', [config_set])
@pytest.mark.parametrize('line_card_choice', line_card_choice)
def test_mixed_speed_diff_dist_over(snappi_api,                  # noqa: F811
                                    conn_graph_facts,            # noqa: F811
                                    fanout_graph_facts,          # noqa: F811
                                    duthosts,
                                    prio_dscp_map,                # noqa: F811
                                    line_card_choice,
                                    linecard_configuration_set,
                                    get_multidut_snappi_ports):    # noqa: F811

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
    port_map = [1, 100, 1, 400]

    # pkt_size of 1024B will be used unless imix flag is set.
    # With imix flag set, the traffic_generation.py uses IMIX profile.
    pkt_size = 1024

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
                'line_card_choice': line_card_choice,
                'port_map': port_map,
                'enable_pfcwd': True,
                'enable_credit_wd': True,
                'stats_interval': 60,
                'background_traffic': True,
                'imix': False,
                'test_check': test_check,
                'verify_flows': False}

    logger.info('Starting the test for line_card_choice : {}'.format(line_card_choice))
    if line_card_choice not in linecard_configuration_set.keys():
        assert False, "Invalid line_card_choice value passed in parameter"

    if (len(linecard_configuration_set[line_card_choice]['hostname']) >= 2):
        dut_list = [dut for dut in duthosts.frontend_nodes
                    if dut.hostname in linecard_configuration_set[line_card_choice]['hostname']]
        duthost1, duthost2 = dut_list
    elif (len(linecard_configuration_set[line_card_choice]['hostname']) == 1):
        dut_list = [dut for dut in duthosts.frontend_nodes
                    if linecard_configuration_set[line_card_choice]['hostname'] == [dut.hostname]]
        duthost1 = duthost2 = dut_list[0]
    else:
        assert False, "Hostname can't be an empty list"

    snappi_port_list = get_multidut_snappi_ports(line_card_choice=line_card_choice,
                                                 line_card_info=linecard_configuration_set[line_card_choice])

    if len(snappi_port_list) < 2:
        assert False, "snappi_port_list: Need Minimum of 2 ports for the test"

    snappi_ports = new_get_multidut_tgen_peer_port_set(line_card_choice, snappi_port_list, config_set, port_map)

    if len(snappi_ports) < 2:
        assert False, "snappi_port: Need Minimum of 2 ports for the test"

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
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    # Check if the supervisor nodes are present.
    if (duthosts.supervisor_nodes):
        for dut in duthosts.supervisor_nodes:
            clear_fabric_counters(dut)
    # Clear fabric counters for line-cards.
    for dut in dut_list:
        clear_fabric_counters(dut)

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

        # Check the fabric counters for supervisor nodes.
        if (duthosts.supervisor_nodes):
            for dut in duthosts.supervisor_nodes:
                check_fabric_counters(dut)
        # Check the fabric counter for the line-cards.
        for dut in dut_list:
            check_fabric_counters(dut)

    finally:
        cleanup_config(dut_list, snappi_ports)


@pytest.mark.parametrize('linecard_configuration_set', [config_set])
@pytest.mark.parametrize('line_card_choice', line_card_choice)
def test_mixed_speed_uni_dist_over(snappi_api,                  # noqa: F811
                                   conn_graph_facts,            # noqa: F811
                                   fanout_graph_facts,          # noqa: F811
                                   duthosts,
                                   prio_dscp_map,                # noqa: F811
                                   line_card_choice,
                                   linecard_configuration_set,
                                   get_multidut_snappi_ports):    # noqa: F811

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
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        line_card_choice: Line card choice to be mentioned in the variable.py file
        linecard_configuration_set : Line card classification, (min 1 or max 2  hostnames and asics to be given)
    Returns:
        N/A

    Purpose of the test case is to test oversubscription with two ingresses and single ingress.
    Traffic pattern has 90% lossless priority and 10% lossy priority traffic.
    No losses for both lossless and lossy priority traffic.
    """

    # port_map is defined as port-speed combination.
    # first two parameters are count of egress links and its speed.
    # last two parameters are count of ingress links and its speed.
    port_map = [1, 100, 1, 400]

    # pkt_size of 1024B will be used unless imix flag is set.
    # With imix flag set, the traffic_generation.py uses IMIX profile.
    pkt_size = 1024

    # Percentage drop expected for lossless and lossy traffic.
    # speed_tol is speed tolerance between egress link speed and actual speed.
    # loss_expected to check losses on DUT and TGEN.
    test_check = {'lossless': 0, 'lossy': 75, 'speed_tol': 3, 'loss_expected': True, 'pfc': True}
    test_def = {'TEST_FLOW_AGGR_RATE_PERCENT': 40,
                'BG_FLOW_AGGR_RATE_PERCENT': 60,
                'data_flow_pkt_size': pkt_size,
                'DATA_FLOW_DURATION_SEC': 300,
                'data_flow_delay_sec': 0,
                'SNAPPI_POLL_DELAY_SEC': 60,
                'test_type': '/tmp/Single_400Gbps_Ingress_Single_100Gbps_Egress_uni_dist_',
                'line_card_choice': line_card_choice,
                'port_map': port_map,
                'enable_pfcwd': True,
                'enable_credit_wd': True,
                'stats_interval': 60,
                'background_traffic': True,
                'imix': False,
                'test_check': test_check,
                'verify_flows': False}

    logger.info('Starting the test for line_card_choice : {}'.format(line_card_choice))
    if line_card_choice not in linecard_configuration_set.keys():
        assert False, "Invalid line_card_choice value passed in parameter"

    if (len(linecard_configuration_set[line_card_choice]['hostname']) >= 2):
        dut_list = [dut for dut in duthosts.frontend_nodes
                    if dut.hostname in linecard_configuration_set[line_card_choice]['hostname']]
        duthost1, duthost2 = dut_list
    elif (len(linecard_configuration_set[line_card_choice]['hostname']) == 1):
        dut_list = [dut for dut in duthosts.frontend_nodes
                    if linecard_configuration_set[line_card_choice]['hostname'] == [dut.hostname]]
        duthost1 = duthost2 = dut_list[0]
    else:
        assert False, "Hostname can't be an empty list"

    snappi_port_list = get_multidut_snappi_ports(line_card_choice=line_card_choice,
                                                 line_card_info=linecard_configuration_set[line_card_choice])

    if len(snappi_port_list) < 2:
        assert False, "snappi_port_list: Need Minimum of 2 ports for the test"

    snappi_ports = new_get_multidut_tgen_peer_port_set(line_card_choice, snappi_port_list, config_set, port_map)

    if len(snappi_ports) < 2:
        assert False, "snappi_port: Need Minimum of 2 ports for the test"

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
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    if (duthosts.supervisor_nodes):
        for dut in duthosts.supervisor_nodes:
            clear_fabric_counters(dut)
    for dut in dut_list:
        clear_fabric_counters(dut)

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

        if (duthosts.supervisor_nodes):
            for dut in duthosts.supervisor_nodes:
                check_fabric_counters(dut)
        for dut in dut_list:
            check_fabric_counters(dut)

    finally:
        cleanup_config(dut_list, snappi_ports)


@pytest.mark.parametrize('linecard_configuration_set', [config_set])
@pytest.mark.parametrize('line_card_choice', line_card_choice)
def test_mixed_speed_pfcwd_enable(snappi_api,                  # noqa: F811
                                  conn_graph_facts,            # noqa: F811
                                  fanout_graph_facts,          # noqa: F811
                                  duthosts,
                                  prio_dscp_map,                # noqa: F811
                                  line_card_choice,
                                  linecard_configuration_set,
                                  get_multidut_snappi_ports):    # noqa: F811

    """
    Test to oversubscribe the 100Gbps egress link and have PFCWD enabled.
    Sending PAUSE frames to egress link for the lossless traffic.
    In response to congestion due to PFC storm, DUT drops lossless traffic on egress side.
    On ingress side, DUT sends PFCs to slow down IXIA transmitter.
    Lossy traffic should be dropped.
    DUT allows equal amount of traffic (lossless and lossy priorities) to the egress.
    Egress traffic is around 60Gbps of lossy traffic only.


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
    port_map = [1, 100, 1, 400]

    # pkt_size of 1024B will be used unless imix flag is set.
    # With imix flag set, the traffic_generation.py uses IMIX profile.
    pkt_size = 1024

    # Percentage drop expected for lossless and lossy traffic.
    # speed_tol is speed tolerance between egress link speed and actual speed.
    # loss_expected to check losses on DUT and TGEN.
    test_check = {'lossless': 100, 'lossy': 75, 'speed_tol': 40, 'loss_expected': True, 'pfc': True}
    test_def = {'TEST_FLOW_AGGR_RATE_PERCENT': 40,
                'BG_FLOW_AGGR_RATE_PERCENT': 60,
                'data_flow_pkt_size': pkt_size,
                'DATA_FLOW_DURATION_SEC': 300,
                'data_flow_delay_sec': 0,
                'SNAPPI_POLL_DELAY_SEC': 60,
                'test_type': '/tmp/Single_400Gbps_Ingress_Single_100Gbps_Egress_pause_pfcwd_enable_',
                'line_card_choice': line_card_choice,
                'port_map': port_map,
                'enable_pfcwd': True,
                'enable_credit_wd': True,
                'stats_interval': 60,
                'background_traffic': True,
                'imix': False,
                'test_check': test_check,
                'verify_flows': False}

    logger.info('Starting the test for line_card_choice : {}'.format(line_card_choice))
    if line_card_choice not in linecard_configuration_set.keys():
        assert False, "Invalid line_card_choice value passed in parameter"

    if (len(linecard_configuration_set[line_card_choice]['hostname']) >= 2):
        dut_list = [dut for dut in duthosts.frontend_nodes
                    if dut.hostname in linecard_configuration_set[line_card_choice]['hostname']]
        duthost1, duthost2 = dut_list
    elif (len(linecard_configuration_set[line_card_choice]['hostname']) == 1):
        dut_list = [dut for dut in duthosts.frontend_nodes
                    if linecard_configuration_set[line_card_choice]['hostname'] == [dut.hostname]]
        duthost1 = duthost2 = dut_list[0]
    else:
        assert False, "Hostname can't be an empty list"

    snappi_port_list = get_multidut_snappi_ports(line_card_choice=line_card_choice,
                                                 line_card_info=linecard_configuration_set[line_card_choice])

    if len(snappi_port_list) < 2:
        assert False, "snappi_port_list: Need Minimum of 2 ports for the test"

    snappi_ports = new_get_multidut_tgen_peer_port_set(line_card_choice, snappi_port_list, config_set, port_map)

    if len(snappi_ports) < 2:
        assert False, "snappi_port: Need Minimum of 2 ports for the test"

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
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    if (duthosts.supervisor_nodes):
        for dut in duthosts.supervisor_nodes:
            clear_fabric_counters(dut)
    for dut in dut_list:
        clear_fabric_counters(dut)

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
                     test_traffic_pause=True,
                     test_def=test_def,
                     snappi_extra_params=snappi_extra_params)

        if (duthosts.supervisor_nodes):
            for dut in duthosts.supervisor_nodes:
                check_fabric_counters(dut)
        for dut in dut_list:
            check_fabric_counters(dut)

    finally:
        cleanup_config(dut_list, snappi_ports)


@pytest.mark.parametrize('linecard_configuration_set', [config_set])
@pytest.mark.parametrize('line_card_choice', line_card_choice)
def test_mixed_speed_pfcwd_disable(snappi_api,                  # noqa: F811
                                   conn_graph_facts,            # noqa: F811
                                   fanout_graph_facts,          # noqa: F811
                                   duthosts,
                                   prio_dscp_map,                # noqa: F811
                                   line_card_choice,
                                   linecard_configuration_set,
                                   get_multidut_snappi_ports):    # noqa: F811

    """
    Test to oversubscribe the 100Gbps egress link and have PFCWD disabled.
    Sending PAUSE frames to egress link for the lossless traffic.
    DUT should send PFCs for the lossless traffic and have zero loss for lossless traffic.
    Lossy traffic should be dropped.
    DUT allows equal amount of traffic (lossless and lossy priorities) to the egress.
    Egress traffic is around 100Gbps.

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
    port_map = [1, 100, 1, 400]

    # pkt_size of 1024B will be used unless imix flag is set.
    # With imix flag set, the traffic_generation.py uses IMIX profile.
    pkt_size = 1024

    # Percentage drop expected for lossless and lossy traffic.
    # speed_tol is speed tolerance between egress link speed and actual speed.
    # loss_expected to check losses on DUT and TGEN.
    test_check = {'lossless': 0, 'lossy': 75, 'speed_tol': 3, 'loss_expected': True, 'pfc': True}
    test_def = {'TEST_FLOW_AGGR_RATE_PERCENT': 40,
                'BG_FLOW_AGGR_RATE_PERCENT': 60,
                'data_flow_pkt_size': pkt_size,
                'DATA_FLOW_DURATION_SEC': 300,
                'data_flow_delay_sec': 0,
                'SNAPPI_POLL_DELAY_SEC': 60,
                'test_type': '/tmp/Single_400Gbps_Ingress_Single_100Gbps_Egress_pause_pfcwd_disable_',
                'line_card_choice': line_card_choice,
                'port_map': port_map,
                'enable_pfcwd': False,
                'enable_credit_wd': False,
                'stats_interval': 60,
                'background_traffic': True,
                'imix': False,
                'test_check': test_check,
                'verify_flows': False}

    logger.info('Starting the test for line_card_choice : {}'.format(line_card_choice))
    if line_card_choice not in linecard_configuration_set.keys():
        assert False, "Invalid line_card_choice value passed in parameter"

    if (len(linecard_configuration_set[line_card_choice]['hostname']) >= 2):
        dut_list = [dut for dut in duthosts.frontend_nodes
                    if dut.hostname in linecard_configuration_set[line_card_choice]['hostname']]
        duthost1, duthost2 = dut_list
    elif (len(linecard_configuration_set[line_card_choice]['hostname']) == 1):
        dut_list = [dut for dut in duthosts.frontend_nodes
                    if linecard_configuration_set[line_card_choice]['hostname'] == [dut.hostname]]
        duthost1 = duthost2 = dut_list[0]
    else:
        assert False, "Hostname can't be an empty list"

    snappi_port_list = get_multidut_snappi_ports(line_card_choice=line_card_choice,
                                                 line_card_info=linecard_configuration_set[line_card_choice])

    if len(snappi_port_list) < 2:
        assert False, "snappi_port_list: Need Minimum of 2 ports for the test"

    snappi_ports = new_get_multidut_tgen_peer_port_set(line_card_choice, snappi_port_list, config_set, port_map)

    if len(snappi_ports) < 2:
        assert False, "snappi_port: Need Minimum of 2 ports for the test"

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
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    if (duthosts.supervisor_nodes):
        for dut in duthosts.supervisor_nodes:
            clear_fabric_counters(dut)
    for dut in dut_list:
        clear_fabric_counters(dut)

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
                     test_traffic_pause=True,
                     test_def=test_def,
                     snappi_extra_params=snappi_extra_params)

        if (duthosts.supervisor_nodes):
            for dut in duthosts.supervisor_nodes:
                check_fabric_counters(dut)
        for dut in dut_list:
            check_fabric_counters(dut)

    finally:
        cleanup_config(dut_list, snappi_ports)


@pytest.mark.parametrize('linecard_configuration_set', [config_set])
@pytest.mark.parametrize('line_card_choice', line_card_choice)
def test_mixed_speed_no_congestion(snappi_api,                  # noqa: F811
                                   conn_graph_facts,            # noqa: F811
                                   fanout_graph_facts,          # noqa: F811
                                   duthosts,
                                   prio_dscp_map,                # noqa: F811
                                   line_card_choice,
                                   linecard_configuration_set,
                                   get_multidut_snappi_ports):    # noqa: F811

    """
    Test to have mixed speed ingress and egress without oversubscribing the egress.
    Since the total ingress traffic on 400Gbps is less than 100Gbps,
    there should be no congestion experienced by DUT.
    No packet drops experienced by the DUT.

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
    port_map = [1, 100, 1, 400]

    # pkt_size of 1024B will be used unless imix flag is set.
    # With imix flag set, the traffic_generation.py uses IMIX profile.
    pkt_size = 1024

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
                'line_card_choice': line_card_choice,
                'port_map': port_map,
                'enable_pfcwd': True,
                'enable_credit_wd': True,
                'stats_interval': 60,
                'background_traffic': True,
                'imix': False,
                'test_check': test_check,
                'verify_flows': False}

    logger.info('Starting the test for line_card_choice : {}'.format(line_card_choice))
    if line_card_choice not in linecard_configuration_set.keys():
        assert False, "Invalid line_card_choice value passed in parameter"

    if (len(linecard_configuration_set[line_card_choice]['hostname']) >= 2):
        dut_list = [dut for dut in duthosts.frontend_nodes
                    if dut.hostname in linecard_configuration_set[line_card_choice]['hostname']]
        duthost1, duthost2 = dut_list
    elif (len(linecard_configuration_set[line_card_choice]['hostname']) == 1):
        dut_list = [dut for dut in duthosts.frontend_nodes
                    if linecard_configuration_set[line_card_choice]['hostname'] == [dut.hostname]]
        duthost1 = duthost2 = dut_list[0]
    else:
        assert False, "Hostname can't be an empty list"

    snappi_port_list = get_multidut_snappi_ports(line_card_choice=line_card_choice,
                                                 line_card_info=linecard_configuration_set[line_card_choice])

    if len(snappi_port_list) < 2:
        assert False, "snappi_port_list: Need Minimum of 2 ports for the test"

    snappi_ports = new_get_multidut_tgen_peer_port_set(line_card_choice, snappi_port_list, config_set, port_map)

    if len(snappi_ports) < 2:
        assert False, "snappi_port: Need Minimum of 2 ports for the test"

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
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    if (duthosts.supervisor_nodes):
        for dut in duthosts.supervisor_nodes:
            clear_fabric_counters(dut)
    for dut in dut_list:
        clear_fabric_counters(dut)

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

        if (duthosts.supervisor_nodes):
            for dut in duthosts.supervisor_nodes:
                check_fabric_counters(dut)
        for dut in dut_list:
            check_fabric_counters(dut)

    finally:
        cleanup_config(dut_list, snappi_ports)
