import pytest
import logging
import random
from tests.common.helpers.assertions import pytest_require, pytest_assert                   # noqa: F401
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts_multidut, \
    fanout_graph_facts   # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
    snappi_api, snappi_multi_base_config, cleanup_config, get_snappi_ports_for_rdma, \
    get_snappi_ports, get_snappi_ports_multi_dut, clear_fabric_counters, check_fabric_counters, \
    get_snappi_ports_single_dut, tgen_port_info, tgen_testbed_subtype, snappi_port_selection      # noqa: F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map, lossless_prio_list, \
    lossy_prio_list, all_prio_list                                                                  # noqa: F401
from tests.common.snappi_tests.common_helpers import get_pfcwd_stats
from tests.snappi_tests.pfcwd.files.pfcwd_actions_helper import run_pfc_test
from tests.common.config_reload import config_reload
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.snappi_tests.cisco.helper import modify_voq_watchdog_cisco_8000              # noqa: F401
from tests.common.helpers.parallel import parallel_run

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology('multidut-tgen')]


# Testplan: docs/testplan/PFC_Snappi_Additional_Testcases.md
# This test-script covers testcase#10: PFCWD-enabled DROP mode test.
# This test-script also covers testcase#11: PFCWD-enabled FWD mode test.


def create_port_map(snappi_ports, tx_count, rx_count):
    """Build port_map [tx_count, speed_gbps, rx_count, speed_gbps] from snappi_ports."""
    port = snappi_ports[0]
    if 'snappi_speed_type' in port:
        speed_gbps = int(port['snappi_speed_type'].split('_')[1])
    else:
        speed_gbps = int(int(port['speed']) / 1000)
    return [tx_count, speed_gbps, rx_count, speed_gbps]


def log_pfcwd_stats(test_prio_list, snappi_ports, dut_list, when='start'):
    """Log PFC-WD stats for each priority and port; call before and after the test."""
    label = 'start' if when == 'start' else 'end'
    logger.info('PFC-WD stats at the {} of the test:'.format(label))
    for prio in test_prio_list:
        for port in snappi_ports:
            for dut in dut_list:
                if dut.hostname == port['peer_device']:
                    pfcwd_stats = get_pfcwd_stats(dut, port['peer_port'], prio)
                    if when == 'start':
                        logger.info('PFCWD stats for dut:{}, port:{},prio:{}'.
                                    format(dut.hostname, port['peer_port'], prio))
                        logger.info('PFCWD Stats::{}'.format(pfcwd_stats))
                    else:
                        logger.info('PFCWD Stats:for dut:{}, port:{},prio:{}, stats::{}'.
                                    format(dut.hostname, port['peer_port'], prio, pfcwd_stats))


@pytest.fixture(autouse=True, scope='module')
def number_of_tx_rx_ports(request):
    # over_subs tests: (1, 2); rest: (1, 1)
    if request.param:
        yield (1, 2)
    else:
        yield (1, 1)


def pfcwd_actions_cleanup(duthosts, tgen_port_info):  # noqa: F811
    _, _, snappi_ports = tgen_port_info
    cleanup_config(duthosts, snappi_ports)

    def do_config_reload(node, results):
        return (config_reload(sonic_host=node))
    parallel_run(do_config_reload, [], {}, list(set([snappi_ports[0]['duthost'], snappi_ports[1]['duthost']])))


@pytest.fixture(autouse=False)
def disable_voq_wd_cisco_8000(duthosts):
    yield
    for dut in duthosts:
        if dut.facts.get('asic_type') == "cisco-8000":
            modify_voq_watchdog_cisco_8000(dut, True)


# This is a single-tx-single-rx test.
@pytest.mark.parametrize("number_of_tx_rx_ports", [False], indirect=True)
def test_pfcwd_drop_90_10(snappi_api,                  # noqa: F811
                          conn_graph_facts,             # noqa: F811
                          fanout_graph_facts_multidut,  # noqa: F811
                          duthosts,
                          prio_dscp_map,                # noqa: F811
                          lossless_prio_list,           # noqa: F811
                          lossy_prio_list,              # noqa: F811
                          tbinfo,
                          tgen_port_info,               # noqa: F811
                          tgen_testbed_subtype):        # noqa: F811
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
        tgen_port_info (pytest fixture): (testbed_config, port_config_list, snappi_ports).
        tgen_testbed_subtype (pytest fixture): testbed subtype for line_card_choice.

    Returns:
        N/A
    """

    pkt_size = 1024
    testbed_config, port_config_list, snappi_ports = tgen_port_info
    port_map = create_port_map(snappi_ports, 1, 1)

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
                'test_type': 'logs/snappi_tests/pfcwd/One_Ingress_Egress_pfcwd_drop_90_10_dist'+str(port_map[1])+'Gbps',
                'line_card_choice': tgen_testbed_subtype,
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

    dut_list = list(set([snappi_ports[0]['duthost'], snappi_ports[-1]['duthost']]))

    for dut in duthosts:
        clear_fabric_counters(dut)

    log_pfcwd_stats(test_prio_list, snappi_ports, dut_list, when='start')

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

    log_pfcwd_stats(test_prio_list, snappi_ports, dut_list, when='end')

    for dut in duthosts:
        check_fabric_counters(dut)


# This is a single-tx-single-rx test.
@pytest.mark.parametrize("number_of_tx_rx_ports", [False], indirect=True)
def test_pfcwd_drop_uni(snappi_api,                  # noqa: F811
                        conn_graph_facts,             # noqa: F811
                        fanout_graph_facts_multidut,  # noqa: F811
                        duthosts,
                        prio_dscp_map,                # noqa: F811
                        lossless_prio_list,           # noqa: F811
                        lossy_prio_list,              # noqa: F811
                        tbinfo,
                        tgen_port_info,               # noqa: F811
                        tgen_testbed_subtype):        # noqa: F811
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
        tgen_port_info (pytest fixture): (testbed_config, port_config_list, snappi_ports).
        tgen_testbed_subtype (pytest fixture): testbed subtype for line_card_choice.

    Returns:
        N/A
    """

    pkt_size = 1024
    testbed_config, port_config_list, snappi_ports = tgen_port_info
    port_map = create_port_map(snappi_ports, 1, 1)

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
                'test_type': 'logs/snappi_tests/pfcwd/One_Ingress_Egress_pfcwd_drop_uni_dist'+str(port_map[1])+'Gbps',
                'line_card_choice': tgen_testbed_subtype,
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

    dut_list = list(set([snappi_ports[0]['duthost'], snappi_ports[-1]['duthost']]))

    for dut in duthosts:
        clear_fabric_counters(dut)

    log_pfcwd_stats(test_prio_list, snappi_ports, dut_list, when='start')

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

    log_pfcwd_stats(test_prio_list, snappi_ports, dut_list, when='end')

    for dut in duthosts:
        check_fabric_counters(dut)


# This is a single-tx-single-rx test.
@pytest.mark.parametrize("number_of_tx_rx_ports", [False], indirect=True)
def test_pfcwd_frwd_90_10(snappi_api,                  # noqa: F811
                          conn_graph_facts,             # noqa: F811
                          fanout_graph_facts_multidut,  # noqa: F811
                          duthosts,
                          prio_dscp_map,                # noqa: F811
                          lossless_prio_list,           # noqa: F811
                          lossy_prio_list,              # noqa: F811
                          tbinfo,
                          tgen_port_info,               # noqa: F811
                          tgen_testbed_subtype):        # noqa: F811

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
        tgen_port_info (pytest fixture): (testbed_config, port_config_list, snappi_ports).
        tgen_testbed_subtype (pytest fixture): testbed subtype for line_card_choice.
    Returns:
        N/A

    """

    # pkt_size of 1024B will be used unless imix flag is set.
    # With imix flag set, the traffic_generation.py uses IMIX profile.
    pkt_size = 1024

    testbed_config, port_config_list, snappi_ports = tgen_port_info
    port_map = create_port_map(snappi_ports, 1, 1)

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
                'test_type': 'logs/snappi_tests/pfcwd/One_Ingress_Egress_pfcwd_frwd_90_10_dist'+str(port_map[1])+'Gbps',
                'line_card_choice': tgen_testbed_subtype,
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
    dut_list = list(set([snappi_ports[0]['duthost'], snappi_ports[-1]['duthost']]))

    for dut in duthosts:
        clear_fabric_counters(dut)

    log_pfcwd_stats(test_prio_list, snappi_ports, dut_list, when='start')

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

    log_pfcwd_stats(test_prio_list, snappi_ports, dut_list, when='end')

    for dut in duthosts:
        check_fabric_counters(dut)


# This is an oversubscribe-testcase.
@pytest.mark.parametrize("number_of_tx_rx_ports", [True], indirect=True)
def test_pfcwd_drop_over_subs_40_09(snappi_api,                  # noqa: F811
                                    conn_graph_facts,             # noqa: F811
                                    fanout_graph_facts_multidut,  # noqa: F811
                                    duthosts,
                                    prio_dscp_map,                # noqa: F811
                                    lossless_prio_list,           # noqa: F811
                                    lossy_prio_list,              # noqa: F811
                                    tbinfo,
                                    tgen_port_info,               # noqa: F811
                                    tgen_testbed_subtype):        # noqa: F811

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
        tgen_port_info (pytest fixture): (testbed_config, port_config_list, snappi_ports).
        tgen_testbed_subtype (pytest fixture): testbed subtype for line_card_choice.

    Returns:
        N/A
    """

    # pkt_size of 1024B will be used unless imix flag is set.
    # With imix flag set, the traffic_generation.py uses IMIX profile.
    pkt_size = 1024

    testbed_config, port_config_list, snappi_ports = tgen_port_info
    port_map = create_port_map(snappi_ports, 1, 2)

    # Percentage drop expected for lossless and lossy traffic.
    # speed_tol is speed tolerance between egress link speed and actual speed.
    # loss_expected to check losses on DUT and TGEN.
    test_check = {'lossless': 100, 'lossy': 0, 'speed_tol': 83, 'loss_expected': True, 'pfc': True}

    test_def = {
        'TEST_FLOW_AGGR_RATE_PERCENT': 40,
        'BG_FLOW_AGGR_RATE_PERCENT': 9,
        'data_flow_pkt_size': pkt_size,
        'DATA_FLOW_DURATION_SEC': 300,
        'data_flow_delay_sec': 1,
        'SNAPPI_POLL_DELAY_SEC': 60,
        'test_type': 'logs/snappi_tests/pfcwd/Two_Ingress_Single_Egress_pfcwd_drop_40_9_dist'+str(port_map[1])+'Gbps',
        'line_card_choice': tgen_testbed_subtype,
        'port_map': port_map,
        'enable_pfcwd_drop': True,
        'enable_pfcwd_fwd': False,
        'enable_credit_wd': True,
        'stats_interval': 60,
        'background_traffic': True,
        'verify_flows': False,
        'imix': False,
        'test_check': test_check
    }

    test_prio_list = lossless_prio_list
    pause_prio_list = test_prio_list
    bg_prio_list = random.sample(lossy_prio_list, 3)
    logger.info('Selected lossless :{} and lossy priorities:{} for the test'.format(test_prio_list, bg_prio_list))

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.duthost1 = snappi_ports[0]['duthost']
    snappi_extra_params.multi_dut_params.duthost2 = snappi_ports[-1]['duthost']

    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports
    dut_list = list(set([snappi_ports[0]['duthost'], snappi_ports[-1]['duthost']]))

    for dut in duthosts:
        clear_fabric_counters(dut)

    log_pfcwd_stats(test_prio_list, snappi_ports, dut_list, when='start')

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

    log_pfcwd_stats(test_prio_list, snappi_ports, dut_list, when='end')

    for dut in duthosts:
        check_fabric_counters(dut)


# This is an oversubscribe-testcase.
@pytest.mark.parametrize("number_of_tx_rx_ports", [True], indirect=True)
def test_pfcwd_frwd_over_subs_40_09(snappi_api,                  # noqa: F811
                                    conn_graph_facts,             # noqa: F811
                                    fanout_graph_facts_multidut,  # noqa: F811
                                    duthosts,
                                    prio_dscp_map,                # noqa: F811
                                    lossless_prio_list,           # noqa: F811
                                    lossy_prio_list,              # noqa: F811
                                    tbinfo,
                                    tgen_port_info,               # noqa: F811
                                    tgen_testbed_subtype):        # noqa: F811

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
        tgen_port_info (pytest fixture): (testbed_config, port_config_list, snappi_ports).
        tgen_testbed_subtype (pytest fixture): testbed subtype for line_card_choice.

    Returns:
        N/A
    """

    # pkt_size of 1024B will be used unless imix flag is set.
    # With imix flag set, the traffic_generation.py uses IMIX profile.
    pkt_size = 1024

    testbed_config, port_config_list, snappi_ports = tgen_port_info
    port_map = create_port_map(snappi_ports, 1, 2)

    # Percentage drop expected for lossless and lossy traffic.
    # speed_tol is speed tolerance between egress link speed and actual speed.
    # loss_expected to check losses on DUT and TGEN.
    test_check = {'lossless': 0, 'lossy': 0, 'speed_tol': 3, 'loss_expected': False, 'pfc': True}

    test_def = {
        'TEST_FLOW_AGGR_RATE_PERCENT': 40,
        'BG_FLOW_AGGR_RATE_PERCENT': 9,
        'data_flow_pkt_size': pkt_size,
        'DATA_FLOW_DURATION_SEC': 300,
        'data_flow_delay_sec': 1,
        'SNAPPI_POLL_DELAY_SEC': 60,
        'test_type': 'logs/snappi_tests/pfcwd/Two_Ingress_Single_Egress_pfcwd_frwd_40_9_dist'+str(port_map[1])+'Gbps',
        'line_card_choice': tgen_testbed_subtype,
        'port_map': port_map,
        'enable_pfcwd_drop': False,
        'enable_pfcwd_fwd': True,
        'enable_credit_wd': True,
        'stats_interval': 60,
        'background_traffic': True,
        'verify_flows': False,
        'imix': False,
        'test_check': test_check
    }

    # Selecting only one lossless priority for the test.
    test_prio_list = random.sample(lossless_prio_list, 1)
    pause_prio_list = test_prio_list
    bg_prio_list = random.sample(lossy_prio_list, 3)
    logger.info('Selected lossless priority:{} for the test'.format(test_prio_list))

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.duthost1 = snappi_ports[0]['duthost']
    snappi_extra_params.multi_dut_params.duthost2 = snappi_ports[-1]['duthost']

    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports
    dut_list = list(set([snappi_ports[0]['duthost'], snappi_ports[-1]['duthost']]))

    for dut in duthosts:
        clear_fabric_counters(dut)

    log_pfcwd_stats(test_prio_list, snappi_ports, dut_list, when='start')

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

    log_pfcwd_stats(test_prio_list, snappi_ports, dut_list, when='end')
    for dut in duthosts:
        check_fabric_counters(dut)


# This is a single-tx-single-rx test.
@pytest.mark.parametrize("number_of_tx_rx_ports", [False], indirect=True)
def test_pfcwd_disable_pause_cngtn(snappi_api,                  # noqa: F811
                                   conn_graph_facts,             # noqa: F811
                                   fanout_graph_facts_multidut,  # noqa: F811
                                   duthosts,
                                   prio_dscp_map,                # noqa: F811
                                   lossless_prio_list,           # noqa: F811
                                   lossy_prio_list,              # noqa: F811
                                   tbinfo,
                                   tgen_port_info,               # noqa: F811
                                   tgen_testbed_subtype,         # noqa: F811
                                   disable_voq_wd_cisco_8000):   # noqa: F811

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
        tgen_port_info (pytest fixture): (testbed_config, port_config_list, snappi_ports).
        tgen_testbed_subtype (pytest fixture): testbed subtype for line_card_choice.

    Returns:
        N/A
    """

    # pkt_size of 1024B will be used unless imix flag is set.
    # With imix flag set, the traffic_generation.py uses IMIX profile.
    pkt_size = 1024

    testbed_config, port_config_list, snappi_ports = tgen_port_info
    port_map = create_port_map(snappi_ports, 1, 1)

    # Percentage drop expected for lossless and lossy traffic.
    # speed_tol is speed tolerance between egress link speed and actual speed.
    # loss_expected to check losses on DUT and TGEN.
    test_check = {'lossless': 0, 'lossy': 0, 'speed_tol': 41, 'loss_expected': False, 'pfc': True}

    test_def = {
        'TEST_FLOW_AGGR_RATE_PERCENT': 40,
        'BG_FLOW_AGGR_RATE_PERCENT': 60,
        'data_flow_pkt_size': pkt_size,
        'DATA_FLOW_DURATION_SEC': 300,
        'data_flow_delay_sec': 1,
        'SNAPPI_POLL_DELAY_SEC': 60,
        'test_type': 'logs/snappi_tests/pfcwd/Single_Ingress_Single_Egress_pause_cngstn_'+str(port_map[1])+'Gbps',
        'line_card_choice': tgen_testbed_subtype,
        'port_map': port_map,
        'enable_pfcwd_drop': False,
        'enable_pfcwd_fwd': False,
        'enable_credit_wd': False,
        'stats_interval': 60,
        'background_traffic': True,
        'verify_flows': False,
        'imix': False,
        'test_check': test_check
    }

    # Selecting only one lossless priority for the test.
    test_prio_list = random.sample(lossless_prio_list, 1)
    pause_prio_list = test_prio_list
    bg_prio_list = random.sample(lossy_prio_list, 3)
    logger.info('Selected lossless priority:{} for the test'.format(test_prio_list))

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.duthost1 = snappi_ports[0]['duthost']
    snappi_extra_params.multi_dut_params.duthost2 = snappi_ports[-1]['duthost']

    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    for dut in duthosts:
        clear_fabric_counters(dut)
        if dut.facts.get('asic_type') == "cisco-8000":
            modify_voq_watchdog_cisco_8000(dut, False)

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
