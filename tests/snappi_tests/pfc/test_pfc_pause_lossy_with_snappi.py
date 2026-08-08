import pytest
import time
import copy
from tests.common.helpers.assertions import pytest_require, pytest_assert                   # noqa: F401
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts, \
    fanout_graph_facts_multidut     # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
    get_snappi_ports_single_dut, snappi_testbed_config, \
    get_snappi_ports_multi_dut, is_snappi_multidut, snappi_port_selection, tgen_port_info, \
    snappi_api, snappi_dut_base_config, get_snappi_ports, get_snappi_ports_for_rdma, cleanup_config, \
    ixia_port_readiness_precheck, is_ixia_readiness_failure  # noqa: F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map, all_prio_list, lossless_prio_list,\
    lossy_prio_list                         # noqa: F401
from tests.common.snappi_tests.traffic_flow_config import TrafficFlowConfig
from tests.snappi_tests.pfc.files.helper import run_pfc_test
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.snappi_tests.files.helper import reboot_duts, setup_ports_and_dut, multidut_port_info  # noqa: F401
from tests.snappi_tests.cisco.helper import disable_voq_watchdog                  # noqa: F401

pytestmark = [pytest.mark.topology('multidut-tgen', 'tgen')]

_RUN_RETRY_ATTEMPTS = 3
_RUN_RETRY_DELAY_SEC = 30


def _reset_snappi_extra_params_for_retry(snappi_extra_params):
    """Reset runtime-mutated Snappi fields while preserving host/topology references."""
    if snappi_extra_params is None:
        return
    snappi_extra_params.base_flow_config = None
    snappi_extra_params.base_flow_config_list = []
    snappi_extra_params.test_tx_frames = 0
    snappi_extra_params.packet_capture_file = None
    snappi_extra_params.packet_capture_ports = None
    snappi_extra_params.traffic_flow_config = TrafficFlowConfig()


def _run_pfc_test_with_dod_retry(**kwargs):
    """
    Call run_pfc_test with defensive retries around protocol-start/DOD failures.

    run_pfc_test mutates testbed_config by appending flows. Each retry must use
    a fresh copy of the original config/params to avoid duplicate flow names.
    """
    base_config = kwargs.get('testbed_config')
    base_params = kwargs.get('snappi_extra_params')
    last_error = None

    for attempt in range(1, _RUN_RETRY_ATTEMPTS + 1):
        try_kwargs = dict(kwargs)
        if base_config is not None:
            try_kwargs['testbed_config'] = copy.deepcopy(base_config)
        if base_params is not None:
            _reset_snappi_extra_params_for_retry(base_params)
            try_kwargs['snappi_extra_params'] = base_params

        try:
            run_pfc_test(**try_kwargs)
            return
        except Exception as e:
            is_retryable = is_ixia_readiness_failure(e)
            if not is_retryable:
                raise

            last_error = e
            if attempt < _RUN_RETRY_ATTEMPTS:
                time.sleep(_RUN_RETRY_DELAY_SEC)

    pytest.skip(
        "Ixia readiness failure (DOD/CPU/protocol start) persisted after {} attempts ({}s wait): {}".format(
            _RUN_RETRY_ATTEMPTS, _RUN_RETRY_DELAY_SEC, last_error
        )
    )


@pytest.fixture(autouse=True, scope='module')
def number_of_tx_rx_ports():
    yield (1, 1)


def test_pfc_pause_single_lossy_prio(snappi_api,                # noqa: F811
                                     conn_graph_facts,          # noqa: F811
                                     fanout_graph_facts_multidut,        # noqa: F811
                                     duthosts,
                                     enum_one_dut_lossy_prio,
                                     prio_dscp_map,             # noqa: F811
                                     lossy_prio_list,           # noqa: F811
                                     all_prio_list,             # noqa: F811
                                     lossless_prio_list,        # noqa: F811
                                     get_snappi_ports,          # noqa: F811
                                     tbinfo,                    # noqa: F811
                                     tgen_port_info        # noqa: F811
                                     ):
    """
    Test if PFC will impact a single lossy priority in multidut setup

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        enum_dut_lossy_prio (str): name of lossy priority to test, e.g., 's6100-1|2'
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        lossy_prio_list (pytest fixture): list of all the lossy priorities
        all_prio_list (pytest fixture): list of all the priorities
        lossy_prio_list (pytest fixture): list of all the lossy priorities


    Returns:
        N/A
    """
    testbed_config, port_config_list, snappi_ports = tgen_port_info

    _, lossy_prio = enum_one_dut_lossy_prio.split('|')
    lossy_prio = int(lossy_prio)
    pause_prio_list = [lossy_prio]
    test_prio_list = [lossy_prio]
    bg_prio_list = [p for p in all_prio_list]
    bg_prio_list.remove(lossy_prio)
    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    flow_factor = 1

    if snappi_ports[0]['asic_type'] == 'cisco-8000' and int(snappi_ports[0]['speed']) > 200000:
        flow_factor = int(snappi_ports[0]['speed']) / 200000
    try:
        _run_pfc_test_with_dod_retry(
                     api=snappi_api,
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
                     test_flow_is_lossless=False,
                     snappi_extra_params=snappi_extra_params,
                     flow_factor=flow_factor)
    finally:
        cleanup_config(duthosts, snappi_ports)


def test_pfc_pause_multi_lossy_prio(snappi_api,             # noqa: F811
                                    conn_graph_facts,       # noqa: F811
                                    fanout_graph_facts_multidut,     # noqa: F811
                                    duthosts,
                                    prio_dscp_map,                   # noqa: F811
                                    lossy_prio_list,              # noqa: F811
                                    lossless_prio_list,              # noqa: F811
                                    get_snappi_ports,         # noqa: F811
                                    tbinfo,                # noqa: F811
                                    tgen_port_info):                 # noqa: F811
    """
    Test if PFC will impact multiple lossy priorities in multidut setup

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        lossy_prio_list (pytest fixture): list of all the lossy priorities
        tbinfo (pytest fixture): fixture provides information about testbed
        get_snappi_ports (pytest fixture): gets snappi ports and connected DUT port info and returns as a list
    Returns:
        N/A
    """
    testbed_config, port_config_list, snappi_ports = tgen_port_info

    pause_prio_list = lossy_prio_list
    test_prio_list = lossy_prio_list
    bg_prio_list = lossless_prio_list

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    flow_factor = 1

    if snappi_ports[0]['asic_type'] == 'cisco-8000' and int(snappi_ports[0]['speed']) > 200000:
        flow_factor = int(snappi_ports[0]['speed']) / 200000
    try:
        _run_pfc_test_with_dod_retry(
                     api=snappi_api,
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
                     test_flow_is_lossless=False,
                     snappi_extra_params=snappi_extra_params,
                     flow_factor=flow_factor)
    finally:
        cleanup_config(duthosts, snappi_ports)


@pytest.mark.disable_loganalyzer
def test_pfc_pause_single_lossy_prio_reboot(snappi_api,             # noqa: F811
                                            conn_graph_facts,       # noqa: F811
                                            fanout_graph_facts_multidut,     # noqa: F811
                                            duthosts,
                                            localhost,
                                            enum_one_dut_lossy_prio_with_completeness_level,
                                            prio_dscp_map,          # noqa: F811
                                            lossy_prio_list,        # noqa: F811
                                            all_prio_list,          # noqa: F811
                                            lossless_prio_list,     # noqa: F811
                                            get_snappi_ports,       # noqa: F811
                                            tbinfo,                 # noqa: F811
                                            tgen_port_info,    # noqa: F811
                                            reboot_duts):           # noqa: F811
    """
    Test if PFC will impact a single lossy priority after various kinds of reboots in multidut setup

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        localhost (pytest fixture): localhost handle
        enum_dut_lossy_prio_with_completeness_level (str): name of lossy priority to test, e.g., 's6100-1|2'
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        lossy_prio_list (pytest fixture): list of all the lossy priorities
        all_prio_list (pytest fixture): list of all the priorities
        reboot_type (str): reboot type to be issued on the DUT
        tbinfo (pytest fixture): fixture provides information about testbed
        get_snappi_ports (pytest fixture): gets snappi ports and connected DUT port info and returns as a list
    Returns:
        N/A
    """
    testbed_config, port_config_list, snappi_ports = tgen_port_info

    _, lossy_prio = enum_one_dut_lossy_prio_with_completeness_level.split('|')
    lossy_prio = int(lossy_prio)
    pause_prio_list = [lossy_prio]
    test_prio_list = [lossy_prio]
    bg_prio_list = [p for p in all_prio_list]
    bg_prio_list.remove(lossy_prio)

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    flow_factor = 1

    if snappi_ports[0]['asic_type'] == 'cisco-8000' and int(snappi_ports[0]['speed']) > 200000:
        flow_factor = int(snappi_ports[0]['speed']) / 200000

    try:
        _run_pfc_test_with_dod_retry(
                     api=snappi_api,
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
                     test_flow_is_lossless=False,
                     snappi_extra_params=snappi_extra_params,
                     flow_factor=flow_factor)
    finally:
        cleanup_config(duthosts, snappi_ports)


@pytest.mark.disable_loganalyzer
def test_pfc_pause_multi_lossy_prio_reboot(snappi_api,          # noqa: F811
                                           conn_graph_facts,    # noqa: F811
                                           fanout_graph_facts_multidut,  # noqa: F811
                                           duthosts,
                                           localhost,
                                           prio_dscp_map,        # noqa: F811
                                           lossy_prio_list,      # noqa: F811
                                           lossless_prio_list,   # noqa: F811
                                           get_snappi_ports,     # noqa: F811
                                           tbinfo,               # noqa: F811
                                           tgen_port_info,  # noqa: F811
                                           reboot_duts):         # noqa: F811
    """
    Test if PFC will impact multiple lossy priorities after various kinds of reboots

    Args:
        snappi_api (pytest fixture): SNAPPI session
        snappi_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        localhost (pytest fixture): localhost handle
        duthosts (pytest fixture): list of DUTs
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        lossy_prio_list (pytest fixture): list of all the lossy priorities
        reboot_type (str): reboot type to be issued on the DUT
        tbinfo (pytest fixture): fixture provides information about testbed
        get_snappi_ports (pytest fixture): gets snappi ports and connected DUT port info and returns as a list
    Returns:
        N/A
    """
    testbed_config, port_config_list, snappi_ports = tgen_port_info

    pause_prio_list = lossy_prio_list
    test_prio_list = lossy_prio_list
    bg_prio_list = lossless_prio_list

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    flow_factor = 1

    if snappi_ports[0]['asic_type'] == 'cisco-8000' and int(snappi_ports[0]['speed']) > 200000:
        flow_factor = int(snappi_ports[0]['speed']) / 200000
    try:
        _run_pfc_test_with_dod_retry(
                     api=snappi_api,
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
                     test_flow_is_lossless=False,
                     snappi_extra_params=snappi_extra_params,
                     flow_factor=flow_factor)
    finally:
        cleanup_config(duthosts, snappi_ports)
