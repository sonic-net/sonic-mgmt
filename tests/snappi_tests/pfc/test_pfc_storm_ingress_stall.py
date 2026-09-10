"""
PFC storm ingress behavior: quanta sweep and PPS sweep.

Topology: 1 TGEN TX -> DUT -> 1 TGEN RX (see number_of_tx_rx_ports fixture).

Quanta sweep includes 0x0 (XON / no hold), half of 0x1800, 0x1800, and 0xFFFF at fixed blocking PPS.
In-flight TGEN TX/RX throughput (``tx_rate_mbps`` / ``rx_rate_mbps`` from ``run_traffic``) are checked
against pause-quanta stall during the pause/data overlap window; post-traffic ingress PFC TX /
egress PFC RX counters and ``show pfcwd stats`` on the DUT egress port are also verified.

The helper enables PFC WD and packet aging on path DUTs (see pfc_storm_ingress_stall_helper); the
disable_pfcwd autouse fixture may still run first, then the helper restores a production-like setting
before traffic.
"""
import logging
import random

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.conn_graph_facts import (  # noqa: F401
    conn_graph_facts,
    fanout_graph_facts,
    fanout_graph_facts_multidut,
)
from tests.common.snappi_tests.snappi_fixtures import (  # noqa: F401
    snappi_api_serv_ip,
    snappi_api_serv_port,
    get_snappi_ports_single_dut,
    snappi_testbed_config,
    get_snappi_ports_multi_dut,
    is_snappi_multidut,
    snappi_port_selection,
    tgen_port_info,
    snappi_api,
    snappi_dut_base_config,
    get_snappi_ports,
    get_snappi_ports_for_rdma,
    cleanup_config,
)
from tests.common.snappi_tests.qos_fixtures import (  # noqa: F401
    prio_dscp_map,
    lossless_prio_list,
    disable_pfcwd,
)
from tests.snappi_tests.files.helper import reboot_duts  # noqa: F401
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.common.snappi_tests.common_helpers import clear_counters
from tests.snappi_tests.cisco.helper import disable_voq_watchdog  # noqa: F401
from tests.snappi_tests.pfc.files.pfc_storm_ingress_stall_helper import (
    PAUSE_NAME_SINGLE,
    baseline_blocking_pps,
    quanta_sweep_pause_pps,
    run_stall_case_with_pause_params,
    verify_pause_stream_dropped,
    verify_quanta_sweep_constant_pps_case,
    verify_pps_sweep_sub_blocking_case,
    verify_stall_on_lossless,
    _max_pause_pps_for_link,
)

logger = logging.getLogger(__name__)
pytestmark = [pytest.mark.topology("multidut-tgen", "tgen")]


@pytest.fixture(autouse=True, scope="module")
def number_of_tx_rx_ports():
    yield (1, 1)


@pytest.mark.parametrize("pause_quanta", [0x0, 0x1800 // 2, 0x1800, 0xFFFF])
def test_pfc_storm_quanta_sweep_constant_pps(snappi_api,                    # noqa: F811
                                             conn_graph_facts,              # noqa: F811
                                             fanout_graph_facts_multidut,   # noqa: F811
                                             duthosts,
                                             prio_dscp_map,                 # noqa: F811
                                             lossless_prio_list,            # noqa: F811
                                             get_snappi_ports,              # noqa: F811
                                             tbinfo,                        # noqa: F811
                                             disable_pfcwd,                 # noqa: F811
                                             tgen_port_info,                # noqa: F811
                                             pause_quanta,):
    """
    At fixed PPS (blocking budget from link speed), vary PFC pause quanta for paused classes.

    Covers 0x0, mid quanta (0x1800/2, 0x1800), and 0xffff (stall + PFCWD storm); verifies in-flight
    TGEN TX/RX throughput (``tx_rate_mbps`` / ``rx_rate_mbps`` during traffic), post-traffic
    ingress PFC, and ``show pfcwd stat``.
    Default watchdog configuration on the DUT.
    """
    testbed_config, port_config_list, snappi_ports = tgen_port_info
    logger.info('Running test for pause_quanta:{}'.format(pause_quanta))
    pause_prio_list = list(lossless_prio_list)
    test_prio_list = list(lossless_prio_list)
    all_prio = list(prio_dscp_map.keys())
    bg_candidates = [p for p in all_prio if p not in pause_prio_list]
    pytest_assert(len(bg_candidates) >= 1, "Need at least one lossy priority for background")
    bg_prio_list = random.sample(bg_candidates, min(2, len(bg_candidates)))

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports
    snappi_extra_params.poll_device_runtime = False

    speed_gbps = int(float(testbed_config.layer1[0].speed.split("_")[1]))
    pps = quanta_sweep_pause_pps(speed_gbps, pause_quanta)
    data_sec = 18
    pause_sec = 18
    data_delay_sec = 1
    pause_delay_sec = 1

    logger.info('Clearing all the DUT counters...')
    rx_port = snappi_ports[0]
    tx_port = snappi_ports[1]
    for path_port in (tx_port, rx_port):
        clear_counters(path_port["duthost"], port=path_port["peer_port"])

    try:
        (
            flow_stats,
            in_flight_metrics,
            speed_gbps,
            _,
            rx_port,
            tx_port,
            pfcwd_before,
            pfcwd_after,
            pfc_before,
            pfc_after,
        ) = run_stall_case_with_pause_params(
            api=snappi_api,
            testbed_config=testbed_config,
            port_config_list=port_config_list,
            snappi_ports=snappi_ports,
            prio_dscp_map=prio_dscp_map,
            pause_prio_list=pause_prio_list,
            test_prio_list=test_prio_list,
            bg_prio_list=bg_prio_list,
            pause_pps=pps,
            pause_quanta=None if pause_quanta == 0xFFFF else pause_quanta,
            data_flow_dur_sec=data_sec,
            pause_flow_dur_sec=pause_sec,
            pause_delay_sec=pause_delay_sec,
            data_flow_delay_sec=data_delay_sec,
            snappi_extra_params=snappi_extra_params,
        )
        verify_pause_stream_dropped(flow_stats, PAUSE_NAME_SINGLE)

        verify_quanta_sweep_constant_pps_case(
            pause_quanta=pause_quanta,
            flow_stats=flow_stats,
            in_flight_metrics=in_flight_metrics,
            speed_gbps=speed_gbps,
            test_prio_list=test_prio_list,
            pause_prio_list=pause_prio_list,
            ingress_duthost=tx_port["duthost"],
            ingress_peer_port=tx_port["peer_port"],
            egress_peer_port=rx_port["peer_port"],
            data_flow_dur_sec=data_sec,
            pause_flow_dur_sec=pause_sec,
            data_flow_delay_sec=data_delay_sec,
            pause_delay_sec=pause_delay_sec,
            pfcwd_counts_before=pfcwd_before,
            pfcwd_counts_after=pfcwd_after,
            pfc_counts_before=pfc_before,
            pfc_counts_after=pfc_after,
        )
    finally:
        cleanup_config(duthosts, snappi_ports)


@pytest.mark.parametrize("pps_case", ["low", "mid", "high"])
def test_pfc_storm_pps_sweep_constant_quanta(snappi_api,                    # noqa: F811
                                             conn_graph_facts,              # noqa: F811
                                             fanout_graph_facts_multidut,   # noqa: F811
                                             duthosts,
                                             prio_dscp_map,                 # noqa: F811
                                             lossless_prio_list,            # noqa: F811
                                             get_snappi_ports,              # noqa: F811
                                             tbinfo,                        # noqa: F811
                                             disable_pfcwd,                 # noqa: F811
                                             tgen_port_info,                # noqa: F811
                                             pps_case,):
    """
    Vary PFC PPS with default 0xffff-equivalent pause (omit flow_quanta).

    Low/mid PPS throttle IXIA TX proportionally (no DUT or IXIA drops); high PPS stalls
    lossless test traffic. Sub-blocking cases also verify egress/ingress PFC relay and
    that PFCWD does not declare a storm.
    Default watchdog configuration on the DUT.
    """
    testbed_config, port_config_list, snappi_ports = tgen_port_info
    pause_prio_list = list(lossless_prio_list)
    test_prio_list = list(lossless_prio_list)
    all_prio = list(prio_dscp_map.keys())
    bg_candidates = [p for p in all_prio if p not in pause_prio_list]
    pytest_assert(len(bg_candidates) >= 1, "Need at least one lossy priority for background")
    bg_prio_list = random.sample(bg_candidates, min(2, len(bg_candidates)))

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports
    snappi_extra_params.poll_device_runtime = False

    speed_gbps = int(float(testbed_config.layer1[0].speed.split("_")[1]))
    base = baseline_blocking_pps(speed_gbps)
    cap = _max_pause_pps_for_link(speed_gbps)
    if pps_case == "low":
        pause_pps = max(1, base // 8)
    elif pps_case == "mid":
        pause_pps = max(1, base // 2)
    else:
        pause_pps = min(cap, max(base, int(base * 1.5)))

    data_sec = 18
    pause_sec = 18

    logger.info('Clearing all the DUT counters...')
    rx_port = snappi_ports[0]
    tx_port = snappi_ports[1]
    for path_port in (tx_port, rx_port):
        clear_counters(path_port["duthost"], port=path_port["peer_port"])

    try:
        (
            flow_stats,
            in_flight_metrics,
            speed_gbps,
            _,
            rx_port,
            tx_port,
            pfcwd_before,
            pfcwd_after,
            pfc_before,
            pfc_after,
        ) = run_stall_case_with_pause_params(
            api=snappi_api,
            testbed_config=testbed_config,
            port_config_list=port_config_list,
            snappi_ports=snappi_ports,
            prio_dscp_map=prio_dscp_map,
            pause_prio_list=pause_prio_list,
            test_prio_list=test_prio_list,
            bg_prio_list=bg_prio_list,
            pause_pps=pause_pps,
            pause_quanta=None,
            data_flow_dur_sec=data_sec,
            pause_flow_dur_sec=pause_sec,
            pause_delay_sec=1,
            data_flow_delay_sec=1,
            snappi_extra_params=snappi_extra_params,
        )
        verify_pause_stream_dropped(flow_stats, PAUSE_NAME_SINGLE)
        if pps_case == "high":
            verify_stall_on_lossless(flow_stats, test_prio_list)
        else:
            verify_pps_sweep_sub_blocking_case(
                pps_case=pps_case,
                pause_pps=pause_pps,
                baseline_pps=base,
                flow_stats=flow_stats,
                in_flight_metrics=in_flight_metrics,
                data_flow_dur_sec=data_sec,
                speed_gbps=speed_gbps,
                test_prio_list=test_prio_list,
                pause_prio_list=pause_prio_list,
                ingress_duthost=tx_port["duthost"],
                ingress_peer_port=tx_port["peer_port"],
                egress_duthost=rx_port["duthost"],
                egress_peer_port=rx_port["peer_port"],
                pfc_counts_before=pfc_before,
                pfc_counts_after=pfc_after,
                pfcwd_counts_before=pfcwd_before,
                pfcwd_counts_after=pfcwd_after,
            )
    finally:
        cleanup_config(duthosts, snappi_ports)
