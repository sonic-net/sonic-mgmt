import logging
import queue
import random
import threading
import time

import ptf.testutils as testutils
import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.ha.conftest import apply_dash_pl_pipeline_config
from constants import (
    LOCAL_PTF_INTF,
    REMOTE_PTF_RECV_INTF,
    VXLAN_UDP_BASE_SRC_PORT,
    VXLAN_UDP_SRC_PORT_MASK,
)
from packets import outbound_pl_packets
from ha_dash_flow_utils import compare_flow_tables
from ha_utils import verify_ha_state, set_dash_ha_scope, parallel_config_reload_dpuhosts

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t1-smartswitch-ha'),
    pytest.mark.skip_check_dut_health
]

MULTI_FLOW_MAX_PACKET_TARGET = 2000
MULTI_FLOW_INNER_SPORT_BASE = 49152
PLANNED_SWO_OUTER_ENCAP = "vxlan"
MULTI_FLOW_SEND_WINDOW_SEC = 45


@pytest.fixture(autouse=True, scope="module")
def common_setup_teardown(
    localhost,
    duthosts,
    ptfhost,
    skip_config,
    dpuhosts,
    setup_ha_config,
    setup_dash_ha_from_json,
    ha_owner,
    setup_gnmi_server,
    set_vxlan_udp_sport_range,
    setup_npu_dpu  # noqa: F811
):
    if skip_config:
        return

    apply_dash_pl_pipeline_config(localhost, duthosts, dpuhosts, ptfhost)

    yield
    parallel_config_reload_dpuhosts(dpuhosts)


def _planned_swo_phase(
    ptfadapter,
    localhost,
    ptfhost,
    swo_duthost,
    swo_scope_key,
    peer_duthost,
    peer_scope_key,
    expected_swo_state,
    expected_peer_state,
    ha_owner,
    send_ptf_intf,
    label,
    *,
    multi_flow=False,
    multi_flow_min_expected_flows=1,
    vm_to_dpu_pkt=None,
    exp_dpu_to_pe_pkt=None,
    rcv_outbound_pl_ports=None,
    dash_pl_config=None,
    dpuhosts=None,
):
    """Run one planned-switchover phase: send traffic, trigger SWO, verify HA state.

    With multi_flow False: same packet each iteration, verify egress on the PTF.

    With multi_flow True: send up to MULTI_FLOW_MAX_PACKET_TARGET distinct flows (varying inner_sport via
    outbound_pl_packets with PLANNED_SWO_OUTER_ENCAP), no inter-packet delay, for at most
    MULTI_FLOW_SEND_WINDOW_SEC seconds from the start of the send loop; then compare_flow_tables with
    max_flows = send_count * 2 + 10 and min_expected_flows = multi_flow_min_expected_flows (sonic-dpu-flow-dump
    path rejects empty dumps matching by accident).

    Args:
        swo_duthost: DUT on which we request standby (the one being switched over).
        swo_scope_key: HA scope key for the SWO DUT.
        peer_duthost: The other DUT in the HA pair.
        peer_scope_key: HA scope key for the peer DUT.
        expected_swo_state: Expected HA state on swo_duthost after SWO (e.g. "standby").
        expected_peer_state: Expected HA state on peer_duthost after SWO (e.g. "active").
        ha_owner: Owner string from ha_owner fixture ("dpu" or "switch").
        label: Human-readable label for logging (e.g. "primary" / "secondary").
        multi_flow_min_expected_flows: When multi_flow, passed to compare_flow_tables(min_expected_flows=...)
            for the sonic-dpu-flow-dump path (default 1).
    """
    rate_pps = 10
    initial_send_count = 10
    config = None
    fixed_vxlan_udp_sport = None
    delay = 0.0

    if multi_flow:
        pytest_assert(
            dash_pl_config is not None and dpuhosts is not None,
            "multi_flow mode requires dash_pl_config and dpuhosts",
        )
        config = dash_pl_config[0]
        fixed_vxlan_udp_sport = random.randint(
            VXLAN_UDP_BASE_SRC_PORT,
            VXLAN_UDP_BASE_SRC_PORT + 2**VXLAN_UDP_SRC_PORT_MASK - 1,
        )
        t_max = time.time() + MULTI_FLOW_SEND_WINDOW_SEC
    else:
        pytest_assert(
            vm_to_dpu_pkt is not None and exp_dpu_to_pe_pkt is not None and rcv_outbound_pl_ports is not None,
            "one-flow mode requires vm_to_dpu_pkt, exp_dpu_to_pe_pkt, rcv_outbound_pl_ports",
        )
        delay = 1.0 / rate_pps
        t_max = time.time() + 60

    packet_sending_flag = queue.Queue(1)

    def swo_action():
        while packet_sending_flag.empty() or (not packet_sending_flag.get()):
            time.sleep(0.2)
        logging.info("Set %s to standby (planned switchover)", label)
        set_dash_ha_scope(localhost, swo_duthost, ptfhost, swo_scope_key, "unspecified", ha_owner)
        set_dash_ha_scope(localhost, peer_duthost, ptfhost, peer_scope_key, "active", ha_owner)

    swo_thread = threading.Thread(target=swo_action, name=f"{label}_swo_action_thread")
    swo_thread.start()
    reached_max_time = False
    ptfadapter.dataplane.flush()
    time.sleep(1)
    send_count = 0

    while not reached_max_time:
        if multi_flow:
            if send_count >= MULTI_FLOW_MAX_PACKET_TARGET:
                break
            inner_sport = MULTI_FLOW_INNER_SPORT_BASE + send_count
            vm_pkt, _ = outbound_pl_packets(
                config,
                PLANNED_SWO_OUTER_ENCAP,
                inner_sport=inner_sport,
                vxlan_udp_sport=fixed_vxlan_udp_sport,
            )
            testutils.send(ptfadapter, send_ptf_intf, vm_pkt, 1)
        else:
            testutils.send(ptfadapter, send_ptf_intf, vm_to_dpu_pkt, 1)
            testutils.verify_packet_any_port(ptfadapter, exp_dpu_to_pe_pkt, rcv_outbound_pl_ports)

        if send_count == 0:
            if multi_flow:
                logger.info("First multi-flow packet sent (inner_sport=%s)", MULTI_FLOW_INNER_SPORT_BASE)
            else:
                logger.info("First outbound packet received")
        send_count += 1
        if send_count == initial_send_count:
            logging.info("Awake SWO action thread")
            packet_sending_flag.put(True)

        if not multi_flow:
            time.sleep(delay)

        reached_max_time = time.time() > t_max

    swo_thread.join()
    time.sleep(2)

    pytest_assert(verify_ha_state(swo_duthost, swo_scope_key, expected_swo_state),
                  f"{label} HA state is not {expected_swo_state} after planned switchover")
    pytest_assert(verify_ha_state(peer_duthost, peer_scope_key, expected_peer_state),
                  f"Peer HA state is not {expected_peer_state} after {label} planned switchover")

    if multi_flow:
        max_flows = send_count * 2 + 10
        flow_ok = compare_flow_tables(
            dpuhosts[0],
            dpuhosts[1],
            verbose=False,
            max_flows=max_flows,
            min_expected_flows=multi_flow_min_expected_flows,
        )
        pytest_assert(flow_ok, "Expected identical flow tables on both DPUs after multi-flow planned SWO")

    if multi_flow:
        logging.info("%s planned switchover complete, %d distinct flows sent", label, send_count)
    else:
        logging.info("%s planned switchover complete, all %d packets received", label, send_count)


def test_ha_planned_swo(
    ptfadapter,
    localhost,
    duthosts,
    ptfhost,
    activate_dash_ha_from_json,
    ha_owner,
    dash_pl_config,
    primary_vdpu_key,
    standby_vdpu_key,
):
    """Planned SWO with one repeated flow; verify each packet on the PTF.

    Only supported when ha_owner is "switch" (Mellanox SN4280 platform).

    Phase 1: Switch primary (active) to standby.
    Phase 2: Switch secondary (now active) again to standby.
    """

    if ha_owner != "switch":
        pytest.skip("Planned switchover is only supported when owner is 'switch'")

    vm_to_dpu_pkt, exp_dpu_to_pe_pkt = outbound_pl_packets(dash_pl_config[0], PLANNED_SWO_OUTER_ENCAP)
    rcv_outbound_pl_ports = dash_pl_config[0][REMOTE_PTF_RECV_INTF] + dash_pl_config[1][REMOTE_PTF_RECV_INTF]
    send_ptf_intf = dash_pl_config[0][LOCAL_PTF_INTF]

    _planned_swo_phase(
        ptfadapter=ptfadapter,
        localhost=localhost,
        ptfhost=ptfhost,
        swo_duthost=duthosts[0],
        swo_scope_key=primary_vdpu_key,
        peer_duthost=duthosts[1],
        peer_scope_key=standby_vdpu_key,
        expected_swo_state="standby",
        expected_peer_state="active",
        ha_owner=ha_owner,
        send_ptf_intf=send_ptf_intf,
        label="primary",
        multi_flow=False,
        vm_to_dpu_pkt=vm_to_dpu_pkt,
        exp_dpu_to_pe_pkt=exp_dpu_to_pe_pkt,
        rcv_outbound_pl_ports=rcv_outbound_pl_ports,
    )

    _planned_swo_phase(
        ptfadapter=ptfadapter,
        localhost=localhost,
        ptfhost=ptfhost,
        swo_duthost=duthosts[1],
        swo_scope_key=standby_vdpu_key,
        peer_duthost=duthosts[0],
        peer_scope_key=primary_vdpu_key,
        expected_swo_state="standby",
        expected_peer_state="active",
        ha_owner=ha_owner,
        send_ptf_intf=send_ptf_intf,
        label="secondary",
        multi_flow=False,
        vm_to_dpu_pkt=vm_to_dpu_pkt,
        exp_dpu_to_pe_pkt=exp_dpu_to_pe_pkt,
        rcv_outbound_pl_ports=rcv_outbound_pl_ports,
    )


def test_ha_planned_swo_multiple_flow(
    ptfadapter,
    localhost,
    duthosts,
    dpuhosts,
    ptfhost,
    activate_dash_ha_from_json,
    ha_owner,
    dash_pl_config,
    primary_vdpu_key,
    standby_vdpu_key,
):
    """Planned SWO with multiple distinct inner flows in <=45s window; validate flow dump sync (min_expected_flows).

    Only supported when ha_owner is "switch".

    Phase 1: Switch primary (active) to standby.
    Phase 2: Switch secondary (now active) again to standby.
    """

    if ha_owner != "switch":
        pytest.skip("Planned switchover is only supported when owner is 'switch'")

    send_ptf_intf = dash_pl_config[0][LOCAL_PTF_INTF]

    _planned_swo_phase(
        ptfadapter=ptfadapter,
        localhost=localhost,
        ptfhost=ptfhost,
        swo_duthost=duthosts[0],
        swo_scope_key=primary_vdpu_key,
        peer_duthost=duthosts[1],
        peer_scope_key=standby_vdpu_key,
        expected_swo_state="standby",
        expected_peer_state="active",
        ha_owner=ha_owner,
        send_ptf_intf=send_ptf_intf,
        label="primary",
        multi_flow=True,
        dash_pl_config=dash_pl_config,
        dpuhosts=dpuhosts,
    )

    _planned_swo_phase(
        ptfadapter=ptfadapter,
        localhost=localhost,
        ptfhost=ptfhost,
        swo_duthost=duthosts[1],
        swo_scope_key=standby_vdpu_key,
        peer_duthost=duthosts[0],
        peer_scope_key=primary_vdpu_key,
        expected_swo_state="standby",
        expected_peer_state="active",
        ha_owner=ha_owner,
        send_ptf_intf=send_ptf_intf,
        label="secondary",
        multi_flow=True,
        dash_pl_config=dash_pl_config,
        dpuhosts=dpuhosts,
    )
