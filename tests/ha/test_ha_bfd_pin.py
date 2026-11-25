import logging

import ptf.testutils as testutils
import pytest
import time
from constants import (
    LOCAL_PTF_INTF,
    REMOTE_PTF_RECV_INTF
)
from ha_packets import outbound_pl_packets, bootstrap_pl_tcp_flow_outbound
from tests.ha.conftest import apply_dash_pl_pipeline_config
from tests.common.helpers.assertions import pytest_assert
from ha_utils import (
    set_vdpu_bfd_probe_states,
    set_dpu_bfd_admin_down,
    wait_dpu_bfd_peers_down,
    wait_dpu_bfd_peers_up,
    verify_ha_state,
    parallel_config_reload_dpuhosts,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t1-smartswitch-ha'),
    pytest.mark.skip_check_dut_health
]

ENCAP_PROTO = "vxlan"
RATE_PPS = 20
SEND_COUNT = 100
# Bounded so a lost packet costs ~0.2s instead of ptf's 2s default, keeping the
# loss count meaningful.
VERIFY_TIMEOUT = 0.2

# pinned_vdpu_bfd_probe_states vectors. Index 0 = DPU1 (active/primary),
# index 1 = DPU2 (standby); "none" removes the pin.
PIN_DPU1_DOWN = ["down", "none"]
PIN_DPU1_UP = ["up", "none"]
UNPIN = ["none", "none"]


@pytest.fixture(autouse=True, scope="function")
def common_setup_teardown(
    localhost,
    duthosts,
    ptfhost,
    dpu_index,
    skip_config,
    dpuhosts,
    setup_ha_config,
    setup_dash_ha_from_json_func_scope,
    setup_gnmi_server,
    ensure_vxlan_udp_sport_range,
    setup_npu_dpu  # noqa: F811
):
    if skip_config:
        return

    apply_dash_pl_pipeline_config(localhost, duthosts, dpuhosts, ptfhost)

    yield
    parallel_config_reload_dpuhosts(dpuhosts)


"""
Test plan: DASH HA "pinned BFD probe state". Two scenarios, each with traffic
sent to the active or the standby side:

1. BFD state UP pinned as DOWN: pin DPU1's (active) probe DOWN over a healthy
   session. Traffic must egress via DUT2 while pinned and return to DUT1 after
   the pin is removed. DPU1 stays active, DPU2 stays standby.
2. BFD state DOWN pinned as UP: force DPU1's software BFD DOWN (admin-shut the
   FRR peers on the DPU), then pin its probe UP. Traffic must egress via DUT1
   while pinned and move to DUT2 after the pin is removed.
"""


def _bfd_pin_scope_keys(dpuhosts):
    return (
        f"vdpu0_{dpuhosts[0].dpu_index}:haset0_0",
        f"vdpu1_{dpuhosts[1].dpu_index}:haset0_0",
    )


def _send_outbound_pl_loss(ptfadapter, tx_intf, vm_to_dpu_pkt, exp_pkt, recv_ports, count=SEND_COUNT):
    """Send ``count`` outbound PL packets; return how many were not received
    (transformed) on ``recv_ports``."""
    lost = 0
    ptfadapter.dataplane.flush()
    for _ in range(count):
        testutils.send(ptfadapter, tx_intf, vm_to_dpu_pkt, 1)
        try:
            testutils.verify_packet_any_port(ptfadapter, exp_pkt, recv_ports, timeout=VERIFY_TIMEOUT)
        except Exception:
            lost += 1
        time.sleep(1.0 / RATE_PPS)
    return lost


def _wait_bfd_pin_steady(duthosts, dpuhosts, active_key):
    """Wait for DPU1 to be active with its software BFD up before probing the data
    plane; a prior test can leave BFD/HA briefly re-converging after config reload."""
    pytest_assert(wait_dpu_bfd_peers_up(dpuhosts[0]),
                  "DPU1 software BFD did not reach 'up' at steady state")
    pytest_assert(verify_ha_state(duthosts[0], active_key, "active"),
                  "DPU1 did not reach 'active' at steady state")


@pytest.mark.parametrize(
    "traffic_to_standby", [True, False],
    ids=["Standby Traffic", "Primary Traffic"]
)
def test_ha_bfd_pin_up_as_down(
    localhost,
    ptfadapter,
    ptfhost,
    duthosts,
    dpuhosts,
    activate_dash_ha_from_json,
    dash_pl_config,
    traffic_to_standby
):
    """BFD state UP pinned as DOWN: pinning DPU1 down moves traffic to DUT2;
    removing the pin returns it to DUT1, with no disruption and no failover."""
    cfg = dash_pl_config[1] if traffic_to_standby else dash_pl_config[0]
    vm_to_dpu_pkt, exp_pkt = outbound_pl_packets(cfg, ENCAP_PROTO)
    tx_intf = cfg[LOCAL_PTF_INTF]
    dut1_recv = dash_pl_config[0][REMOTE_PTF_RECV_INTF]
    dut2_recv = dash_pl_config[1][REMOTE_PTF_RECV_INTF]
    active_key, _ = _bfd_pin_scope_keys(dpuhosts)

    # Wait for steady state (a prior test may have churned BFD/HA) before probing.
    _wait_bfd_pin_steady(duthosts, dpuhosts, active_key)

    # Establish the stateful TCP flow (syncs to the standby) before pinning.
    bootstrap_pl_tcp_flow_outbound(ptfadapter, cfg, ENCAP_PROTO, recv_ports=dut1_recv + dut2_recv)

    try:
        # Pin DPU1 (active) probe DOWN -> traffic honors the pin, egresses via DUT2.
        set_vdpu_bfd_probe_states(localhost, ptfhost, duthosts, PIN_DPU1_DOWN)
        pytest_assert(verify_ha_state(duthosts[0], active_key, "active"),
                      "DPU1 must remain active while its probe is pinned down")
        lost = _send_outbound_pl_loss(ptfadapter, tx_intf, vm_to_dpu_pkt, exp_pkt, dut2_recv)
        pytest_assert(lost == 0,
                      f"UP-pinned-as-DOWN: {lost}/{SEND_COUNT} lost while pinned (expected egress on DUT2)")

        # Remove the pin -> probe follows the real (up) state, egress returns to DUT1.
        set_vdpu_bfd_probe_states(localhost, ptfhost, duthosts, UNPIN)
        pytest_assert(verify_ha_state(duthosts[0], active_key, "active"),
                      "DPU1 must remain active after the pin is removed")
        lost = _send_outbound_pl_loss(ptfadapter, tx_intf, vm_to_dpu_pkt, exp_pkt, dut1_recv)
        pytest_assert(lost == 0,
                      f"UP-pinned-as-DOWN: {lost}/{SEND_COUNT} lost after unpin (expected egress on DUT1)")
    finally:
        set_vdpu_bfd_probe_states(localhost, ptfhost, duthosts, UNPIN)


@pytest.mark.parametrize(
    "traffic_to_standby", [True, False],
    ids=["Standby Traffic", "Primary Traffic"]
)
def test_ha_bfd_pin_down_as_up(
    localhost,
    ptfadapter,
    ptfhost,
    duthosts,
    dpuhosts,
    activate_dash_ha_from_json,
    dash_pl_config,
    traffic_to_standby
):
    """BFD state DOWN pinned as UP: with DPU1's software BFD forced down, pinning
    its probe UP keeps traffic on DUT1; removing the pin lets the real down state
    move traffic to DUT2."""
    cfg = dash_pl_config[1] if traffic_to_standby else dash_pl_config[0]
    vm_to_dpu_pkt, exp_pkt = outbound_pl_packets(cfg, ENCAP_PROTO)
    tx_intf = cfg[LOCAL_PTF_INTF]
    dut1_recv = dash_pl_config[0][REMOTE_PTF_RECV_INTF]
    dut2_recv = dash_pl_config[1][REMOTE_PTF_RECV_INTF]
    active_key, _ = _bfd_pin_scope_keys(dpuhosts)

    # Wait for steady state (a prior test may have churned BFD/HA) before probing.
    _wait_bfd_pin_steady(duthosts, dpuhosts, active_key)

    bootstrap_pl_tcp_flow_outbound(ptfadapter, cfg, ENCAP_PROTO, recv_ports=dut1_recv + dut2_recv)

    try:
        # Force DPU1's real software BFD DOWN by admin-shutting its FRR peers.
        # BfdMgr dedupes, so hamgrd re-writes will not revert this.
        set_dpu_bfd_admin_down(dpuhosts[0], shutdown=True)
        pytest_assert(wait_dpu_bfd_peers_down(dpuhosts[0]),
                      "DPU1 software BFD did not go down after admin shutdown")

        # Pin DPU1 probe UP -> masks the real down; traffic stays on DUT1.
        set_vdpu_bfd_probe_states(localhost, ptfhost, duthosts, PIN_DPU1_UP)
        pytest_assert(verify_ha_state(duthosts[0], active_key, "active"),
                      "DPU1 must remain active while its probe is pinned up")
        lost = _send_outbound_pl_loss(ptfadapter, tx_intf, vm_to_dpu_pkt, exp_pkt, dut1_recv)
        pytest_assert(lost == 0,
                      f"DOWN-pinned-as-UP: {lost}/{SEND_COUNT} lost while pinned (expected egress on DUT1)")

        # Remove the pin -> the real (down) state governs; traffic moves to DUT2.
        set_vdpu_bfd_probe_states(localhost, ptfhost, duthosts, UNPIN)
        lost = _send_outbound_pl_loss(ptfadapter, tx_intf, vm_to_dpu_pkt, exp_pkt, dut2_recv)
        pytest_assert(lost == 0,
                      f"DOWN-pinned-as-UP: {lost}/{SEND_COUNT} lost after unpin (expected egress on DUT2)")
    finally:
        # Restore BFD before removing the pin so HA never sees a real-down and
        # unpinned window (which would churn the active role).
        set_dpu_bfd_admin_down(dpuhosts[0], shutdown=False)
        set_vdpu_bfd_probe_states(localhost, ptfhost, duthosts, UNPIN)
