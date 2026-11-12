import logging
import queue
import threading
import time

import configs.privatelink_config as pl
import ptf.packet as scapy
import ptf.testutils as testutils
import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.common.dash_utils import verify_tunnel_packets
from tests.ha.conftest import apply_dash_pl_pipeline_config
from constants import (
    LOCAL_PTF_INTF,
    REMOTE_PTF_RECV_INTF,
    REMOTE_PTF_SEND_INTF,
)
from ha_dash_flow_utils import compare_flow_tables
from ha_packets import inbound_pl_packets, outbound_pl_packets, bootstrap_pl_tcp_flow_outbound
from ha_utils import verify_ha_state, set_dash_ha_scope, parallel_config_reload_dpuhosts

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t1-smartswitch-ha'),
    pytest.mark.skip_check_dut_health
]

PLANNED_SWO_OUTER_ENCAP = "vxlan"

# Fixed inner L4 ports for the single repeated floating-NIC flow.
FNIC_INNER_SPORT = 6789
FNIC_INNER_DPORT = 4567


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

    apply_dash_pl_pipeline_config(localhost, duthosts, dpuhosts, ptfhost, floating_nic=True)

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
    vm_to_dpu_pkt=None,
    exp_dpu_to_pe_pkt=None,
    rcv_outbound_pl_ports=None,
    pe_to_dpu_pkt=None,
    exp_dpu_to_vm_pkt=None,
    send_pe_ptf_intf=None,
    t2_ports=None,
    tunnel_endpoint_ips=None,
    dpuhosts=None,
):
    """Run one planned-switchover phase using floating-NIC traffic: send traffic, trigger SWO, verify HA state.

    Send the same floating-NIC packet each iteration, verify outbound egress on the PTF and the inbound
    (reverse) return path tunneled to the T2 (upstream) ports via verify_tunnel_packets. Because the active side
    flips during switchover, t2_ports should cover both DUTs' upstream ports.

    Args:
        swo_duthost: DUT on which we request standby (the one being switched over).
        swo_scope_key: HA scope key for the SWO DUT.
        peer_duthost: The other DUT in the HA pair.
        peer_scope_key: HA scope key for the peer DUT.
        expected_swo_state: Expected HA state on swo_duthost after SWO (e.g. "standby").
        expected_peer_state: Expected HA state on peer_duthost after SWO (e.g. "active").
        ha_owner: Owner string from ha_owner fixture ("dpu" or "switch").
        label: Human-readable label for logging (e.g. "primary" / "secondary").
    """
    rate_pps = 10
    initial_send_count = 10
    delay = 1.0 / rate_pps
    t_max = time.time() + 60

    pytest_assert(
        vm_to_dpu_pkt is not None and exp_dpu_to_pe_pkt is not None and rcv_outbound_pl_ports is not None,
        "one-flow mode requires vm_to_dpu_pkt, exp_dpu_to_pe_pkt, rcv_outbound_pl_ports",
    )
    pytest_assert(
        pe_to_dpu_pkt is not None and exp_dpu_to_vm_pkt is not None and send_pe_ptf_intf is not None
        and t2_ports is not None and tunnel_endpoint_ips is not None,
        "one-flow mode requires reverse-path pe_to_dpu_pkt, exp_dpu_to_vm_pkt, send_pe_ptf_intf, "
        "t2_ports, tunnel_endpoint_ips",
    )
    tunnel_endpoint_counts = {ip: 0 for ip in tunnel_endpoint_ips}

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
    outbound_loss_count = 0
    return_path_loss_count = 0
    first_outbound_received = False
    first_return_path_received = False

    while not reached_max_time:
        testutils.send(ptfadapter, send_ptf_intf, vm_to_dpu_pkt, 1)
        try:
            testutils.verify_packet_any_port(ptfadapter, exp_dpu_to_pe_pkt, rcv_outbound_pl_ports)
            if not first_outbound_received:
                logger.info("First outbound packet received")
                first_outbound_received = True
        except (Exception, pytest.fail.Exception) as e:
            outbound_loss_count += 1
            logger.info("%s outbound packet dropped: %s", label, e)

        testutils.send(ptfadapter, send_pe_ptf_intf, pe_to_dpu_pkt, 1)
        try:
            verify_tunnel_packets(ptfadapter, t2_ports, exp_dpu_to_vm_pkt, tunnel_endpoint_counts)
            if not first_return_path_received:
                logger.info("First return-path packet received")
                first_return_path_received = True
        except (Exception, pytest.fail.Exception) as e:
            return_path_loss_count += 1
            logger.info("%s return-path packet dropped: %s", label, e)

        send_count += 1
        if send_count == initial_send_count:
            logging.info("Awake SWO action thread")
            packet_sending_flag.put(True)

        time.sleep(delay)

        reached_max_time = time.time() > t_max

    swo_thread.join()
    time.sleep(1)

    total_loss_count = outbound_loss_count + return_path_loss_count
    logging.info(
        "%s planned switchover traffic complete: sent=%d, lost=%d "
        "(outbound=%d, return-path=%d, return-path endpoints=%s)",
        label, send_count, total_loss_count, outbound_loss_count, return_path_loss_count, tunnel_endpoint_counts,
    )

    pytest_assert(verify_ha_state(swo_duthost, swo_scope_key, expected_swo_state),
                  f"{label} HA state is not {expected_swo_state} after planned switchover")
    pytest_assert(verify_ha_state(peer_duthost, peer_scope_key, expected_peer_state),
                  f"Peer HA state is not {expected_peer_state} after {label} planned switchover")

    if dpuhosts is not None:
        try:
            flow_ok = compare_flow_tables(dpuhosts[0], dpuhosts[1], verbose=True, flow_state=True)
            if not flow_ok:
                logger.warning("%s flow tables differ after planned switchover", label)
        except Exception as e:
            logger.warning("%s failed to dump/compare flow tables after planned switchover: %s", label, e)

    pytest_assert(
        total_loss_count == 0,
        f"{label} planned switchover lost {total_loss_count} packets "
        f"(outbound={outbound_loss_count}, return-path={return_path_loss_count})",
    )

    logging.info(
        "%s planned switchover complete, all %d packet pairs received (return-path: %s)",
        label, send_count, tunnel_endpoint_counts,
    )


def test_ha_planned_swo_fnic(
    ptfadapter,
    localhost,
    duthosts,
    ptfhost,
    dpuhosts,
    activate_dash_ha_from_json,
    ha_owner,
    dash_pl_config,
    get_t2_info,
    primary_vdpu_key,
    standby_vdpu_key,
):
    """Planned SWO with one repeated floating-NIC flow; verify each packet on the PTF.

    Only supported when ha_owner is "switch" (Mellanox SN4280 platform).

    Phase 1: Switch primary (active) to standby.
    Phase 2: Switch secondary (now active) again to standby.
    """

    if ha_owner != "switch":
        pytest.skip("Planned switchover is only supported when owner is 'switch'")

    vm_to_dpu_pkt, exp_dpu_to_pe_pkt = outbound_pl_packets(
        dash_pl_config[0], PLANNED_SWO_OUTER_ENCAP, floating_nic=True,
        inner_sport=FNIC_INNER_SPORT, inner_dport=FNIC_INNER_DPORT, vni=pl.ENI_TRUSTED_VNI
    )
    pe_to_dpu_pkt, exp_dpu_to_vm_pkt = inbound_pl_packets(
        dash_pl_config[0], floating_nic=True, inner_sport=FNIC_INNER_DPORT, inner_dport=FNIC_INNER_SPORT
    )
    exp_dpu_to_vm_pkt.set_do_not_care_packet(scapy.IP, "dst")
    exp_dpu_to_vm_pkt = ptfadapter.update_payload(exp_dpu_to_vm_pkt)
    rcv_outbound_pl_ports = dash_pl_config[0][REMOTE_PTF_RECV_INTF] + dash_pl_config[1][REMOTE_PTF_RECV_INTF]
    send_ptf_intf = dash_pl_config[0][LOCAL_PTF_INTF]
    send_pe_ptf_intf = dash_pl_config[0][REMOTE_PTF_SEND_INTF]
    t2_ports = get_t2_info[duthosts[0].hostname] + get_t2_info[duthosts[1].hostname]

    # Default HA traffic is TCP. Bootstrap the stateful flow with SYN so repeated
    # outbound/inbound ACK packets match the established connection across SWO.
    bootstrap_pl_tcp_flow_outbound(
        ptfadapter,
        dash_pl_config[0],
        PLANNED_SWO_OUTER_ENCAP,
        recv_ports=rcv_outbound_pl_ports,
        floating_nic=True,
        inner_sport=FNIC_INNER_SPORT,
        inner_dport=FNIC_INNER_DPORT,
        vni=pl.ENI_TRUSTED_VNI,
    )

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
        vm_to_dpu_pkt=vm_to_dpu_pkt,
        exp_dpu_to_pe_pkt=exp_dpu_to_pe_pkt,
        rcv_outbound_pl_ports=rcv_outbound_pl_ports,
        pe_to_dpu_pkt=pe_to_dpu_pkt,
        exp_dpu_to_vm_pkt=exp_dpu_to_vm_pkt,
        send_pe_ptf_intf=send_pe_ptf_intf,
        t2_ports=t2_ports,
        tunnel_endpoint_ips=pl.TUNNEL1_ENDPOINT_IPS,
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
        vm_to_dpu_pkt=vm_to_dpu_pkt,
        exp_dpu_to_pe_pkt=exp_dpu_to_pe_pkt,
        rcv_outbound_pl_ports=rcv_outbound_pl_ports,
        pe_to_dpu_pkt=pe_to_dpu_pkt,
        exp_dpu_to_vm_pkt=exp_dpu_to_vm_pkt,
        send_pe_ptf_intf=send_pe_ptf_intf,
        t2_ports=t2_ports,
        tunnel_endpoint_ips=pl.TUNNEL1_ENDPOINT_IPS,
        dpuhosts=dpuhosts,
    )
