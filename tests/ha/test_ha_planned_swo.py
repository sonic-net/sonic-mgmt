import logging

import configs.privatelink_config as pl
import ptf.testutils as testutils
import pytest
import time
import threading
import queue
import concurrent.futures
from tests.common.helpers.assertions import pytest_assert
from constants import LOCAL_PTF_INTF, REMOTE_PTF_RECV_INTF
from gnmi_utils import apply_messages
from packets import outbound_pl_packets
from tests.common.config_reload import config_reload
from ha_utils import verify_ha_state, set_dash_ha_scope

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t1-smartswitch-ha'),
    pytest.mark.skip_check_dut_health
]


@pytest.fixture(autouse=True, scope="function")
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

    for i in range(len(duthosts)):
        duthost = duthosts[i]
        dpuhost = dpuhosts[i]
        base_config_messages = {
            **pl.APPLIANCE_CONFIG,
            **pl.ROUTING_TYPE_PL_CONFIG,
            **pl.VNET_CONFIG,
            **pl.ROUTE_GROUP1_CONFIG,
            **pl.METER_POLICY_V4_CONFIG
        }
        logger.info(f"configure on {duthost.hostname} dpu {dpuhost.dpu_index} {base_config_messages}")

        apply_messages(localhost, duthost, ptfhost, base_config_messages, dpuhost.dpu_index)

        route_and_mapping_messages = {
            **pl.PE_VNET_MAPPING_CONFIG,
            **pl.PE_SUBNET_ROUTE_CONFIG,
            **pl.VM_SUBNET_ROUTE_CONFIG
        }

        if 'bluefield' in dpuhost.facts['asic_type']:
            route_and_mapping_messages.update({
                **pl.INBOUND_VNI_ROUTE_RULE_CONFIG
            })

        logger.info(route_and_mapping_messages)
        apply_messages(localhost, duthost, ptfhost, route_and_mapping_messages, dpuhost.dpu_index)

        meter_rule_messages = {
            **pl.METER_RULE1_V4_CONFIG,
            **pl.METER_RULE2_V4_CONFIG,
        }
        logger.info(meter_rule_messages)
        apply_messages(localhost, duthost, ptfhost, meter_rule_messages, dpuhost.dpu_index)

        logger.info(pl.ENI_CONFIG)
        apply_messages(localhost, duthost, ptfhost, pl.ENI_CONFIG, dpuhost.dpu_index)

        logger.info(pl.ENI_ROUTE_GROUP1_CONFIG)
        apply_messages(localhost, duthost, ptfhost, pl.ENI_ROUTE_GROUP1_CONFIG, dpuhost.dpu_index)

    yield

    def _reload(host):
        logger.info(f"config reload on {host.hostname}")
        config_reload(host, safe_reload=True, yang_validate=False)

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(dpuhosts)) as executor:
        list(executor.map(_reload, dpuhosts))


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
    vm_to_dpu_pkt,
    exp_dpu_to_pe_pkt,
    send_ptf_intf,
    rcv_outbound_pl_ports,
    label,
):
    """Run one planned-switchover phase: send traffic, trigger SWO, verify states, re-activate.

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

    packet_sending_flag = queue.Queue(1)

    def swo_action():
        while packet_sending_flag.empty() or (not packet_sending_flag.get()):
            time.sleep(0.2)
        logging.info("Set %s to standby (planned switchover)", label)
        set_dash_ha_scope(localhost, swo_duthost, ptfhost, swo_scope_key, "unspecified", ha_owner)
        set_dash_ha_scope(localhost, peer_duthost, ptfhost, peer_scope_key, "active", ha_owner)

    t = threading.Thread(target=swo_action, name=f"{label}_swo_action_thread")
    t.start()
    t_max = time.time() + 60
    reached_max_time = False
    ptfadapter.dataplane.flush()
    time.sleep(1)
    send_count = 0

    while not reached_max_time:
        testutils.send(ptfadapter, send_ptf_intf, vm_to_dpu_pkt, 1)
        testutils.verify_packet_any_port(ptfadapter, exp_dpu_to_pe_pkt, rcv_outbound_pl_ports)
        if send_count == 0:
            logger.info("First outbound packet received")
        send_count += 1
        if send_count == initial_send_count:
            logging.info("Awake SWO action thread")
            packet_sending_flag.put(True)
        time.sleep(delay)
        reached_max_time = time.time() > t_max

    t.join()
    time.sleep(2)

    pytest_assert(verify_ha_state(swo_duthost, swo_scope_key, expected_swo_state),
                  f"{label} HA state is not {expected_swo_state} after planned switchover")
    pytest_assert(verify_ha_state(peer_duthost, peer_scope_key, expected_peer_state),
                  f"Peer HA state is not {expected_peer_state} after {label} planned switchover")

    logging.info("%s planned switchover complete, all %d packets received", label, send_count)


def test_ha_planned_swo(
    ptfadapter,
    localhost,
    duthosts,
    ptfhost,
    activate_dash_ha_from_json,
    ha_owner,
    dash_pl_config
):
    """Test planned switchover: active node transitions to standby, standby becomes active.

    Only supported when ha_owner is "switch" (Mellanox SN4280 platform).

    Phase 1: Switch primary (active) to standby.
    Phase 2: Switch secondary (now active) again to standby.
    """

    if ha_owner != "switch":
        pytest.skip("Planned switchover is only supported when owner is 'switch'")

    encap_proto = "vxlan"
    vm_to_dpu_pkt, exp_dpu_to_pe_pkt = outbound_pl_packets(dash_pl_config[0], encap_proto)
    rcv_outbound_pl_ports = dash_pl_config[0][REMOTE_PTF_RECV_INTF] + dash_pl_config[1][REMOTE_PTF_RECV_INTF]
    send_ptf_intf = dash_pl_config[0][LOCAL_PTF_INTF]

    # Phase 1: primary (active) -> standby
    _planned_swo_phase(
        ptfadapter=ptfadapter,
        localhost=localhost,
        ptfhost=ptfhost,
        swo_duthost=duthosts[0],
        swo_scope_key="vdpu0_0:haset0_0",
        peer_duthost=duthosts[1],
        peer_scope_key="vdpu1_0:haset0_0",
        expected_swo_state="standby",
        expected_peer_state="active",
        ha_owner=ha_owner,
        vm_to_dpu_pkt=vm_to_dpu_pkt,
        exp_dpu_to_pe_pkt=exp_dpu_to_pe_pkt,
        send_ptf_intf=send_ptf_intf,
        rcv_outbound_pl_ports=rcv_outbound_pl_ports,
        label="primary",
    )

    # Phase 2: secondary (now active) -> standby
    _planned_swo_phase(
        ptfadapter=ptfadapter,
        localhost=localhost,
        ptfhost=ptfhost,
        swo_duthost=duthosts[1],
        swo_scope_key="vdpu1_0:haset0_0",
        peer_duthost=duthosts[0],
        peer_scope_key="vdpu0_0:haset0_0",
        expected_swo_state="standby",
        expected_peer_state="active",
        ha_owner=ha_owner,
        vm_to_dpu_pkt=vm_to_dpu_pkt,
        exp_dpu_to_pe_pkt=exp_dpu_to_pe_pkt,
        send_ptf_intf=send_ptf_intf,
        rcv_outbound_pl_ports=rcv_outbound_pl_ports,
        label="secondary",
    )
