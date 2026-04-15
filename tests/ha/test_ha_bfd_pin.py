import logging

import configs.privatelink_config as pl
import ptf.testutils as testutils
import pytest
import time
import threading
import queue
from constants import (
    LOCAL_PTF_INTF,
    REMOTE_PTF_RECV_INTF
)
from gnmi_utils import apply_messages
from packets import outbound_pl_packets
from tests.common.config_reload import config_reload
from ha_utils import bfd_pin_primary, bfd_unpin_primary, bfd_pin_both_sides, bfd_unpin_both_sides

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t1-smartswitch-ha'),
    pytest.mark.skip_check_dut_health
]

TRAFFIC_LOSS_THRESHOLD_PERCENTAGE = 1.0


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
        logger.info(f"Starting DASH configuration on {duthost.hostname} dpu {dpuhost.dpu_index} "
                    f"with {base_config_messages}")

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
    for dpuhost in dpuhosts:
        logger.info(f"config reload on {dpuhost.hostname}")
        config_reload(dpuhost, safe_reload=True, yang_validate=False)


"""
We are testing 4 scenarios:
1. BFD state UP pinned as DOWN(Pin DPU1 BFD probe state as DOWN) - traffic to active side
   Verify: DPU1 remains active, DPU2 remains standby and T2 receives packets without disruption.
2. BFD state UP pinned as DOWN(Pin DPU1 BFD probe state as DOWN) - traffic to standby side
   Verify: DPU1 remains active, DPU2 remains standby and T2 receives packets without disruption.
3. Both side pinned as DOWN (Pin DPU1 and DPU2 BFD probe state as DOWN) - traffic to active side
   Verify: DPU1 remains active, DPU2 remains standby. T2 receives packets without disruption.
4. Both side pinned as DOWN (Pin DPU1 and DPU2 BFD probe state as DOWN) - traffic to standby side
   Verify: DPU1 remains active, DPU2 remains standby. T2 receives packets without disruption.
"""


@pytest.mark.parametrize(
    "both_sides_pinned", [True, False],
    ids=["Both Sides Pinned", "Single Side Pinned"]
)
@pytest.mark.parametrize(
    "traffic_to_standby", [True, False],
    ids=["Standby Traffic", "Primary Traffic"]
)
def test_ha_bfd_pin(
    localhost,
    ptfadapter,
    ptfhost,
    duthosts,
    dpuhosts,
    activate_dash_ha_from_json,
    dash_pl_config,
    both_sides_pinned,
    traffic_to_standby
):
    traffic = "traffic to standby" if traffic_to_standby else "traffic to primary"
    bfd_pin_type = "Both sides pinned" if both_sides_pinned else "Primary side pinned"
    encap_proto = "vxlan"
    rate_pps = 20  # packets per second
    initial_send_count = 100
    delay = 1.0 / rate_pps
    rcv_outbound_pl_ports = dash_pl_config[0][REMOTE_PTF_RECV_INTF] + dash_pl_config[1][REMOTE_PTF_RECV_INTF]

    if traffic_to_standby:
        vm_to_dpu_pkt, exp_dpu_to_pe_pkt = outbound_pl_packets(dash_pl_config[1], encap_proto)
    else:
        vm_to_dpu_pkt, exp_dpu_to_pe_pkt = outbound_pl_packets(dash_pl_config[0], encap_proto)

    packet_sending_flag = queue.Queue(1)

    send_count = 0
    failed_count = 0

    def pinning_ha_action():
        # wait for packets sending started, then pin BFD state as DOWN
        while packet_sending_flag.empty() or (not packet_sending_flag.get()):
            time.sleep(0.2)
        if both_sides_pinned:
            logger.info(f"{bfd_pin_type}, pkt sent {send_count}")
            bfd_pin_both_sides(localhost, ptfhost, duthosts)
        else:
            logger.info(f"{bfd_pin_type}, pkt sent {send_count}")
            bfd_pin_primary(localhost, ptfhost, duthosts)
        logger.info(f"After BFD pinning, pkt sent {send_count}")

    t = threading.Thread(target=pinning_ha_action, name="pinning_ha_action_thread")
    t.start()
    t_max = time.time() + 60
    reached_max_time = False
    ptfadapter.dataplane.flush()
    time.sleep(1)
    while not reached_max_time:
        # After we send initial_send_count packets, awake pinning_ha_action thread
        if send_count == initial_send_count:
            logger.info("Awake pinning HA action thread")
            packet_sending_flag.put(True)

        try:
            if traffic_to_standby:
                if send_count == 0:
                    logger.info("Send first packet to standby")
                testutils.send(ptfadapter, dash_pl_config[1][LOCAL_PTF_INTF], vm_to_dpu_pkt, 1)
                testutils.verify_packet_any_port(ptfadapter, exp_dpu_to_pe_pkt, rcv_outbound_pl_ports)
                if send_count == 0:
                    logger.info("First packet verified on standby")
            else:
                if send_count == 0:
                    logger.info("Send first packet to primary")
                testutils.send(ptfadapter, dash_pl_config[0][LOCAL_PTF_INTF], vm_to_dpu_pkt, 1)
                testutils.verify_packet_any_port(ptfadapter, exp_dpu_to_pe_pkt, rcv_outbound_pl_ports)
                if send_count == 0:
                    logger.info("First packet verified on primary")
        except Exception as e:
            if failed_count == 0:
                logger.info(f"pkt dropped after {send_count} pkts, exception {e}")
                if send_count == 0:
                    logger.error(f"pkt dropped exception {e}")
                    pytest.fail(f"{bfd_pin_type} with {traffic} test error: no packets received")
            failed_count += 1

        send_count += 1
        time.sleep(delay)
        reached_max_time = time.time() > t_max

    t.join()
    time.sleep(2)
    if failed_count > 0:
        pytest.fail(f"{bfd_pin_type} with {traffic} test failed: "
                    f"sent: {send_count}, lost {failed_count}")
    else:
        logger.info(f"{bfd_pin_type} with {traffic} test passed. All {send_count} packets received.")
    if both_sides_pinned:
        bfd_unpin_both_sides(localhost, ptfhost, duthosts)
    else:
        bfd_unpin_primary(localhost, ptfhost, duthosts)
