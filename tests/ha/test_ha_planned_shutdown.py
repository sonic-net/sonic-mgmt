import logging

import configs.privatelink_config as pl
import ptf.testutils as testutils
import pytest
import time
import threading
import queue
from tests.common.helpers.assertions import pytest_assert
from constants import LOCAL_PTF_INTF, REMOTE_PTF_RECV_INTF
from gnmi_utils import apply_messages
from packets import outbound_pl_packets
from tests.common.config_reload import config_reload
from ha_utils_planned_shut import set_dead_dash_ha_scope, verify_ha_state, activate_primary_dash_ha

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t1-smartswitch-ha'),
    pytest.mark.skip_check_dut_health
]

"""
Test prerequisites:
- Assign IPs to DPU-NPU dataplane interfaces
"""


@pytest.fixture(autouse=True, scope="function")
def common_setup_teardown(
    localhost,
    duthosts,
    ptfhost,
    dpu_index,
    skip_config,
    dpuhosts,
    setup_ha_config,
    setup_dash_ha_from_json,
    setup_gnmi_server,
    set_vxlan_udp_sport_range,
    setup_npu_dpu  # noqa: F811
):
    if skip_config:
        return

    for i in range(len(duthosts)):
        breakpoint()
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

    config_reload(dpuhost, safe_reload=True, yang_validate=False)
    # apply_messages(localhost, duthost, ptfhost, pl.ENI_ROUTE_GROUP1_CONFIG, dpuhost.dpu_index, False)
    # apply_messages(localhost, duthost, ptfhost, pl.ENI_CONFIG, dpuhost.dpu_index, False)
    # apply_messages(localhost, duthost, ptfhost, meter_rule_messages, dpuhost.dpu_index, False)
    # apply_messages(localhost, duthost, ptfhost, route_and_mapping_messages, dpuhost.dpu_index, False)
    # apply_messages(localhost, duthost, ptfhost, base_config_messages, dpuhost.dpu_index, False)


def test_ha_planned_shutdown(
    ptfadapter,
    duthosts,
    activate_dash_ha_from_json,
    dash_pl_config
):
    encap_proto = "vxlan"
    rate_pps = 10  # packets per second
    initial_send_count = 10
    delay = 1.0 / rate_pps

    vm_to_dpu_pkt, exp_dpu_to_pe_pkt = outbound_pl_packets(dash_pl_config[0], encap_proto)
    breakpoint()

    packet_sending_flag = queue.Queue(1)

    def primary_ha_action():
        # wait for packets sending started, then set primary to dead
        while packet_sending_flag.empty() or (not packet_sending_flag.get()):
            time.sleep(0.2)
        logging.info("Set primary to dead")
        set_dead_dash_ha_scope(duthosts[0], "vdpu0_0:haset0_0")
        pytest_assert(verify_ha_state(duthosts[0], "vdpu0_0:haset0_0", "dead"),
                      "Primary HA state is not dead")
        pytest_assert(verify_ha_state(duthosts[1], "vdpu1_0:haset0_0", "standalone"),
                      "Secondary HA state is not standalone")

    t = threading.Thread(target=primary_ha_action, name="primary_ha_action_thread")
    t.start()
    t_max = time.time() + 60
    # Calculate the delay between packets based on the desired rate
    reached_max_time = False
    ptfadapter.dataplane.flush()
    time.sleep(1)
    send_count = 0
    while not reached_max_time:
        # After we send initial_send_count packets, awake perform_ha_action thread
        if send_count == initial_send_count:
            logging.info("Awake HA action thread")
            packet_sending_flag.put(True)

        testutils.send(ptfadapter, dash_pl_config[0][LOCAL_PTF_INTF], vm_to_dpu_pkt, 1)
        send_count += 1
        time.sleep(delay)
        reached_max_time = time.time() > t_max

    t.join()
    time.sleep(2)
    match_count = testutils.count_matched_packets_all_ports(ptfadapter, exp_dpu_to_pe_pkt,
                                                            ports=dash_pl_config[0][REMOTE_PTF_RECV_INTF], timeout=10)
    logging.info("match_count: {}, send_count: {}".format(match_count, send_count))

    assert match_count == send_count, (
        "Packets lost during primary shutdown, "
        f"send_count: {send_count}, match_count: {match_count}"
    )
    # Re-activate primary
    pytest_assert(activate_primary_dash_ha(duthosts[0], "vdpu0_0:haset0_0"),
                  "Failed to re-activate HA on primary")

    packet_sending_flag = queue.Queue(1)

    def standby_ha_action():
        # wait for packets sending started, then set primary to dead
        while packet_sending_flag.empty() or (not packet_sending_flag.get()):
            time.sleep(0.2)
        logging.info("Set standby to dead")

        set_dead_dash_ha_scope(duthosts[1], "vdpu1_0:haset0_0")
        pytest_assert(verify_ha_state(duthosts[1], "vdpu1_0:haset0_0", "dead"),
                      "Secondary HA state is not dead")
        pytest_assert(verify_ha_state(duthosts[0], "vdpu0_0:haset0_0", "standalone"),
                      "Primary HA state is not standalone")

    t = threading.Thread(target=standby_ha_action, name="standby_ha_action_thread")
    t.start()
    t_max = time.time() + 60
    reached_max_time = False
    ptfadapter.dataplane.flush()
    time.sleep(1)
    send_count = 0
    while not reached_max_time:
        # After we send initial_send_count packets, awake standby_ha_action thread
        if send_count == initial_send_count:
            logging.info("Awake standby HA action thread")
            packet_sending_flag.put(True)

        testutils.send(ptfadapter, dash_pl_config[0][LOCAL_PTF_INTF], vm_to_dpu_pkt, 1)
        send_count += 1
        time.sleep(delay)
        reached_max_time = time.time() > t_max

    t.join()
    time.sleep(2)
    match_count = testutils.count_matched_packets_all_ports(ptfadapter, exp_dpu_to_pe_pkt,
                                                            ports=dash_pl_config[0][REMOTE_PTF_RECV_INTF], timeout=10)
    logging.info("match_count: {}, send_count: {}".format(match_count, send_count))

    assert match_count == send_count, (
        "Packets lost during secondary shutdown, "
        f"send_count: {send_count}, match_count: {match_count}"
    )
# pytest_assert(match_count == send_count,  # noqa: E122
#                  "Packets lost during secondary shutdown, send_count: {}, match_count: {}".format(
#                  send_count, match_count))
