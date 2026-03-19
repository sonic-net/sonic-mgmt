import logging

import configs.privatelink_config as pl
import ptf.testutils as testutils
import pytest
import time
import threading
import queue
from constants import (
    LOCAL_PTF_INTF,
    REMOTE_PTF_RECV_INTF,
    REMOTE_PTF_SEND_INTF
)
from gnmi_utils import apply_messages
from packets import outbound_pl_packets, inbound_pl_packets
from tests.common.config_reload import config_reload
from tests.common.platform.device_utils import platform_api_conn
from ha_dpu_utils import dpu_power_off_index, dpu_power_on_index

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
        duthost = duthosts[i]
        dpuhost = dpuhosts[i]
        base_config_messages = {
            **pl.APPLIANCE_CONFIG,
            **pl.ROUTING_TYPE_PL_CONFIG,
            **pl.VNET_CONFIG,
            **pl.ROUTE_GROUP1_CONFIG,
            **pl.METER_POLICY_V4_CONFIG
        }
        logger.info(f"Starting DASH configuration on {duthost.hostname}"
                    "dpu {dpuhost.dpu_index} with {base_config_messages}")

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


"""
We are testing 4 scenarios:
    1. Traffic to Primary and Primary DPU failure
    2. Traffic to Primary and Standby DPU failure
    3. Traffic to Standby and Primary DPU Failure
    4. Traffic to Standby and Standby DPU Failure
    When DPU failure is on standby not traffic loss should be observed
    When DPU failure is on primary less than 1% traffic loss should be observed
"""


@pytest.mark.parametrize(
    "standby_dpu_fail", [True, False],
    ids=["Standby DPU Fail", "Primary DPU Fail"]
)
@pytest.mark.parametrize(
    "traffic_to_standby", [True, False],
    ids=["Standby Traffic", "Primary Traffic"]
)
def test_ha_dpu_failure(
    ptfadapter,
    duthosts,
    dpuhosts,
    activate_dash_ha_from_json,
    dash_pl_config,
    standby_link_fail,
    standby_dpu_fail,
    traffic_to_standby
):
    encap_proto = "vxlan"
    rate_pps = 20
    initial_send_count = 100
    delay = 1.0 / rate_pps
    rcv_outbound_pl_ports = dash_pl_config[0][REMOTE_PTF_RECV_INTF] + dash_pl_config[1][REMOTE_PTF_RECV_INTF]

    if traffic_to_standby:
        vm_to_dpu_pkt, exp_dpu_to_pe_pkt = outbound_pl_packets(dash_pl_config[1], encap_proto)
        pe_to_dpu_pkt, exp_dpu_to_vm_pkt = inbound_pl_packets(dash_pl_config[1])
    else:
        vm_to_dpu_pkt, exp_dpu_to_pe_pkt = outbound_pl_packets(dash_pl_config[0], encap_proto)
        pe_to_dpu_pkt, exp_dpu_to_vm_pkt = inbound_pl_packets(dash_pl_config[0])

    _, exp_dpu_to_vm_pkt_standby = inbound_pl_packets(dash_pl_config[1])
    packet_sending_flag = queue.Queue(1)

    send_count = 0
    failed_count = 0

    def dpu_ha_action():
        # wait for packets sending started, then simulate link failure
        while packet_sending_flag.empty() or (not packet_sending_flag.get()):
            time.sleep(0.2)
        if standby_dpu_fail:
            logger.info(f"Simulate standby DPU failure, pkt sent {send_count}")
            dpu_power_off_index(duthosts[1], platform_api_conn, 0)
        else:
            logger.info(f"Simulate primary DPU failure, pkt sent {send_count}")
            dpu_power_off_index(duthosts[0], platform_api_conn, 0)
        logger.info(f"After DPU failure, pkt sent {send_count}")

    t = threading.Thread(target=dpu_ha_action, name="dpu_ha_action_thread")
    t.start()
    t_max = time.time() + 60
    reached_max_time = False
    ptfadapter.dataplane.flush()
    time.sleep(1)
    rcv_inbound_pl_ports = [dash_pl_config[0][LOCAL_PTF_INTF], dash_pl_config[1][LOCAL_PTF_INTF]]
    while not reached_max_time:
        # After we send initial_send_count packets, awake link_ha_action thread
        if send_count == initial_send_count:
            logger.info("Awake DPU failure HA action thread")
            packet_sending_flag.put(True)

        try:
            if traffic_to_standby:
                if send_count == 0:
                    logger.info("Send first outbound packet to standby")
                testutils.send(ptfadapter, dash_pl_config[1][LOCAL_PTF_INTF], vm_to_dpu_pkt, 1)
                testutils.verify_packet_any_port(ptfadapter, exp_dpu_to_pe_pkt, rcv_outbound_pl_ports)
                if send_count == 0:
                    logger.info("First outbound packet received")
                    logger.info("Send first inbound packet to standby")
                try:
                    testutils.send(ptfadapter, dash_pl_config[1][REMOTE_PTF_SEND_INTF], pe_to_dpu_pkt, 1)
                    if failed_count > 0:
                        testutils.verify_packet(ptfadapter, exp_dpu_to_vm_pkt_standby,
                                                dash_pl_config[1][LOCAL_PTF_INTF])
                    else:
                        testutils.verify_packet_any_port(ptfadapter, exp_dpu_to_vm_pkt, rcv_inbound_pl_ports)
                except Exception as e:
                    if failed_count < 3:
                        logger.info(f"inbound pkt dropped: {e}")
                    failed_count += 1
                if send_count == 0:
                    logger.info("First packets verified to standby")
            else:
                if send_count == 0:
                    logger.info("Send first outbound packet to primary")
                testutils.send(ptfadapter, dash_pl_config[0][LOCAL_PTF_INTF], vm_to_dpu_pkt, 1)
                testutils.verify_packet_any_port(ptfadapter, exp_dpu_to_pe_pkt, rcv_outbound_pl_ports)
                if send_count == 0:
                    logger.info("First outbound packet received")
                    logger.info("Send first inbound packet to primary")
                try:
                    testutils.send(ptfadapter, dash_pl_config[0][REMOTE_PTF_SEND_INTF], pe_to_dpu_pkt, 1)
                    if failed_count > 0:
                        testutils.verify_packet(ptfadapter, exp_dpu_to_vm_pkt_standby,
                                                dash_pl_config[1][LOCAL_PTF_INTF])
                    else:
                        testutils.verify_packet_any_port(ptfadapter, exp_dpu_to_vm_pkt, rcv_inbound_pl_ports)
                    if send_count == 0:
                        logger.info("First inbound packet received")
                except Exception as e:
                    if failed_count < 3:
                        logger.info(f"inbound pkt dropped: {e}")
                    failed_count += 1
        except Exception as e:
            if failed_count == 0:
                logger.info(f"pkt dropped after {send_count} pkts, exception {e}")
                if send_count == 0:
                    logger.error(f"pkt dropped exception {e}")
                    pytest.fail("HA link fail test error: no packets were received")
            failed_count += 1

        send_count += 1
        time.sleep(delay)
        reached_max_time = time.time() > t_max

    t.join()
    time.sleep(2)
    breakpoint()
    if standby_dpu_fail:
        dpu_power_on_index(duthosts[1], platform_api_conn, 0)
    else:
        dpu_power_on_index(duthosts[0], platform_api_conn, 0)

    traffic = "traffic to standby" if traffic_to_standby else "traffic to primary"
    if standby_dpu_fail:
        if failed_count > 0:
            pytest.fail(f"Standby DPU fail with {traffic} test error: {failed_count} "
                        "packets not received  {send_count} packets sent.")
        else:
            logger.info(f"Standby DPU fail with {traffic} test OK. All {send_count} packets sent were received.")
    else:
        threshold_loss = 1.0
        percentage_loss = (failed_count / send_count) * 100
        if (percentage_loss < threshold_loss):
            logger.info(f"Primary DPU fail with {traffic} test OK. Sent: {send_count},"
                        f" not received: {failed_count}, loss: {percentage_loss}, threshold: {threshold_loss}")
        else:
            pytest.fail(f"Primary DPU fail with {traffic} test error. Sent: {send_count},"
                        f" not received: {failed_count} loss: {percentage_loss}, threshold: {threshold_loss}")
