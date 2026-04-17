import logging
from multiprocessing.pool import ThreadPool
import concurrent.futures

import configs.privatelink_config as pl
import ptf.testutils as testutils
import pytest
import time
import threading
from constants import (
    LOCAL_PTF_INTF,
    REMOTE_PTF_RECV_INTF
)
from gnmi_utils import apply_messages
from packets import outbound_pl_packets
from tests.common.utilities import wait_until
from tests.common.config_reload import config_reload
from tests.common.reboot import reboot_smartswitch, wait_for_startup
from tests.ha.ha_dpu_utils import CHECK_DPU_STATE_TIMEOUT, CHECK_DPU_STATE_TIME_INT, check_dpu_up_state

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t1-smartswitch-ha')
]


THRESHOLD_LOSS_PERCENT = 2.0
RATE_PPS = 20
INITIAL_SEND_COUNT = 100


def reload_config_for_host(dpuhost):
    logger.info(f"config reload on {dpuhost.hostname}")
    config_reload(dpuhost, safe_reload=True, yang_validate=False)


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
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(dpuhosts)) as executor:
        # Map the reload_config_for_host function to the dpuhosts list
        executor.map(reload_config_for_host, dpuhosts)


"""
We are testing 4 scenarios:
    1. Traffic to Primary and Primary NPU reboot
    2. Traffic to Primary and Standby NPU reboot
    3. Traffic to Standby and Primary NPU reboot
    4. Traffic to Standby and Standby NPU reboot
For each scenario, we will send traffic for 60 seconds and check if the packet loss is within the threshold.
"""


@pytest.mark.parametrize(
    "standby_npu_reboot", [True, False],
    ids=["Standby NPU Reboot", "Primary NPU Reboot"]
)
@pytest.mark.parametrize(
    "traffic_to_standby", [True, False],
    ids=["Standby Traffic", "Primary Traffic"]
)
def test_ha_npu_reboot(
    ptfadapter,
    localhost,
    duthosts,
    dpuhosts,
    activate_dash_ha_from_json,
    dash_pl_config,
    standby_npu_reboot,
    traffic_to_standby
):
    traffic = "traffic to standby" if traffic_to_standby else "traffic to primary"
    npu_reboot = "standby NPU reboot" if standby_npu_reboot else "primary NPU reboot"
    dpu_id = 0
    encap_proto = "vxlan"
    rate_pps = RATE_PPS
    initial_send_count = INITIAL_SEND_COUNT
    delay = 1.0 / rate_pps
    rcv_outbound_pl_ports = dash_pl_config[0][REMOTE_PTF_RECV_INTF] + dash_pl_config[1][REMOTE_PTF_RECV_INTF]

    if traffic_to_standby:
        vm_to_dpu_pkt, exp_dpu_to_pe_pkt = outbound_pl_packets(dash_pl_config[1], encap_proto)
    else:
        vm_to_dpu_pkt, exp_dpu_to_pe_pkt = outbound_pl_packets(dash_pl_config[0], encap_proto)

    stop_event = threading.Event()
    action_event = threading.Event()
    pool = ThreadPool()
    send_count = 0
    failed_count = 0

    dut = duthosts[1] if standby_npu_reboot else duthosts[0]

    def npu_ha_action():
        # wait for a number of packets to be sent, then simulate failure
        while not stop_event.is_set() and not action_event.is_set():
            time.sleep(0.2)

        if stop_event.is_set():
            return

        logger.info(f"Reboot {dut.hostname}, pkt sent {send_count}")
        reboot_res, _ = reboot_smartswitch(dut, pool)
        logger.info(f"After {dut.hostname} reboot, pkt sent {send_count}, reboot result {reboot_res}")

    t = threading.Thread(target=npu_ha_action, name="npu_ha_action_thread")
    t.start()
    t_max = time.time() + 60
    reached_max_time = False
    ptfadapter.dataplane.flush()
    time.sleep(1)

    while not reached_max_time:
        # After we send initial_send_count packets, awake link_ha_action thread
        if send_count == initial_send_count:
            logger.info("Awake HA action thread")
            action_event.set()

        try:
            if traffic_to_standby:
                if send_count == 0:
                    logger.info("Send first packet to standby")
                testutils.send(ptfadapter, dash_pl_config[1][LOCAL_PTF_INTF], vm_to_dpu_pkt, 1)
                testutils.verify_packet_any_port(ptfadapter, exp_dpu_to_pe_pkt, rcv_outbound_pl_ports)
                if send_count == 0:
                    logger.info("First packet to standby received")
            else:
                if send_count == 0:
                    logger.info("Send first packet to primary")
                testutils.send(ptfadapter, dash_pl_config[0][LOCAL_PTF_INTF], vm_to_dpu_pkt, 1)
                testutils.verify_packet_any_port(ptfadapter, exp_dpu_to_pe_pkt, rcv_outbound_pl_ports)
                if send_count == 0:
                    logger.info("First packet to primary received")
        except Exception as e:
            if failed_count == 0:
                if send_count == 0:
                    logger.error(f"first pkt dropped exception {e}")
                    stop_event.set()
                    pytest.fail(f"HA NPU reboot with {traffic} test error: no packets received")
                else:
                    logger.info(f"first pkt dropped after {send_count} pkts")
            failed_count += 1

        send_count += 1
        time.sleep(delay)
        reached_max_time = time.time() > t_max

    t.join()
    time.sleep(2)

    # wait for NPU and DPU to be up
    dut = duthosts[1] if standby_npu_reboot else duthosts[0]
    wait_for_startup(dut, localhost, delay=10, timeout=600)
    status = wait_until(CHECK_DPU_STATE_TIMEOUT, CHECK_DPU_STATE_TIME_INT, 0,
                        check_dpu_up_state, dut, dpu_id)
    if not status:
        logger.error(f"DPU{dpu_id} not up on {dut.hostname}")

    threshold_loss = THRESHOLD_LOSS_PERCENT
    percentage_loss = (failed_count / send_count) * 100
    if (percentage_loss < threshold_loss):
        logger.info(f"{npu_reboot} with {traffic} test OK. Sent: {send_count},"
                    f" not received: {failed_count}, loss: {percentage_loss}, threshold: {threshold_loss}")
    else:
        pytest.fail(f"{npu_reboot} with {traffic} test error. Sent: {send_count},"
                    f" not received: {failed_count} loss: {percentage_loss}, threshold: {threshold_loss}")
