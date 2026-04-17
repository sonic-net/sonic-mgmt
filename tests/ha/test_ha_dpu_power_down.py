import logging

import configs.privatelink_config as pl
import ptf.testutils as testutils
import pytest
import time
import threading
import concurrent.futures
from constants import (
    LOCAL_PTF_INTF,
    REMOTE_PTF_RECV_INTF
)
from gnmi_utils import apply_messages
from packets import outbound_pl_packets
from tests.common.helpers.assertions import pytest_assert
from tests.common.config_reload import config_reload
from ha_dpu_utils import dpu_power_off_for_index, dpu_power_on_for_index

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
    1. Traffic to Primary and Primary DPU failure
    2. Traffic to Primary and Standby DPU failure
    3. Traffic to Standby and Primary DPU Failure
    4. Traffic to Standby and Standby DPU Failure
    DPU failure on standby: no traffic loss expected
    DPU failure on primary: less than a specified percentage traffic loss expected
"""


@pytest.mark.parametrize(
    "traffic_to_standby", [True, False],
    ids=["Standby Traffic", "Primary Traffic"]
)
@pytest.mark.parametrize(
    "standby_dpu_fail", [True, False],
    ids=["Standby DPU Fail", "Primary DPU Fail"]
)
def test_ha_dpu_failure(
    ptfadapter,
    duthosts,
    dpuhosts,
    activate_dash_ha_from_json,
    dash_pl_config,
    standby_dpu_fail,
    traffic_to_standby
):
    traffic = "traffic to standby" if traffic_to_standby else "traffic to primary"
    dpu_shut = "Standby DPU shut" if standby_dpu_fail else "Primary DPU shut"
    encap_proto = "vxlan"
    dpu_id = 0
    rate_pps = RATE_PPS
    initial_send_count = INITIAL_SEND_COUNT
    delay = 1.0 / rate_pps
    rcv_outbound_pl_ports = dash_pl_config[0][REMOTE_PTF_RECV_INTF] + dash_pl_config[1][REMOTE_PTF_RECV_INTF]

    if traffic_to_standby:
        vm_to_dpu_pkt, exp_dpu_to_pe_pkt = outbound_pl_packets(dash_pl_config[1], encap_proto)
    else:
        vm_to_dpu_pkt, exp_dpu_to_pe_pkt = outbound_pl_packets(dash_pl_config[0], encap_proto)

    send_count = 0
    failed_count = 0

    shutdown_event = threading.Event()
    start_action = threading.Event()

    def dpu_ha_action():
        # wait for a number of packets to be sent, then simulate failure
        while not shutdown_event.is_set() and not start_action.is_set():
            time.sleep(0.2)

        if shutdown_event.is_set():
            return

        if standby_dpu_fail:
            logger.info(f"Simulate standby DPU failure, pkt sent {send_count}")
            dpu_power_off_for_index(duthosts[1], dpu_id)
        else:
            logger.info(f"Simulate primary DPU failure, pkt sent {send_count}")
            dpu_power_off_for_index(duthosts[0], dpu_id)
        logger.info(f"After DPU failure, pkt sent {send_count}")

    t = threading.Thread(target=dpu_ha_action, name="dpu_ha_action_thread")
    t.start()
    t_max = time.time() + 60
    reached_max_time = False
    ptfadapter.dataplane.flush()
    time.sleep(1)

    while not reached_max_time:
        # After we send initial_send_count packets, awake ha_action thread
        if send_count == initial_send_count:
            logger.info(f"Awake HA action thread after {send_count} packets")
            start_action.set()

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
                    # terminate action thread since test failed
                    shutdown_event.set()
                    pytest.fail(f"HA DPU reboot with {traffic} test error: no packets received")
                else:
                    logger.info(f"first pkt dropped after {send_count} pkts")
            failed_count += 1

        send_count += 1
        time.sleep(delay)
        reached_max_time = time.time() > t_max

    t.join()
    time.sleep(2)
    # bring back up the DPU
    dut = duthosts[1] if standby_dpu_fail else duthosts[0]
    dpu_name = f"DPU{dpu_id}"
    logger.info(f"Startup {dpu_name} on {dut.hostname}")
    pytest_assert(dpu_power_on_for_index(dut, dpu_id), f"Failed to bring up {dpu_name} on {dut.hostname}")

    threshold_loss = THRESHOLD_LOSS_PERCENT
    percentage_loss = (failed_count / send_count) * 100
    if (percentage_loss < threshold_loss):
        logger.info(f"{dpu_shut} with {traffic} test OK. Sent: {send_count},"
                    f" not received: {failed_count}, loss: {percentage_loss}, threshold: {threshold_loss}")
    else:
        pytest.fail(f"{dpu_shut} with {traffic} test error. Sent: {send_count},"
                    f" not received: {failed_count} loss: {percentage_loss}, threshold: {threshold_loss}")
