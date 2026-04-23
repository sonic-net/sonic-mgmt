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
from ha_bgp_utils import ha_bgp_shutdown, ha_bgp_start

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t1-smartswitch-ha'),
    pytest.mark.skip_check_dut_health
]

TRAFFIC_LOSS_THRESHOLD_PERCENTAGE = 2.0


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
    1. Traffic to Primary and Primary BGP shut
    2. Traffic to Primary and Standby BGP shut
    3. Traffic to Standby and Primary BGP shut
    4. Traffic to Standby and Standby BGP shut
    When BGP is shut on standby DUT, not traffic loss is expected
    When BGP is shut on primary DUT, less than 1% traffic loss is expected
"""


@pytest.mark.parametrize(
    "bgp_shut_on_standby", [True, False],
    ids=["Standby BGP Shut", "Primary BGP Shut"]
)
@pytest.mark.parametrize(
    "traffic_to_standby", [True, False],
    ids=["Standby Traffic", "Primary Traffic"]
)
def test_ha_bgp_shut(
    localhost,
    ptfadapter,
    duthosts,
    dpuhosts,
    activate_dash_ha_from_json,
    dash_pl_config,
    bgp_shut_on_standby,
    traffic_to_standby
):
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

    def bgp_shut_ha_action():
        # wait for packets sending started, then shut BGP
        while packet_sending_flag.empty() or (not packet_sending_flag.get()):
            time.sleep(0.2)
        if bgp_shut_on_standby:
            logger.info(f"Standby BGP shut, pkt sent {send_count}")
            ha_bgp_shutdown(duthosts[1])
        else:
            logger.info(f"Primary BGP shut, pkt sent {send_count}")
            ha_bgp_shutdown(duthosts[0])
        logger.info(f"After BGP shut, pkt sent {send_count}")

    t = threading.Thread(target=bgp_shut_ha_action, name="bgp_shut_ha_action_thread")
    t.start()
    t_max = time.time() + 60
    reached_max_time = False
    ptfadapter.dataplane.flush()
    time.sleep(1)
    while not reached_max_time:
        # After we send initial_send_count packets, awake bgp_shut_ha_action thread
        if send_count == initial_send_count:
            logger.info("Awake BGP shut HA action thread")
            packet_sending_flag.put(True)

        try:
            if traffic_to_standby:
                if send_count == 0:
                    logger.info("Send first outbound packet to standby")
                testutils.send(ptfadapter, dash_pl_config[1][LOCAL_PTF_INTF], vm_to_dpu_pkt, 1)
                testutils.verify_packet_any_port(ptfadapter, exp_dpu_to_pe_pkt, rcv_outbound_pl_ports)
                if send_count == 0:
                    logger.info("First packet verified on standby")
            else:
                if send_count == 0:
                    logger.info("Send first outbound packet to primary")
                testutils.send(ptfadapter, dash_pl_config[0][LOCAL_PTF_INTF], vm_to_dpu_pkt, 1)
                testutils.verify_packet_any_port(ptfadapter, exp_dpu_to_pe_pkt, rcv_outbound_pl_ports)
                if send_count == 0:
                    logger.info("First packet verified on primary")
        except Exception as e:
            if failed_count == 0:
                logger.info(f"pkt dropped after {send_count} pkts, exception {e}")
                if send_count == 0:
                    logger.error(f"pkt dropped exception {e}")
                    pytest.fail("HA BGP shut test error: no packets were received")
            failed_count += 1

        send_count += 1
        time.sleep(delay)
        reached_max_time = time.time() > t_max

    t.join()
    time.sleep(2)
    traffic = "traffic to standby" if traffic_to_standby else "traffic to primary"
    bgp_shut = "Standby BGP shut" if traffic_to_standby else "Primary BGP shut"
    threshold_loss = TRAFFIC_LOSS_THRESHOLD_PERCENTAGE
    percentage_loss = (failed_count / send_count) * 100
    if bgp_shut_on_standby:
        ha_bgp_start(duthosts[1])
    else:
        ha_bgp_start(duthosts[0])

    if (percentage_loss < threshold_loss):
        logger.info(f"{bgp_shut} with {traffic} test passed. Sent: {send_count},"
                    f" lost: {failed_count}, percentage loss: {percentage_loss}, threshold: {threshold_loss}")
    else:
        pytest.fail(f"{bgp_shut} with {traffic} test failed. Sent: {send_count},"
                    f" lost: {failed_count} percentage loss: {percentage_loss}, threshold: {threshold_loss}")
