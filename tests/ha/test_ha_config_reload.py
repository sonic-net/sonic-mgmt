import logging

import ptf.testutils as testutils
import pytest
import time
import threading
import queue
from constants import (
    LOCAL_PTF_INTF,
    REMOTE_PTF_RECV_INTF
)
from packets import outbound_pl_packets
from tests.common.config_reload import config_reload
from tests.ha.conftest import apply_dash_pl_pipeline_config
from tests.common.helpers.assertions import pytest_assert
from ha_dash_flow_utils import compare_flow_tables_pdsctl
from ha_utils import parallel_config_reload_dpuhosts

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
    ensure_vxlan_udp_sport_range,
    setup_npu_dpu  # noqa: F811
):
    if skip_config:
        return

    apply_dash_pl_pipeline_config(localhost, duthosts, dpuhosts, ptfhost)

    yield
    parallel_config_reload_dpuhosts(dpuhosts)


"""
We are testing 4 scenarios:
    1. Traffic to Primary and Primary DUT reboot
    2. Traffic to Primary and Standby DUT reboot
    3. Traffic to Standby and Primary DUT reboot
    4. Traffic to Standby and Standby DUT reboot
    When config is realoaded on standby DUT not traffic loss is expected
    When config is reloaded on primary less than 1% traffic loss is expected
"""


@pytest.mark.parametrize(
    "standby_config_reload", [True, False],
    ids=["Standby Config Reload", "Primary Config Reload"]
)
@pytest.mark.parametrize(
    "traffic_to_standby", [True, False],
    ids=["Standby Traffic", "Primary Traffic"]
)
def test_ha_dut_config_reload(
    localhost,
    ptfadapter,
    duthosts,
    dpuhosts,
    activate_dash_ha_from_json,
    dash_pl_config,
    standby_config_reload,
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

    def config_reload_ha_action():
        # wait for packets sending started, then reload the DUT
        while packet_sending_flag.empty() or (not packet_sending_flag.get()):
            time.sleep(0.2)
        if standby_config_reload:
            logger.info(f"Standby DUT config reload, pkt sent {send_count}")
            config_reload(dpuhosts[1], yang_validate=False)
        else:
            logger.info(f"Primary DUT config reload, pkt sent {send_count}")
            config_reload(dpuhosts[0], yang_validate=False)
        logger.info(f"After config reload, pkt sent {send_count}")

    t = threading.Thread(target=config_reload_ha_action, name="config_reload_ha_action_thread")
    t.start()
    t_max = time.time() + 60
    reached_max_time = False
    ptfadapter.dataplane.flush()
    time.sleep(1)
    while not reached_max_time:
        # After we send initial_send_count packets, awake config_reload_ha_action thread
        if send_count == initial_send_count:
            logger.info("Awake config reload HA action thread")
            packet_sending_flag.put(True)

        try:
            if traffic_to_standby:
                if send_count == 0:
                    logger.info("Send first outbound packet to standby")
                testutils.send(ptfadapter, dash_pl_config[1][LOCAL_PTF_INTF], vm_to_dpu_pkt, 1)
                testutils.verify_packet_any_port(ptfadapter, exp_dpu_to_pe_pkt, rcv_outbound_pl_ports)
                if send_count == 0:
                    logger.info("First packet verified on standby - compare flows")
                    flow_op = compare_flow_tables_pdsctl(dpuhosts[0], dpuhosts[1])
                    pytest_assert(flow_op, "Expected identical flow tables on primary and standby")

            else:
                if send_count == 0:
                    logger.info("Send first outbound packet to primary")
                testutils.send(ptfadapter, dash_pl_config[0][LOCAL_PTF_INTF], vm_to_dpu_pkt, 1)
                testutils.verify_packet_any_port(ptfadapter, exp_dpu_to_pe_pkt, rcv_outbound_pl_ports)
                if send_count == 0:
                    logger.info("First packet verified on primary - compare flows")
                    flow_op = compare_flow_tables_pdsctl(dpuhosts[0], dpuhosts[1])
                    pytest_assert(flow_op, "Expected identical flow tables on primary and standby")
        except Exception as e:
            if failed_count == 0:
                logger.info(f"pkt dropped after {send_count} pkts, exception {e}")
                if send_count == 0:
                    logger.error(f"pkt dropped exception {e}")
                    pytest.fail("HA config reload test error: no packets were received")
            failed_count += 1

        send_count += 1
        time.sleep(delay)
        reached_max_time = time.time() > t_max

    t.join()
    time.sleep(2)
    traffic = "traffic to standby" if traffic_to_standby else "traffic to primary"
    reload_dut = "Standby config reload" if standby_config_reload else "Primary config reload"
    threshold_loss = TRAFFIC_LOSS_THRESHOLD_PERCENTAGE
    percentage_loss = (failed_count / send_count) * 100

    if (percentage_loss < threshold_loss):
        logger.info(f"{reload_dut} with {traffic} test OK. Sent: {send_count},"
                    f" lost: {failed_count}, loss percentage: {percentage_loss}, threshold: {threshold_loss}")
    else:
        pytest.fail(f"{reload_dut} with {traffic} test error. Sent: {send_count},"
                    f" lost: {failed_count} loss percentage: {percentage_loss}, threshold: {threshold_loss}")
