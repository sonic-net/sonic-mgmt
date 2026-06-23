import logging

import ptf.testutils as testutils
import pytest
import time
import threading
from constants import (
    LOCAL_PTF_INTF,
    REMOTE_PTF_RECV_INTF,
    REMOTE_PTF_SEND_INTF,
    NPU_DATAPLANE_PORT
)
from packets import outbound_pl_packets, inbound_pl_packets
from tests.common.helpers.assertions import pytest_assert
from tests.ha.conftest import apply_dash_pl_pipeline_config
from ha_dash_flow_utils import compare_flow_tables
from ha_utils import set_dash_ha_scope, activate_secondary_dash_ha, verify_ha_state
from ha_link_utils import (
    add_acl_link_drop,
    remove_acl_link_drop_table,
    shutdown_dpu_dataplane_port,
    startup_dpu_dataplane_port
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t1-smartswitch-ha'),
    pytest.mark.skip_check_dut_health
]

TRAFFIC_LOSS_DURATION = 2.0  # Up to 2s of allowable loss during link failure.
RATE_PPS = 20  # packets per second


def restore_ha_state(localhost, ptfhost, duthost, standby_vdpu_key="vdpu1_0:haset0_0", ha_owner="switch"):
    try:
        set_dash_ha_scope(localhost, duthost, ptfhost, standby_vdpu_key, "dead", ha_owner)
        activate_secondary_dash_ha(localhost, duthost, ptfhost, standby_vdpu_key, "activate_role", ha_owner)
    except Exception as e:
        logger.error(f"HA state restoration on {duthost.hostname} exception: {e}")


@pytest.fixture(autouse=True, scope="module")
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

    apply_dash_pl_pipeline_config(localhost, duthosts, dpuhosts, ptfhost)

    yield


"""
We are testing 4 scenarios:
    1. Traffic to Primary and Primary Link failure
    2. Traffic to Primary and Standby Link failure
    3. Traffic to Standby and Primary Link Failure
    4. Traffic to Standby and Standby Link Failure
    When link failure is on standby not traffic loss should be observed
    When link failure is on primary less than 1% traffic loss should be observed
"""


@pytest.mark.parametrize(
    "standby_link_fail", [True, False],
    ids=["Standby_Link_Fail", "Primary_Link_Fail"]
)
@pytest.mark.parametrize(
    "traffic_to_standby", [True, False],
    ids=["Standby_Traffic", "Primary_Traffic"]
)
def test_ha_link_failure(
    ptfadapter,
    localhost,
    duthosts,
    dpuhosts,
    ptfhost,
    activate_dash_ha_from_json,
    dash_pl_config,
    standby_link_fail,
    traffic_to_standby,
    primary_vdpu_key,
    standby_vdpu_key,
    ha_owner
):
    encap_proto = "vxlan"
    initial_send_count = 100
    delay = 1.0 / RATE_PPS
    rcv_outbound_pl_ports = dash_pl_config[0][REMOTE_PTF_RECV_INTF] + dash_pl_config[1][REMOTE_PTF_RECV_INTF]

    if traffic_to_standby:
        vm_to_dpu_pkt, exp_dpu_to_pe_pkt = outbound_pl_packets(dash_pl_config[1], encap_proto)
        pe_to_dpu_pkt, exp_dpu_to_vm_pkt = inbound_pl_packets(dash_pl_config[1])
    else:
        vm_to_dpu_pkt, exp_dpu_to_pe_pkt = outbound_pl_packets(dash_pl_config[0], encap_proto)
        pe_to_dpu_pkt, exp_dpu_to_vm_pkt = inbound_pl_packets(dash_pl_config[0])

    _, exp_dpu_to_vm_pkt_standby = inbound_pl_packets(dash_pl_config[1])
    packet_sending_event = threading.Event()
    stop_link_action_event = threading.Event()

    send_count = 0
    failed_count = 0

    def link_ha_action():
        # wait for packets sending started, then simulate link failure
        while not packet_sending_event.is_set():
            if stop_link_action_event.wait(0.2):
                return
        if standby_link_fail:
            logger.info(f"Simulate standby link failure, pkt sent {send_count}")
            remove_acl_link_drop_table(duthosts[1])
            add_acl_link_drop(duthosts[1], dash_pl_config[1][NPU_DATAPLANE_PORT])
        else:
            logger.info(f"Simulate primary link failure, pkt sent {send_count}")
            remove_acl_link_drop_table(duthosts[0])
            add_acl_link_drop(duthosts[0], dash_pl_config[0][NPU_DATAPLANE_PORT])
        logger.info(f"After link failure, pkt sent {send_count}")

    t = threading.Thread(target=link_ha_action, name="link_ha_action_thread")
    t.start()
    t_max = time.time() + 60
    reached_max_time = False
    ptfadapter.dataplane.flush()
    time.sleep(1)
    rcv_inbound_pl_ports = [dash_pl_config[0][LOCAL_PTF_INTF], dash_pl_config[1][LOCAL_PTF_INTF]]
    while not reached_max_time:
        # After we send initial_send_count packets, awake link_ha_action thread
        if send_count == initial_send_count:
            logger.info("Awake link failure HA action thread")
            packet_sending_event.set()

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
                    logger.info(f"inbound pkt dropped: {e}")
                    failed_count += 1
                if send_count == 0:
                    logger.info("First packets verified to standby - compare flows")
                    flow_op = compare_flow_tables(dpuhosts[0], dpuhosts[1])
                    pytest_assert(flow_op, "Expected identical flow tables on primary and standby")

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
                    logger.warning(f"inbound pkt dropped: {e}")
                    failed_count += 1
        except Exception as e:
            logger.info(f"outbound pkt dropped after {send_count} pkts, exception {e}")
            if send_count == 0:
                logger.error(f"pkt dropped exception {e}")
                pytest.fail("HA link fail test error: no packets were received")
            failed_count += 1

        send_count += 1
        time.sleep(delay)
        reached_max_time = time.time() > t_max

    stop_link_action_event.set()
    t.join(timeout=5)
    pytest_assert(not t.is_alive(), "link_ha_action thread did not exit in time")

    if send_count < initial_send_count:
        pytest.fail(
            f"HA link fail test error: sent only {send_count} packets in test window, "
            f"requires at least {initial_send_count} to trigger link failure action"
        )

    time.sleep(2)
    if standby_link_fail:
        remove_acl_link_drop_table(duthosts[1])
    else:
        remove_acl_link_drop_table(duthosts[0])
    # take system out of split-brain
    pytest_assert(verify_ha_state(duthosts[0], primary_vdpu_key, "standalone"),
                  "Primary HA state is not standalone")
    restore_ha_state(localhost, ptfhost, duthosts[1], standby_vdpu_key=standby_vdpu_key, ha_owner=ha_owner)

    traffic = "traffic to standby" if traffic_to_standby else "traffic to primary"
    link_fail = "Standby link fail" if standby_link_fail else "Primary link fail"
    if standby_link_fail:
        if failed_count > 0:
            pytest.fail(f"{link_fail} with {traffic} test error:"
                        f"{failed_count} packets not received  {send_count} packets sent.")
        else:
            logger.info(f"{link_fail} with {traffic} test OK. All {send_count} packets sent were received.")
    else:
        threshold_loss = RATE_PPS * TRAFFIC_LOSS_DURATION
        percentage_loss = (failed_count / send_count) * 100
        if (failed_count < threshold_loss):
            logger.info(f"{link_fail} with {traffic} test OK. Sent: {send_count},"
                        f" not received: {failed_count}, loss: {percentage_loss}, threshold: {threshold_loss}")
        else:
            pytest.fail(f"{link_fail} with {traffic} test error. Sent: {send_count},"
                        f" not received: {failed_count} loss: {percentage_loss}, threshold: {threshold_loss}")


@pytest.mark.parametrize(
    "standby_link_fail", [True, False],
    ids=["Standby_Link_Fail", "Primary_Link_Fail"]
)
@pytest.mark.parametrize(
    "traffic_to_standby", [True, False],
    ids=["Standby_Traffic", "Primary_Traffic"]
)
def test_ha_link_down(
    ptfadapter,
    localhost,
    duthosts,
    dpuhosts,
    ptfhost,
    activate_dash_ha_from_json,
    dash_pl_config,
    standby_link_fail,
    traffic_to_standby,
    primary_vdpu_key,
    standby_vdpu_key,
    ha_owner
):
    encap_proto = "vxlan"
    initial_send_count = 100
    delay = 1.0 / RATE_PPS
    rcv_outbound_pl_ports = dash_pl_config[0][REMOTE_PTF_RECV_INTF] + dash_pl_config[1][REMOTE_PTF_RECV_INTF]

    if traffic_to_standby:
        vm_to_dpu_pkt, exp_dpu_to_pe_pkt = outbound_pl_packets(dash_pl_config[1], encap_proto)
        pe_to_dpu_pkt, exp_dpu_to_vm_pkt = inbound_pl_packets(dash_pl_config[1])
    else:
        vm_to_dpu_pkt, exp_dpu_to_pe_pkt = outbound_pl_packets(dash_pl_config[0], encap_proto)
        pe_to_dpu_pkt, exp_dpu_to_vm_pkt = inbound_pl_packets(dash_pl_config[0])

    _, exp_dpu_to_vm_pkt_standby = inbound_pl_packets(dash_pl_config[1])
    packet_sending_event = threading.Event()
    stop_link_action_event = threading.Event()

    send_count = 0
    failed_count = 0

    def link_ha_action():
        # wait for packets sending started, then shut down the DPU dataplane interface
        while not packet_sending_event.is_set():
            if stop_link_action_event.wait(0.2):
                return
        if standby_link_fail:
            logger.info(f"Shut down standby DPU dataplane interface, pkt sent {send_count}")
            shutdown_dpu_dataplane_port(dpuhosts[1])
        else:
            logger.info(f"Shut down primary DPU dataplane interface, pkt sent {send_count}")
            shutdown_dpu_dataplane_port(dpuhosts[0])
        logger.info(f"After DPU dataplane interface down, pkt sent {send_count}")

    t = threading.Thread(target=link_ha_action, name="link_ha_action_thread")
    t.start()
    t_max = time.time() + 60
    reached_max_time = False
    ptfadapter.dataplane.flush()
    time.sleep(1)
    rcv_inbound_pl_ports = [dash_pl_config[0][LOCAL_PTF_INTF], dash_pl_config[1][LOCAL_PTF_INTF]]
    while not reached_max_time:
        # After we send initial_send_count packets, awake link_ha_action thread
        if send_count == initial_send_count:
            logger.info("Awake link down HA action thread")
            packet_sending_event.set()

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
                    logger.info(f"inbound pkt dropped: {e}")
                    failed_count += 1
                if send_count == 0:
                    logger.info("First packets verified to standby - compare flows")
                    flow_op = compare_flow_tables(dpuhosts[0], dpuhosts[1])
                    pytest_assert(flow_op, "Expected identical flow tables on primary and standby")

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
                    logger.warning(f"inbound pkt dropped: {e}")
                    failed_count += 1
        except Exception as e:
            logger.info(f"outbound pkt dropped after {send_count} pkts, exception {e}")
            if send_count == 0:
                logger.error(f"pkt dropped exception {e}")
                pytest.fail("HA link down test error: no packets were received")
            failed_count += 1

        send_count += 1
        time.sleep(delay)
        reached_max_time = time.time() > t_max

    stop_link_action_event.set()
    t.join(timeout=5)
    pytest_assert(not t.is_alive(), "link_ha_action thread did not exit in time")

    if send_count < initial_send_count:
        pytest.fail(
            f"HA link down test error: sent only {send_count} packets in test window, "
            f"requires at least {initial_send_count} to trigger link down action"
        )

    time.sleep(2)
    if standby_link_fail:
        startup_dpu_dataplane_port(dpuhosts[1])
    else:
        startup_dpu_dataplane_port(dpuhosts[0])
    # take system out of split-brain
    pytest_assert(verify_ha_state(duthosts[0], primary_vdpu_key, "standalone"),
                  "Primary HA state is not standalone")
    restore_ha_state(localhost, ptfhost, duthosts[1], standby_vdpu_key=standby_vdpu_key, ha_owner=ha_owner)

    traffic = "traffic to standby" if traffic_to_standby else "traffic to primary"
    link_fail = "Standby link down" if standby_link_fail else "Primary link down"
    if standby_link_fail:
        if failed_count > 0:
            pytest.fail(f"{link_fail} with {traffic} test error:"
                        f"{failed_count} packets not received  {send_count} packets sent.")
        else:
            logger.info(f"{link_fail} with {traffic} test OK. All {send_count} packets sent were received.")
    else:
        threshold_loss = RATE_PPS * TRAFFIC_LOSS_DURATION
        percentage_loss = (failed_count / send_count) * 100
        if (failed_count < threshold_loss):
            logger.info(f"{link_fail} with {traffic} test OK. Sent: {send_count},"
                        f" not received: {failed_count}, loss: {percentage_loss}, threshold: {threshold_loss}")
        else:
            pytest.fail(f"{link_fail} with {traffic} test error. Sent: {send_count},"
                        f" not received: {failed_count} loss: {percentage_loss}, threshold: {threshold_loss}")
