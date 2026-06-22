import logging
import random

import configs.privatelink_config as pl
import ptf.testutils as testutils
import pytest
import time
import threading
import queue
from tests.common.helpers.assertions import pytest_assert
from constants import LOCAL_PTF_INTF, REMOTE_PTF_RECV_INTF
from packets import outbound_pl_packets
from tests.ha.conftest import apply_dash_pl_pipeline_config
from ha_dash_flow_utils import compare_flow_tables, compare_flow_tables_pdsctl
from ha_utils import (
    activate_primary_dash_ha,
    activate_secondary_dash_ha,
    verify_ha_state,
    set_dash_ha_scope,
    set_dead_dash_ha_scope,
    parallel_config_reload_dpuhosts,
)

logger = logging.getLogger(__name__)

# Distinct inner UDP ports used only after standby shutdown to create a new
# flow on the standalone primary and verify it is bulk-synced to the standby.
POST_SHUTDOWN_INNER_SPORT = 50001
POST_SHUTDOWN_INNER_DPORT = 50002

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

    apply_dash_pl_pipeline_config(localhost, duthosts, dpuhosts, ptfhost, floating_nic=True)

    yield

    parallel_config_reload_dpuhosts(dpuhosts)


def test_ha_planned_shutdown(
    ptfadapter,
    localhost,
    duthosts,
    dpuhosts,
    ptfhost,
    activate_dash_ha_from_json,
    ha_owner,
    dash_pl_config,
    primary_vdpu_key,
    standby_vdpu_key
):
    encap_proto = "vxlan"
    rate_pps = 10  # packets per second
    initial_send_count = 10
    delay = 1.0 / rate_pps

    rcv_outbound_pl_ports = dash_pl_config[0][REMOTE_PTF_RECV_INTF] + dash_pl_config[1][REMOTE_PTF_RECV_INTF]

    if ha_owner == "dpu":
        # shutdown active HA Scope is only applicable to DPU-driven HA
        packet_sending_flag = queue.Queue(1)

        def primary_ha_action():
            # wait for packets sending started, then set primary to dead
            while packet_sending_flag.empty() or (not packet_sending_flag.get()):
                time.sleep(0.2)
            logging.info("HA: Set primary to dead")
            set_dead_dash_ha_scope(localhost, duthosts[0], ptfhost, primary_vdpu_key, ha_owner)

        t = threading.Thread(target=primary_ha_action, name="primary_ha_action_thread")
        t.start()
        t_max = time.time() + 60
        # Calculate the delay between packets based on the desired rate
        reached_max_time = False
        ptfadapter.dataplane.flush()
        time.sleep(1)
        send_count = 0
        while not reached_max_time:
            sport = random.randint(49152, 65535)
            dport = random.randint(49152, 65535)
            vm_to_dpu_pkt, exp_dpu_to_pe_pkt = outbound_pl_packets(
                dash_pl_config[0], encap_proto, floating_nic=True,
                inner_sport=sport, inner_dport=dport, vni=pl.ENI_TRUSTED_VNI
            )
            testutils.send(ptfadapter, dash_pl_config[0][LOCAL_PTF_INTF], vm_to_dpu_pkt, 1)
            testutils.verify_packet_any_port(ptfadapter, exp_dpu_to_pe_pkt, rcv_outbound_pl_ports)
            if send_count == 0:
                logger.info("HA: First packet received - compare flows")
                flow_op = compare_flow_tables_pdsctl(dpuhosts[0], dpuhosts[1])
                pytest_assert(flow_op, "Expected identical flow tables on primary and standby")
            send_count += 1
            # After we send initial_send_count packets, awake perform_ha_action thread
            if send_count == initial_send_count:
                logging.info("HA: awake action thread")
                packet_sending_flag.put(True)

            time.sleep(delay)
            reached_max_time = time.time() > t_max

        t.join()
        time.sleep(2)

        pytest_assert(verify_ha_state(duthosts[0], primary_vdpu_key, "dead"),
                      "Primary HA state is not dead")
        pytest_assert(verify_ha_state(duthosts[1], standby_vdpu_key, "standalone"),
                      "Standby HA state is not standalone")

        logging.info(f"HA: Primary shutdown all {send_count} packets received")

        # Re-activate primary
        set_dash_ha_scope(localhost, duthosts[0], ptfhost, primary_vdpu_key, "dead", ha_owner, disabled=True)
        pytest_assert(activate_primary_dash_ha(localhost, duthosts[0], ptfhost, primary_vdpu_key, "activate_role"),
                      "Failed to re-activate HA on primary")

    packet_sending_flag = queue.Queue(1)

    def standby_ha_action():
        # wait for packets sending started, then set standby to dead
        while packet_sending_flag.empty() or (not packet_sending_flag.get()):
            time.sleep(0.2)
        logging.info("HA: Set standby to dead")
        set_dead_dash_ha_scope(localhost, duthosts[1], ptfhost, standby_vdpu_key, ha_owner)

    t = threading.Thread(target=standby_ha_action, name="standby_ha_action_thread")
    t.start()
    t_max = time.time() + 60
    reached_max_time = False
    ptfadapter.dataplane.flush()
    time.sleep(1)
    send_count = 0

    while not reached_max_time:
        sport = random.randint(49152, 65535)
        dport = random.randint(49152, 65535)
        vm_to_dpu_pkt, exp_dpu_to_pe_pkt = outbound_pl_packets(
            dash_pl_config[0], encap_proto, floating_nic=True,
            inner_sport=sport, inner_dport=dport, vni=pl.ENI_TRUSTED_VNI
        )
        testutils.send(ptfadapter, dash_pl_config[0][LOCAL_PTF_INTF], vm_to_dpu_pkt, 1)
        testutils.verify_packet_any_port(ptfadapter, exp_dpu_to_pe_pkt, rcv_outbound_pl_ports)
        if send_count == 0:
            logger.info("HA: First packet received - compare flows")
            flow_op = compare_flow_tables(dpuhosts[0], dpuhosts[1])
            pytest_assert(flow_op, "Expected identical flow tables on primary and standby")
        send_count += 1
        # After we send initial_send_count packets, awake perform_ha_action thread
        if send_count == initial_send_count:
            logging.info("HA: awake action thread")
            packet_sending_flag.put(True)
        time.sleep(delay)
        reached_max_time = time.time() > t_max

    t.join()
    time.sleep(2)

    pytest_assert(verify_ha_state(duthosts[1], standby_vdpu_key, "dead"),
                  "Standby HA state is not dead")
    pytest_assert(verify_ha_state(duthosts[0], primary_vdpu_key, "standalone"),
                  "Primary HA state is not standalone")

    logging.info(f"HA: standby shutdown all {send_count} packets received")

    logger.info(
        "HA: Post-shutdown - send outbound packet with inner_sport=%s then compare flow tables",
        POST_SHUTDOWN_INNER_SPORT,
    )
    ptfadapter.dataplane.flush()
    time.sleep(1)
    vm_post_sd, exp_post_sd = outbound_pl_packets(
        dash_pl_config[0], encap_proto, floating_nic=True,
        inner_sport=POST_SHUTDOWN_INNER_SPORT, inner_dport=POST_SHUTDOWN_INNER_DPORT,
        vni=pl.ENI_TRUSTED_VNI
    )
    testutils.send(ptfadapter, dash_pl_config[0][LOCAL_PTF_INTF], vm_post_sd, 1)
    testutils.verify_packet_any_port(ptfadapter, exp_post_sd, rcv_outbound_pl_ports)

    # Re-activate standby
    set_dash_ha_scope(localhost, duthosts[1], ptfhost, standby_vdpu_key, "dead", ha_owner, disabled=True)
    pytest_assert(activate_secondary_dash_ha(localhost, duthosts[1], ptfhost, standby_vdpu_key, "activate_role",
                                             owner=ha_owner), "Failed to re-activate HA on standby")

    flow_post = compare_flow_tables(
        dpuhosts[0], dpuhosts[1], verbose=True, flow_state=True
    )
    pytest_assert(flow_post, "Expected identical flow tables after launch from standalone (bulk sync)")
