import logging
from multiprocessing.pool import ThreadPool

import configs.privatelink_config as pl
import ptf.testutils as testutils
import pytest
import time
import threading
from constants import (
    LOCAL_DUT_INTF,
    LOCAL_PTF_INTF,
    REMOTE_DUT_INTF,
    REMOTE_PTF_RECV_INTF
)
from gnmi_utils import (
    apply_gnmi_cert,
    generate_gnmi_cert,
    recover_gnmi_cert
)
from packets import outbound_pl_packets
from tests.common.utilities import wait_until
from tests.ha.conftest import apply_dash_pl_pipeline_config
from tests.common.helpers.assertions import pytest_assert, pytest_require as pt_require
from tests.common.platform.processes_utils import wait_critical_processes
from ha_dash_flow_utils import compare_flow_tables
from tests.common.reboot import reboot_smartswitch, wait_for_startup
from tests.ha.conftest import get_interface_ip
from tests.ha.ha_dpu_utils import CHECK_DPU_STATE_TIMEOUT, CHECK_DPU_STATE_TIME_INT, check_dpu_up_state
from ha_utils import parallel_config_reload_dpuhosts


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t1-smartswitch-ha'),
    pytest.mark.skip_check_dut_health
]


THRESHOLD_LOSS_PERCENT = 2.0
RATE_PPS = 20
INITIAL_SEND_COUNT = 100


@pytest.fixture(scope="function")
def setup_gnmi_server(duthosts, localhost, ptfhost, skip_cert_cleanup):
    for duthost in duthosts:
        wait_for_startup(duthost, localhost, delay=10, timeout=600)
        wait_critical_processes(duthost)
        generate_gnmi_cert(localhost, duthost)
        apply_gnmi_cert(duthost, ptfhost)
    yield
    for duthost in duthosts:
        wait_for_startup(duthost, localhost, delay=10, timeout=600)
        wait_critical_processes(duthost)
        recover_gnmi_cert(localhost, duthost, skip_cert_cleanup)


@pytest.fixture(scope="function")
def add_npu_static_routes(
    duthosts, localhost, dash_pl_config, skip_config, skip_cleanup, dpu_index
):
    if not skip_config:
        for i in range(len(duthosts)):
            duthost = duthosts[i]
            wait_for_startup(duthost, localhost, delay=10, timeout=600)
            wait_critical_processes(duthost)

            cmds = []
            vm_nexthop_ip = get_interface_ip(duthost, dash_pl_config[i][LOCAL_DUT_INTF]).ip + 1
            pe_nexthop_ip = get_interface_ip(duthost, dash_pl_config[i][REMOTE_DUT_INTF]).ip + 1

            pt_require(vm_nexthop_ip, "VM nexthop interface does not have an IP address")
            pt_require(pe_nexthop_ip, "PE nexthop interface does not have an IP address")

            cmds.append(f"config route add prefix {pl.VM1_PA}/32 nexthop {vm_nexthop_ip}")
            cmds.append(f"config route add prefix {pl.PE_PA}/32 nexthop {pe_nexthop_ip}")
            logger.info(f"Adding function-scoped static routes: {cmds} on {duthost}")
            duthost.shell_cmds(cmds=cmds)

    yield

    if not skip_config and not skip_cleanup:
        for i in range(len(duthosts)):
            duthost = duthosts[i]
            wait_for_startup(duthost, localhost, delay=10, timeout=600)
            wait_critical_processes(duthost)

            cmds = []
            vm_nexthop_ip = get_interface_ip(duthost, dash_pl_config[i][LOCAL_DUT_INTF]).ip + 1
            pe_nexthop_ip = get_interface_ip(duthost, dash_pl_config[i][REMOTE_DUT_INTF]).ip + 1

            cmds.append(f"config route del prefix {pl.VM1_PA}/32 nexthop {vm_nexthop_ip}")
            cmds.append(f"config route del prefix {pl.PE_PA}/32 nexthop {pe_nexthop_ip}")
            logger.info(f"Removing function-scoped static routes: {cmds} from {duthost}")
            duthost.shell_cmds(cmds=cmds, continue_on_fail=True, module_ignore_errors=True)


@pytest.fixture(scope="function")
def setup_npu_dpu(dpu_setup, setup_gnmi_server, add_npu_static_routes):
    yield


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
                    logger.info("First packet to standby received - compare flows")
                    flow_op = compare_flow_tables(dpuhosts[0], dpuhosts[1])
                    pytest_assert(flow_op, "Expected identical flow tables on primary and standby")

            else:
                if send_count == 0:
                    logger.info("Send first packet to primary")
                testutils.send(ptfadapter, dash_pl_config[0][LOCAL_PTF_INTF], vm_to_dpu_pkt, 1)
                testutils.verify_packet_any_port(ptfadapter, exp_dpu_to_pe_pkt, rcv_outbound_pl_ports)
                if send_count == 0:
                    logger.info("First packet to primary received - compare flows")
                    flow_op = compare_flow_tables(dpuhosts[0], dpuhosts[1])
                    pytest_assert(flow_op, "Expected identical flow tables on primary and standby")
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
