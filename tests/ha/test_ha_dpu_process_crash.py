"""
HA DPU Critical Process Crash Tests

Verifies HA behavior when critical processes crash on DPUs in the
t1-smartswitch-ha topology.

For each DPU process under test (syncd, bgp) there are 4 variations:
    1. Crash on primary DPU,  traffic landing on primary DPU
    2. Crash on primary DPU,  traffic landing on standby DPU
    3. Crash on standby DPU, traffic landing on primary DPU
    4. Crash on standby DPU, traffic landing on standby DPU

Expected Control Plane : HA state converges eventually.
Expected Data Plane    : T2 receives packets with allowed disruption.

Traffic runs continuously in a background thread so that data-plane
impact is measured *during* the crash, not just before/after.
"""

import logging
import time
import threading

import ptf.testutils as testutils
import pytest

from constants import LOCAL_PTF_INTF, REMOTE_PTF_RECV_INTF
from packets import outbound_pl_packets
from tests.common.utilities import wait_until, InterruptableThread
from tests.ha.ha_utils import verify_ha_state

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("t1-smartswitch-ha"),
    pytest.mark.skip_check_dut_health,
]

PROCESS_RECOVERY_TIMEOUT = 120
HA_CONVERGENCE_TIMEOUT = 180
HA_CHECK_INTERVAL = 5
TRAFFIC_SEND_INTERVAL = 0.1
PL_VERIFY_TIMEOUT = 10

MAX_TRAFFIC_LOSS_PCT = 5.0

DPU_CRITICAL_PROCESSES = [
    pytest.param("syncd", "syncd", id="syncd"),
    pytest.param("bgpd", "bgp", id="bgp"),
]


def kill_process_on_dpu(dpuhost, process_name, container):
    cmd = f"docker exec {container} pkill -9 {process_name} || true"
    logger.info(f"{dpuhost.hostname}: killing '{process_name}' in {container}")
    dpuhost.shell(cmd)


def wait_for_process_recovery(host, process_name, container,
                              timeout=PROCESS_RECOVERY_TIMEOUT):
    def _is_running():
        result = host.shell(
            f"docker exec {container} pgrep {process_name} || true"
        )
        return bool(result["stdout"].strip())

    logger.info(
        f"{host.hostname}: waiting for '{process_name}' recovery in {container}"
    )
    return wait_until(timeout, HA_CHECK_INTERVAL, 0, _is_running)


def verify_ha_state_converged(duthost, scope_key, expected_state):
    assert verify_ha_state(
        duthost,
        scope_key=scope_key,
        expected_state=expected_state,
        timeout=HA_CONVERGENCE_TIMEOUT,
        interval=HA_CHECK_INTERVAL,
    ), (
        f"{duthost.hostname}: HA scope '{scope_key}' did not reach "
        f"'{expected_state}' within {HA_CONVERGENCE_TIMEOUT}s"
    )
    logger.info(
        f"{duthost.hostname}: HA scope '{scope_key}' reached '{expected_state}'"
    )


def all_recv_ports(dash_pl_config):
    """Combine REMOTE_PTF_RECV_INTF from both DUTs so post-switchover
    packets exiting the peer are also counted."""
    ports = list(dash_pl_config[0][REMOTE_PTF_RECV_INTF])
    for p in dash_pl_config[1][REMOTE_PTF_RECV_INTF]:
        if p not in ports:
            ports.append(p)
    return ports


def send_continuous_pl_traffic(ptfadapter, send_config, recv_ports,
                               stop_event, results):
    sent = 0
    received = 0
    send_pkt, exp_pkt = outbound_pl_packets(send_config, "vxlan")
    while not stop_event.is_set():
        try:
            testutils.send(
                ptfadapter, send_config[LOCAL_PTF_INTF], send_pkt, count=1
            )
            sent += 1
            try:
                testutils.verify_packet_any_port(
                    ptfadapter, exp_pkt, recv_ports, timeout=1,
                )
                received += 1
            except AssertionError:
                # Packet not received; counted as loss for traffic stats
                pass
        except Exception as e:
            logger.debug(f"Traffic sender: {e}")
        time.sleep(TRAFFIC_SEND_INTERVAL)
    results["sent"] = sent
    results["received"] = received


@pytest.fixture(scope="module")
def primary_dut(duthosts):
    return duthosts[0]


@pytest.fixture(scope="module")
def standby_dut(duthosts):
    return duthosts[1]


@pytest.fixture(scope="module")
def primary_dpuhost(dpuhosts):
    return dpuhosts[0]


@pytest.fixture(scope="module")
def standby_dpuhost(dpuhosts):
    return dpuhosts[1]


class TestDpuProcessCrash:

    def _run(
        self, process_name, container,
        crash_dpuhost, crash_duthost, crash_scope_key,
        expected_ha_state_after_crash,
        verify_duthost, verify_scope_key, expected_ha_state_verify,
        ptfadapter, dash_pl_config, traffic_dut_index,
    ):
        pl_config = dash_pl_config[traffic_dut_index]
        recv_ports = all_recv_ports(dash_pl_config)

        logger.info(
            f"=== DPU {process_name} crash on {crash_dpuhost.hostname} "
            f"(scope: {crash_scope_key}) ==="
        )

        send_pkt, exp_pkt = outbound_pl_packets(pl_config, "vxlan")
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, pl_config[LOCAL_PTF_INTF], send_pkt, count=1)
        testutils.verify_packet_any_port(
            ptfadapter, exp_pkt, recv_ports, timeout=PL_VERIFY_TIMEOUT,
        )
        logger.info("Baseline PL traffic verified")

        stop_event = threading.Event()
        traffic_results = {}
        traffic_thread = InterruptableThread(
            target=send_continuous_pl_traffic,
            args=(ptfadapter, pl_config, recv_ports,
                  stop_event, traffic_results),
        )
        traffic_thread.start()
        time.sleep(2)

        try:
            kill_process_on_dpu(crash_dpuhost, process_name, container)

            verify_ha_state_converged(
                crash_duthost, crash_scope_key, expected_ha_state_after_crash
            )
            verify_ha_state_converged(
                verify_duthost, verify_scope_key, expected_ha_state_verify
            )

            recovered = wait_for_process_recovery(
                crash_dpuhost, process_name, container
            )
            assert recovered, (
                f"{process_name} did not recover on {crash_dpuhost.hostname} "
                f"within {PROCESS_RECOVERY_TIMEOUT}s"
            )
            logger.info(f"{process_name} recovered")
        finally:
            stop_event.set()
            traffic_thread.join(timeout=30)

        sent = traffic_results.get("sent", 0)
        received = traffic_results.get("received", 0)
        loss_pct = 100 * (sent - received) / max(sent, 1)
        logger.info(
            f"Traffic: sent={sent} received={received} "
            f"loss={sent - received} ({loss_pct:.1f}%)"
        )
        assert loss_pct <= MAX_TRAFFIC_LOSS_PCT, (
            f"Traffic loss {loss_pct:.1f}% exceeds threshold "
            f"{MAX_TRAFFIC_LOSS_PCT}%  (sent={sent} received={received})"
        )

    @pytest.mark.parametrize("process_name,container", DPU_CRITICAL_PROCESSES)
    def test_crash_active_dpu_traffic_on_active(
        self, process_name, container,
        primary_dut, standby_dut, primary_dpuhost,
        setup_ha_config, setup_gnmi_server, setup_dash_pl_pipeline,
        ptfadapter, dash_pl_config,
        activate_dash_ha_from_json,
        primary_vdpu_key,
        standby_vdpu_key
    ):
        self._run(
            process_name=process_name, container=container,
            crash_dpuhost=primary_dpuhost, crash_duthost=primary_dut,
            crash_scope_key=primary_vdpu_key,
            expected_ha_state_after_crash="active",
            verify_duthost=standby_dut,
            verify_scope_key=standby_vdpu_key,
            expected_ha_state_verify="active",
            ptfadapter=ptfadapter, dash_pl_config=dash_pl_config,
            traffic_dut_index=0,
        )

    @pytest.mark.parametrize("process_name,container", DPU_CRITICAL_PROCESSES)
    def test_crash_active_dpu_traffic_on_standby(
        self, process_name, container,
        primary_dut, standby_dut, primary_dpuhost, primary_vdpu_key, standby_vdpu_key,
        setup_ha_config, setup_gnmi_server, setup_dash_pl_pipeline,
        ptfadapter, dash_pl_config,
        activate_dash_ha_from_json,
    ):
        self._run(
            process_name=process_name, container=container,
            crash_dpuhost=primary_dpuhost, crash_duthost=primary_dut,
            crash_scope_key=primary_vdpu_key,
            expected_ha_state_after_crash="active",
            verify_duthost=standby_dut,
            verify_scope_key=standby_vdpu_key,
            expected_ha_state_verify="active",
            ptfadapter=ptfadapter, dash_pl_config=dash_pl_config,
            traffic_dut_index=1,
        )

    @pytest.mark.parametrize("process_name,container", DPU_CRITICAL_PROCESSES)
    def test_crash_standby_dpu_traffic_on_active(
        self, process_name, container,
        primary_dut, standby_dut, standby_dpuhost, primary_vdpu_key, standby_vdpu_key,
        setup_ha_config, setup_gnmi_server, setup_dash_pl_pipeline,
        ptfadapter, dash_pl_config,
        activate_dash_ha_from_json,
    ):
        self._run(
            process_name=process_name, container=container,
            crash_dpuhost=standby_dpuhost, crash_duthost=standby_dut,
            crash_scope_key=standby_vdpu_key,
            expected_ha_state_after_crash="active",
            verify_duthost=primary_dut,
            verify_scope_key=primary_vdpu_key,
            expected_ha_state_verify="active",
            ptfadapter=ptfadapter, dash_pl_config=dash_pl_config,
            traffic_dut_index=0,
        )

    @pytest.mark.parametrize("process_name,container", DPU_CRITICAL_PROCESSES)
    def test_crash_standby_dpu_traffic_on_standby(
        self, process_name, container,
        primary_dut, standby_dut, standby_dpuhost, primary_vdpu_key, standby_vdpu_key,
        setup_ha_config, setup_gnmi_server, setup_dash_pl_pipeline,
        ptfadapter, dash_pl_config,
        activate_dash_ha_from_json,
    ):
        self._run(
            process_name=process_name, container=container,
            crash_dpuhost=standby_dpuhost, crash_duthost=standby_dut,
            crash_scope_key=standby_vdpu_key,
            expected_ha_state_after_crash="active",
            verify_duthost=primary_dut,
            verify_scope_key=primary_vdpu_key,
            expected_ha_state_verify="active",
            ptfadapter=ptfadapter, dash_pl_config=dash_pl_config,
            traffic_dut_index=1,
        )
