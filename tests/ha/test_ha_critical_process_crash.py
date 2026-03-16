"""
Module 6: HA Critical Process Crash Tests

Verifies HA behavior when critical processes crash on DPUs in the
t1-smartswitch-ha topology.

For each process under test there are 4 variations:
    1. Crash on active DPU,  traffic landing on active DPU
    2. Crash on active DPU,  traffic landing on standby DPU
    3. Crash on standby DPU, traffic landing on active DPU
    4. Crash on standby DPU, traffic landing on standby DPU

Expected Control Plane : HA state converges eventually.
Expected Data Plane    : T2 receives packets with allowed disruption.

Traffic runs continuously in a background thread so that data-plane
impact is measured *during* the crash, not just before/after.

Uses existing packet generation from packets.py and PL config from
configs/privatelink_config.py (already merged in PR #22161).
"""

import logging
import time
import threading

import ptf.testutils as testutils
import pytest

from constants import LOCAL_PTF_INTF, REMOTE_PTF_RECV_INTF
from packets import outbound_pl_packets
from tests.common.utilities import wait_until, InterruptableThread
from tests.ha.ha_utils import wait_for_ha_state

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("t1-smartswitch-ha"),
    pytest.mark.skip_check_dut_health,
]

###############################################################################
# Constants
###############################################################################

PROCESS_RECOVERY_TIMEOUT = 120
HA_CONVERGENCE_TIMEOUT = 180
HA_CHECK_INTERVAL = 5
TRAFFIC_SEND_INTERVAL = 0.1
PL_VERIFY_TIMEOUT = 10

ACTIVE_SCOPE_KEY = "vdpu0_0:haset0_0"
STANDBY_SCOPE_KEY = "vdpu1_0:haset0_0"

DPU_CRITICAL_PROCESSES = [
    pytest.param("syncd", "syncd", id="syncd"),
    pytest.param("orchagent", "swss", id="orchagent"),
    pytest.param("hamgrd", "dash-ha", id="hamgrd"),
]

###############################################################################
# Helpers
###############################################################################


def kill_process_on_dpu(dpuhost, process_name, container):
    """Kill a process inside a docker container on the DPU host via SSH."""
    cmd = f"docker exec {container} pkill -9 {process_name} || true"
    logger.info(f"{dpuhost.hostname}: killing '{process_name}' in {container}")
    dpuhost.shell(cmd)


def wait_for_process_recovery(dpuhost, process_name, container,
                              timeout=PROCESS_RECOVERY_TIMEOUT):
    """Wait until the process is running again on the DPU host."""
    def _is_running():
        result = dpuhost.shell(
            f"docker exec {container} pgrep {process_name} || true"
        )
        return bool(result["stdout"].strip())

    logger.info(
        f"{dpuhost.hostname}: waiting for '{process_name}' recovery in {container}"
    )
    return wait_until(timeout, HA_CHECK_INTERVAL, 0, _is_running)


def verify_ha_state_converged(duthost, scope_key, expected_state):
    """Assert that the HA scope reaches the expected state within timeout."""
    assert wait_for_ha_state(
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


def send_continuous_pl_traffic(ptfadapter, config, stop_event, results):
    """Send outbound PL packets in a loop until stop_event is set.

    Designed to run in a background thread so data-plane impact
    is measured concurrently with the process crash.
    """
    sent = 0
    received = 0
    while not stop_event.is_set():
        try:
            send_pkt, exp_pkt = outbound_pl_packets(config, "vxlan")
            testutils.send(
                ptfadapter, config[LOCAL_PTF_INTF], send_pkt, count=1
            )
            sent += 1
            try:
                testutils.verify_packet_any_port(
                    ptfadapter, exp_pkt,
                    config[REMOTE_PTF_RECV_INTF],
                    timeout=1,
                )
                received += 1
            except AssertionError:
                pass
        except Exception as e:
            logger.debug(f"Traffic sender: {e}")
        time.sleep(TRAFFIC_SEND_INTERVAL)
    results["sent"] = sent
    results["received"] = received


###############################################################################
# Fixtures
###############################################################################


@pytest.fixture(scope="module")
def active_dut(duthosts):
    """Return the DUT that hosts the active DPU (DUT index 0)."""
    return duthosts[0]


@pytest.fixture(scope="module")
def standby_dut(duthosts):
    """Return the DUT that hosts the standby DPU (DUT index 1)."""
    return duthosts[1]


@pytest.fixture(scope="module")
def active_dpuhost(dpuhosts):
    """Return the DPU host for the active side."""
    return dpuhosts[0]


@pytest.fixture(scope="module")
def standby_dpuhost(dpuhosts):
    """Return the DPU host for the standby side."""
    return dpuhosts[1]


###############################################################################
# Test Class
###############################################################################


class TestCriticalProcessCrash:
    """
    Verify HA behavior when a critical process crashes on a DPU.

    Traffic runs continuously in a background thread so data-plane
    impact is measured during the crash, not just before/after.
    Uses existing outbound_pl_packets() from packets.py for packet
    generation and dash_pl_config fixture from conftest for config.
    """

    def _run_process_crash(
        self,
        process_name,
        container,
        crash_dpuhost,
        crash_duthost,
        crash_scope_key,
        expected_ha_state_after_crash,
        verify_duthost,
        verify_scope_key,
        expected_ha_state_verify,
        ptfadapter,
        pl_config,
    ):
        """Common body shared by all crash variations.

        Steps:
            1. Verify PL dataplane baseline
            2. Start continuous background traffic
            3. Kill process on DPU (via SSH to DPU host)
            4. Verify HA state converges on crash DUT
            5. Verify peer HA state unchanged
            6. Wait for process recovery
            7. Stop background traffic and log results
        """
        logger.info(
            f"=== {process_name} crash on {crash_dpuhost.hostname} "
            f"(scope: {crash_scope_key}) ==="
        )

        send_pkt, exp_pkt = outbound_pl_packets(pl_config, "vxlan")
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, pl_config[LOCAL_PTF_INTF], send_pkt, count=1)
        testutils.verify_packet_any_port(
            ptfadapter, exp_pkt, pl_config[REMOTE_PTF_RECV_INTF],
            timeout=PL_VERIFY_TIMEOUT,
        )
        logger.info("Baseline PL traffic verified")

        stop_event = threading.Event()
        traffic_results = {}
        traffic_thread = InterruptableThread(
            target=send_continuous_pl_traffic,
            args=(ptfadapter, pl_config, stop_event, traffic_results),
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

    # ------------------------------------------------------------------
    # Variation 1: Crash on active DPU, traffic landing on active DPU
    # ------------------------------------------------------------------
    @pytest.mark.parametrize("process_name,container", DPU_CRITICAL_PROCESSES)
    def test_crash_active_dpu_traffic_on_active(
        self,
        process_name,
        container,
        active_dut,
        standby_dut,
        active_dpuhost,
        setup_ha_config,
        setup_dash_ha_from_json,
        setup_gnmi_server,
        activate_dash_ha_from_json,
        ptfadapter,
        dash_pl_config,
    ):
        """Crash on active DPU, traffic landing on active DPU."""
        self._run_process_crash(
            process_name=process_name,
            container=container,
            crash_dpuhost=active_dpuhost,
            crash_duthost=active_dut,
            crash_scope_key=ACTIVE_SCOPE_KEY,
            expected_ha_state_after_crash="active",
            verify_duthost=standby_dut,
            verify_scope_key=STANDBY_SCOPE_KEY,
            expected_ha_state_verify="standby",
            ptfadapter=ptfadapter,
            pl_config=dash_pl_config[0],
        )

    # ------------------------------------------------------------------
    # Variation 2: Crash on active DPU, traffic landing on standby DPU
    # ------------------------------------------------------------------
    @pytest.mark.parametrize("process_name,container", DPU_CRITICAL_PROCESSES)
    def test_crash_active_dpu_traffic_on_standby(
        self,
        process_name,
        container,
        active_dut,
        standby_dut,
        active_dpuhost,
        setup_ha_config,
        setup_dash_ha_from_json,
        setup_gnmi_server,
        activate_dash_ha_from_json,
        ptfadapter,
        dash_pl_config,
    ):
        """Crash on active DPU, traffic landing on standby DPU."""
        self._run_process_crash(
            process_name=process_name,
            container=container,
            crash_dpuhost=active_dpuhost,
            crash_duthost=active_dut,
            crash_scope_key=ACTIVE_SCOPE_KEY,
            expected_ha_state_after_crash="active",
            verify_duthost=standby_dut,
            verify_scope_key=STANDBY_SCOPE_KEY,
            expected_ha_state_verify="standby",
            ptfadapter=ptfadapter,
            pl_config=dash_pl_config[1],
        )

    # ------------------------------------------------------------------
    # Variation 3: Crash on standby DPU, traffic landing on active DPU
    # ------------------------------------------------------------------
    @pytest.mark.parametrize("process_name,container", DPU_CRITICAL_PROCESSES)
    def test_crash_standby_dpu_traffic_on_active(
        self,
        process_name,
        container,
        active_dut,
        standby_dut,
        standby_dpuhost,
        setup_ha_config,
        setup_dash_ha_from_json,
        setup_gnmi_server,
        activate_dash_ha_from_json,
        ptfadapter,
        dash_pl_config,
    ):
        """Crash on standby DPU, traffic landing on active DPU."""
        self._run_process_crash(
            process_name=process_name,
            container=container,
            crash_dpuhost=standby_dpuhost,
            crash_duthost=standby_dut,
            crash_scope_key=STANDBY_SCOPE_KEY,
            expected_ha_state_after_crash="standby",
            verify_duthost=active_dut,
            verify_scope_key=ACTIVE_SCOPE_KEY,
            expected_ha_state_verify="active",
            ptfadapter=ptfadapter,
            pl_config=dash_pl_config[0],
        )

    # ------------------------------------------------------------------
    # Variation 4: Crash on standby DPU, traffic landing on standby DPU
    # ------------------------------------------------------------------
    @pytest.mark.parametrize("process_name,container", DPU_CRITICAL_PROCESSES)
    def test_crash_standby_dpu_traffic_on_standby(
        self,
        process_name,
        container,
        active_dut,
        standby_dut,
        standby_dpuhost,
        setup_ha_config,
        setup_dash_ha_from_json,
        setup_gnmi_server,
        activate_dash_ha_from_json,
        ptfadapter,
        dash_pl_config,
    ):
        """Crash on standby DPU, traffic landing on standby DPU."""
        self._run_process_crash(
            process_name=process_name,
            container=container,
            crash_dpuhost=standby_dpuhost,
            crash_duthost=standby_dut,
            crash_scope_key=STANDBY_SCOPE_KEY,
            expected_ha_state_after_crash="standby",
            verify_duthost=active_dut,
            verify_scope_key=ACTIVE_SCOPE_KEY,
            expected_ha_state_verify="active",
            ptfadapter=ptfadapter,
            pl_config=dash_pl_config[1],
        )
