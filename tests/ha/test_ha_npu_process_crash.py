"""
HA NPU Critical Process Crash Tests

Verifies HA behavior when critical processes crash on the NPU in the
t1-smartswitch-ha topology.

For each NPU process under test (hamgrd, pmon, bgp) there are 4 variations:
    1. Crash on primary NPU,  traffic landing on primary DUT
    2. Crash on primary NPU,  traffic landing on standby DUT
    3. Crash on standby NPU, traffic landing on primary DUT
    4. Crash on standby NPU, traffic landing on standby DUT

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
from tests.ha.ha_gnmi import apply_ha_messages, ha_scope_config

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("t1-smartswitch-ha"),
    pytest.mark.skip_check_dut_health,
]

PROCESS_RECOVERY_TIMEOUT = 300
HA_CONVERGENCE_TIMEOUT = 180
# BGP disrupts routing when killed; HA needs extra time to reconverge
# after BGP routes are restored.
BGP_HA_CONVERGENCE_TIMEOUT = 300
HA_CHECK_INTERVAL = 5
TRAFFIC_SEND_INTERVAL = 0.1
PL_VERIFY_TIMEOUT = 10


# Processes whose containers must be fully restarted for recovery because
# dependent-startup injects required runtime arguments (e.g. --slot-id).
# Other processes (e.g. pmond, bgpd) are managed by supervisord inside their
# containers and recover automatically without a container restart.
NEEDS_CONTAINER_RESTART = {"hamgrd"}

# Containers to kill entirely (docker kill) instead of killing a single
# process inside them.  Used when the critical process (e.g. pmond) may not
# be present in supervisord on every platform — killing the whole container
# is the reliable, platform-agnostic way to test crash recovery.
KILL_ENTIRE_CONTAINER = {"pmon"}

MAX_TRAFFIC_LOSS_PCT = 5.0

NPU_CRITICAL_PROCESSES = [
    pytest.param("hamgrd", "dash-hadpu0", id="hamgrd"),
    pytest.param("pmond", "pmon", id="pmon"),
    pytest.param("bgpd", "bgp", id="bgp"),
]


def wait_for_container_up(host, container, timeout=PROCESS_RECOVERY_TIMEOUT):
    """Wait until a Docker container is running again after being killed."""
    def _is_up():
        result = host.shell(
            f"docker ps --filter name=^/{container}$ --filter status=running -q || true",
            module_ignore_errors=True,
        )
        return bool(result["stdout"].strip())

    logger.info(f"{host.hostname}: waiting for container '{container}' to come back up")
    return wait_until(timeout, HA_CHECK_INTERVAL, 0, _is_up)


def wait_for_process_recovery(host, process_name, container,
                              timeout=PROCESS_RECOVERY_TIMEOUT):
    if container in KILL_ENTIRE_CONTAINER:
        return wait_for_container_up(host, container, timeout)

    def _is_running():
        result = host.shell(
            f"docker exec {container} pgrep {process_name} || true"
        )
        return bool(result["stdout"].strip())

    if process_name in NEEDS_CONTAINER_RESTART and not _is_running():
        logger.info(
            f"{host.hostname}: '{process_name}' not running in {container}; "
            f"restarting container to let dependent-startup re-launch it"
        )
        host.shell(f"docker restart {container}", module_ignore_errors=True)
        time.sleep(15)

    logger.info(
        f"{host.hostname}: waiting for '{process_name}' recovery in {container}"
    )
    return wait_until(timeout, HA_CHECK_INTERVAL, 0, _is_running)


DPU_ONLINE_TIMEOUT = 300
DPU_ONLINE_INTERVAL = 10


def ensure_dpu0_online(duthosts):
    """Ensure DPU0 is Online on every DUT before a test starts.

    If DPU0 is Offline or Partial Online, issue a startup command and wait
    up to DPU_ONLINE_TIMEOUT seconds for it to reach Online.
    """
    for duthost in duthosts:
        def _is_online():
            result = duthost.shell(
                "show chassis module status | grep -i DPU0 || true"
            )
            return "Online" in result["stdout"] and "Partial" not in result["stdout"]

        if not _is_online():
            logger.info(
                f"{duthost.hostname}: DPU0 is not Online; "
                f"issuing 'config chassis modules startup DPU0'"
            )
            duthost.shell(
                "sudo config chassis modules startup DPU0",
                module_ignore_errors=True,
            )

        assert wait_until(DPU_ONLINE_TIMEOUT, DPU_ONLINE_INTERVAL, 0, _is_online), (
            f"{duthost.hostname}: DPU0 did not reach Online within {DPU_ONLINE_TIMEOUT}s"
        )
        logger.info(f"{duthost.hostname}: DPU0 is Online")


def verify_ha_state_converged(duthost, scope_key, expected_state,
                              timeout=HA_CONVERGENCE_TIMEOUT):
    assert verify_ha_state(
        duthost,
        scope_key=scope_key,
        expected_state=expected_state,
        timeout=timeout,
        interval=HA_CHECK_INTERVAL,
    ), (
        f"{duthost.hostname}: HA scope '{scope_key}' did not reach "
        f"'{expected_state}' within {timeout}s"
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


class TestNpuProcessCrash:

    def _run(
        self, process_name, container,
        crash_duthost, crash_scope_key,
        expected_ha_state_after_crash,
        verify_duthost, verify_scope_key, expected_ha_state_verify,
        ptfadapter, dash_pl_config, traffic_dut_index, duthosts,
        localhost, ptfhost,
    ):
        # Verify DPU0 is Online on both DUTs before doing anything else.
        # A previous test may have left DPU0 Offline (e.g. after container
        # restart); if so, issue a startup and wait for it to recover.
        ensure_dpu0_online(duthosts)

        pl_config = dash_pl_config[traffic_dut_index]
        recv_ports = all_recv_ports(dash_pl_config)

        logger.info(
            f"=== NPU {process_name} crash on {crash_duthost.hostname} "
            f"(scope: {crash_scope_key}) ==="
        )

        # Wait for both DUTs to reach their initial expected HA states before
        # the crash. Both DUTs show "active" in local_acked_asic_ha_state
        # because the DPU HA dataplane operates in active/active mode.
        logger.info("Waiting for initial HA states to stabilize before crash")
        verify_ha_state_converged(
            crash_duthost, crash_scope_key, expected_ha_state_after_crash
        )
        verify_ha_state_converged(
            verify_duthost, verify_scope_key, expected_ha_state_verify
        )
        logger.info("Initial HA states confirmed")

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
            if container in KILL_ENTIRE_CONTAINER:
                cmd = f"docker kill {container}"
                logger.info(
                    f"{crash_duthost.hostname}: killing container '{container}'"
                )
            else:
                cmd = f"docker exec {container} pkill -9 {process_name} || true"
                logger.info(
                    f"{crash_duthost.hostname}: killing '{process_name}' "
                    f"in {container}"
                )
            crash_duthost.shell(cmd, module_ignore_errors=True)

            if process_name == "bgpd":
                # Killing bgpd drops BGP routes, which directly breaks HA
                # control-plane connectivity.  HA cannot converge back to
                # "active" until BGP routes are restored.  Therefore we must
                # wait for bgpd to recover FIRST, then check HA state.
                # Give a short grace period for management connectivity first.
                logger.info("Waiting for management connectivity after bgpd kill")
                time.sleep(15)

                recovered = wait_for_process_recovery(
                    crash_duthost, process_name, container
                )
                assert recovered, (
                    f"{process_name} did not recover on {crash_duthost.hostname} "
                    f"within {PROCESS_RECOVERY_TIMEOUT}s"
                )
                logger.info(f"{process_name} recovered; waiting 120s for BGP sessions and routes to fully re-establish")
                time.sleep(120)
                logger.info("BGP settle wait complete; verifying critical routes before HA convergence")

                peer_scope_key = verify_scope_key
                peer_vdpu = peer_scope_key.split(":")[0]
                peer_subnet = "20.0.201.0/24" if peer_vdpu == "vdpu1_0" else "20.0.200.0/24"
                route_check = crash_duthost.shell(
                    f'vtysh -c "show ip route {peer_subnet} json"',
                    module_ignore_errors=True,
                )
                import json as _json
                try:
                    rdata = _json.loads(route_check["stdout"])
                    route_failed = rdata.get(peer_subnet, [{}])[0].get("failed", False)
                except Exception:
                    route_failed = None
                logger.info(f"Route {peer_subnet} failed={route_failed}")

                if route_failed:
                    logger.warning(
                        f"Route {peer_subnet} has failed FIB install; "
                        f"doing hard BGP clear to force re-programming"
                    )
                    crash_duthost.shell(
                        'vtysh -c "clear ip bgp *"', module_ignore_errors=True,
                    )
                    time.sleep(30)

                logger.info("Route check done; now checking HA convergence")

                # After bgpd recovery, HA may land in "standalone" or
                # "dead" with pending operations.  The state machine
                # needs: approve pending ops AND, when the state is
                # stuck (standalone/dead) with no pending ops,
                # re-push desired_ha_state to trigger a new
                # activate_role.  Loop until "active" or timeout.
                db_key = "DASH_HA_SCOPE_STATE|" + crash_scope_key.replace(":", "|")
                vdpu_id, ha_set_id = crash_scope_key.split(":", 1)
                reactivation_sent = False
                toggle_retry_count = 0
                approval_deadline = time.time() + BGP_HA_CONVERGENCE_TIMEOUT
                while time.time() < approval_deadline:
                    state_res = crash_duthost.shell(
                        f'sonic-db-cli STATE_DB HGET "{db_key}" local_acked_asic_ha_state'
                    )["stdout"].strip()
                    logger.info(f"HA state on {crash_duthost.hostname}: {state_res}")
                    if state_res == expected_ha_state_after_crash:
                        logger.info(f"HA reached '{expected_ha_state_after_crash}' on {crash_duthost.hostname}")
                        break

                    ids_str = crash_duthost.shell(
                        f'sonic-db-cli STATE_DB HGET "{db_key}" pending_operation_ids'
                    )["stdout"].strip()
                    types_str = crash_duthost.shell(
                        f'sonic-db-cli STATE_DB HGET "{db_key}" pending_operation_types'
                    )["stdout"].strip()
                    all_ids = [i.strip() for i in ids_str.split(",") if i.strip()]
                    all_types = [t.strip() for t in types_str.split(",") if t.strip()]
                    pending_ops = list(zip(all_types, all_ids))

                    if pending_ops:
                        approve_ids = [op_id for _, op_id in pending_ops]
                        op_summary = ", ".join(f"{t}={i}" for t, i in pending_ops)
                        logger.info(f"Approving {len(approve_ids)} pending ops: {op_summary}")
                        messages = ha_scope_config(
                            vdpu_id=vdpu_id, ha_set_id=ha_set_id,
                            version="1", disabled=False,
                            desired_ha_state="active", owner="dpu",
                            approved_pending_operation_ids=approve_ids,
                        )
                        apply_ha_messages(
                            localhost=localhost, duthost=crash_duthost,
                            ptfhost=ptfhost, messages=messages,
                        )
                        reactivation_sent = False
                        logger.info("Pending ops approved; waiting 15s for state transition")
                        time.sleep(15)
                    elif state_res in ("standalone", "dead", "unknown") and not reactivation_sent:
                        logger.info(
                            f"State is '{state_res}' with no pending ops; "
                            f"toggling HA scope (disable then re-enable) to force activation"
                        )
                        disable_msgs = ha_scope_config(
                            vdpu_id=vdpu_id, ha_set_id=ha_set_id,
                            version="1", disabled=True,
                            desired_ha_state="active", owner="dpu",
                        )
                        apply_ha_messages(
                            localhost=localhost, duthost=crash_duthost,
                            ptfhost=ptfhost, messages=disable_msgs,
                        )
                        logger.info("HA scope disabled; waiting 5s before re-enabling")
                        time.sleep(5)
                        enable_msgs = ha_scope_config(
                            vdpu_id=vdpu_id, ha_set_id=ha_set_id,
                            version="1", disabled=False,
                            desired_ha_state="active", owner="dpu",
                        )
                        apply_ha_messages(
                            localhost=localhost, duthost=crash_duthost,
                            ptfhost=ptfhost, messages=enable_msgs,
                        )
                        reactivation_sent = True
                        logger.info("HA scope re-enabled; waiting 20s for pending op")
                        time.sleep(20)
                    elif reactivation_sent and toggle_retry_count < 3:
                        toggle_retry_count += 1
                        logger.info(
                            f"No pending ops, state={state_res} after toggle "
                            f"(retry {toggle_retry_count}/3); re-toggling"
                        )
                        reactivation_sent = False
                        time.sleep(5)
                    else:
                        logger.info(f"No pending ops, state={state_res}; waiting 10s")
                        time.sleep(10)
                else:
                    state_res = crash_duthost.shell(
                        f'sonic-db-cli STATE_DB HGET "{db_key}" local_acked_asic_ha_state'
                    )["stdout"].strip()
                    assert state_res == expected_ha_state_after_crash, (
                        f"{crash_duthost.hostname}: HA scope '{crash_scope_key}' "
                        f"is '{state_res}', expected '{expected_ha_state_after_crash}' "
                        f"after {BGP_HA_CONVERGENCE_TIMEOUT}s of approval attempts"
                    )

                verify_ha_state_converged(
                    verify_duthost, verify_scope_key, expected_ha_state_verify,
                )
            else:
                # For hamgrd/pmon: HA data plane is independent of the NPU
                # process, so HA should remain "active" while the process is
                # down.  Check HA first, then wait for process recovery.
                verify_ha_state_converged(
                    crash_duthost, crash_scope_key, expected_ha_state_after_crash
                )
                verify_ha_state_converged(
                    verify_duthost, verify_scope_key, expected_ha_state_verify
                )

                recovered = wait_for_process_recovery(
                    crash_duthost, process_name, container
                )
                assert recovered, (
                    f"{process_name} did not recover on {crash_duthost.hostname} "
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

    @pytest.mark.parametrize("process_name,container", NPU_CRITICAL_PROCESSES)
    def test_crash_active_npu_traffic_on_active(
        self, process_name, container,
        primary_dut, standby_dut, duthosts,
        setup_ha_config, setup_dash_ha_from_json,
        setup_gnmi_server, setup_dash_pl_pipeline_module_scope,
        ptfadapter, dash_pl_config,
        localhost, ptfhost,
        activate_dash_ha_from_json,
        primary_vdpu_key,
        standby_vdpu_key
    ):
        self._run(
            process_name=process_name, container=container,
            crash_duthost=primary_dut,
            crash_scope_key=primary_vdpu_key,
            expected_ha_state_after_crash="active",
            verify_duthost=standby_dut,
            verify_scope_key=standby_vdpu_key,
            expected_ha_state_verify="active",
            ptfadapter=ptfadapter, dash_pl_config=dash_pl_config,
            traffic_dut_index=0, duthosts=duthosts,
            localhost=localhost, ptfhost=ptfhost,
        )

    @pytest.mark.parametrize("process_name,container", NPU_CRITICAL_PROCESSES)
    def test_crash_active_npu_traffic_on_standby(
        self, process_name, container,
        primary_dut, standby_dut, primary_vdpu_key, standby_vdpu_key, duthosts,
        setup_ha_config, setup_dash_ha_from_json,
        setup_gnmi_server, setup_dash_pl_pipeline_module_scope,
        ptfadapter, dash_pl_config,
        localhost, ptfhost,
        activate_dash_ha_from_json,
    ):
        self._run(
            process_name=process_name, container=container,
            crash_duthost=primary_dut,
            crash_scope_key=primary_vdpu_key,
            expected_ha_state_after_crash="active",
            verify_duthost=standby_dut,
            verify_scope_key=standby_vdpu_key,
            expected_ha_state_verify="active",
            ptfadapter=ptfadapter, dash_pl_config=dash_pl_config,
            traffic_dut_index=1, duthosts=duthosts,
            localhost=localhost, ptfhost=ptfhost,
        )

    @pytest.mark.parametrize("process_name,container", NPU_CRITICAL_PROCESSES)
    def test_crash_standby_npu_traffic_on_active(
        self, process_name, container,
        primary_dut, standby_dut, primary_vdpu_key, standby_vdpu_key, duthosts,
        setup_ha_config, setup_dash_ha_from_json,
        setup_gnmi_server, setup_dash_pl_pipeline_module_scope,
        ptfadapter, dash_pl_config,
        localhost, ptfhost,
        activate_dash_ha_from_json,
    ):
        self._run(
            process_name=process_name, container=container,
            crash_duthost=standby_dut,
            crash_scope_key=standby_vdpu_key,
            expected_ha_state_after_crash="active",
            verify_duthost=primary_dut,
            verify_scope_key=primary_vdpu_key,
            expected_ha_state_verify="active",
            ptfadapter=ptfadapter, dash_pl_config=dash_pl_config,
            traffic_dut_index=0, duthosts=duthosts,
            localhost=localhost, ptfhost=ptfhost,
        )

    @pytest.mark.parametrize("process_name,container", NPU_CRITICAL_PROCESSES)
    def test_crash_standby_npu_traffic_on_standby(
        self, process_name, container,
        primary_dut, standby_dut, primary_vdpu_key, standby_vdpu_key, duthosts,
        setup_ha_config, setup_dash_ha_from_json,
        setup_gnmi_server, setup_dash_pl_pipeline_module_scope,
        ptfadapter, dash_pl_config,
        localhost, ptfhost,
        activate_dash_ha_from_json,
    ):
        self._run(
            process_name=process_name, container=container,
            crash_duthost=standby_dut,
            crash_scope_key=standby_vdpu_key,
            expected_ha_state_after_crash="active",
            verify_duthost=primary_dut,
            verify_scope_key=primary_vdpu_key,
            expected_ha_state_verify="active",
            ptfadapter=ptfadapter, dash_pl_config=dash_pl_config,
            traffic_dut_index=1, duthosts=duthosts,
            localhost=localhost, ptfhost=ptfhost,
        )
