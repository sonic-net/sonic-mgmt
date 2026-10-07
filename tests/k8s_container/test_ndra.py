"""Qualify the Network Device Repair Agent (NDRA) on the Kubernetes container infrastructure."""

import logging
import shlex
import time

import pytest

from tests.common.utilities import wait_until


pytest_plugins = ("tests.k8s_container.ndra_provider",)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.disable_loganalyzer,
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.skip_check_dut_health,
]

SOAK_SECONDS = 180
OBSERVABILITY_WORKFLOW = "sonic_observability_alert"
RESTART_WORKFLOW = "restart_os_process"
# The OsProcessDown rules of the repair-agent problem mapping, in rule order.
RESTART_TARGETS = (
    ("dhcp_server", "/usr/bin/dhcp_server"),
    ("CA_cert_downloader", "CA_cert_downloader"),
    ("telemetry", "telemetry"),
    ("fancontrol", "/usr/sbin/fancontrol"),
)
RESTART_SETTLE_SECONDS = "60"
WORKFLOW_TIMEOUT_SECONDS = 420
TRIGGER_SOURCE = "sonic-mgmt:k8s_container/test_ndra.py"
# Repair-agent gRPC, NPD server (started only by NPD's Kubernetes exporter), and NPD metrics.
LISTENER_PORTS = ("9090", "20256", "20257")
REQUIRED_LISTENER_PORTS = ("9090", "20257")


@pytest.fixture(scope="module")
def minikube_duthost(rand_selected_dut):
    if not rand_selected_dut.sonichost.is_frontend_node():
        pytest.skip("Kubernetes NDRA qualification requires a frontend DUT")
    if rand_selected_dut.facts.get("num_asic") != 1:
        pytest.skip("Kubernetes NDRA qualification currently supports one ASIC")
    return rand_selected_dut


def _unit_state(duthost, unit):
    result = duthost.shell(
        "systemctl show --property=ActiveState --property=MainPID {}".format(shlex.quote(unit)),
        module_ignore_errors=True,
    )
    values = dict(
        line.split("=", 1)
        for line in result.get("stdout", "").splitlines()
        if "=" in line
    )
    try:
        main_pid = int(values.get("MainPID", "0"))
    except ValueError:
        main_pid = 0
    return values.get("ActiveState", ""), main_pid


def _restarted(duthost, unit, original_pid):
    state, main_pid = _unit_state(duthost, unit)
    return state == "active" and main_pid > 0 and main_pid != original_pid


def test_ndra_repair_agent_serves_grpc(kubernetes_ndra_workload):
    health = kubernetes_ndra_workload.repair_agent_grpc("HealthCheck")
    assert health.get("status") == "OK", health
    assert int(health.get("loadedWorkflows", 0)) > 0, health

    listed = kubernetes_ndra_workload.repair_agent_grpc("ListWorkflows")
    names = {workflow.get("name") for workflow in listed.get("workflows", [])}
    missing = sorted({OBSERVABILITY_WORKFLOW, RESTART_WORKFLOW} - names)
    assert not missing, "repair-agent did not load workflows {}".format(missing)


def test_ndra_node_problem_detector_serves_metrics(kubernetes_ndra_workload):
    assert wait_until(90, 5, 0, kubernetes_ndra_workload.node_problem_detector_serving_metrics), (
        "node-problem-detector does not serve http://127.0.0.1:20257/metrics"
    )


def test_ndra_listens_on_loopback_only(minikube_duthost, kubernetes_ndra_workload):
    ports = " or ".join("sport = :{}".format(port) for port in LISTENER_PORTS)
    result = minikube_duthost.shell("ss -Hltn '( {} )'".format(ports), module_ignore_errors=True)
    assert result.get("rc", 1) == 0, result.get("stderr", "")
    listeners = [
        line.split()[3]
        for line in result.get("stdout", "").splitlines()
        if len(line.split()) >= 4
    ]
    listening = {address.rsplit(":", 1)[-1] for address in listeners}
    missing = sorted(port for port in REQUIRED_LISTENER_PORTS if port not in listening)
    assert not missing, "NDRA listeners are absent on ports {}".format(missing)
    exposed = sorted(
        address for address in listeners
        if not address.startswith("127.") and not address.startswith("[::1]:")
    )
    assert not exposed, "NDRA must listen on loopback only; found {}".format(exposed)


def test_ndra_soak_keeps_dut_healthy(minikube_duthost, kubernetes_ndra_workload):
    time.sleep(SOAK_SECONDS)

    services = minikube_duthost.critical_services_status()
    stopped = sorted(name for name, running in services.items() if not running)
    assert not stopped, "critical services stopped while NDRA was running: {}".format(stopped)

    restarted = sorted(
        name
        for name, container_id in kubernetes_ndra_workload.initial_container_ids.items()
        if kubernetes_ndra_workload.running_container_id(name) != container_id
    )
    assert not restarted, "NDRA containers restarted during the soak: {}".format(restarted)

    unexpected = sorted(set(kubernetes_ndra_workload.attempted_workflows()) - {OBSERVABILITY_WORKFLOW})
    assert not unexpected, "NDRA attempted mitigation on a healthy DUT: {}".format(unexpected)


def test_ndra_kill_switch_blocks_workflows(kubernetes_ndra_workload):
    request = {
        "workflow": OBSERVABILITY_WORKFLOW,
        "reason": "kill switch qualification",
        "source": TRIGGER_SOURCE,
    }
    with kubernetes_ndra_workload.kill_switch():
        response = kubernetes_ndra_workload.repair_agent_grpc("TriggerWorkflow", request)
    assert response.get("status") == "DISABLED", response
    assert "kill-switch" in response.get("message", ""), response


def test_ndra_restart_os_process_workflow(minikube_duthost, kubernetes_ndra_workload):
    target = None
    for unit, executable in RESTART_TARGETS:
        state, main_pid = _unit_state(minikube_duthost, unit)
        if state == "active" and main_pid > 0:
            target = (unit, executable, main_pid)
            break
    if target is None:
        pytest.skip("No OS process mapped to {} is running on this DUT".format(RESTART_WORKFLOW))
    unit, executable, original_pid = target
    logger.info("Restarting %s (main PID %s) through %s", unit, original_pid, RESTART_WORKFLOW)

    request = {
        "workflow": RESTART_WORKFLOW,
        "reason": "restart_os_process qualification",
        "source": TRIGGER_SOURCE,
        "params": {
            "systemd_unit": unit,
            "process_executable": executable,
            "settle_seconds": RESTART_SETTLE_SECONDS,
        },
    }
    try:
        with kubernetes_ndra_workload.paused_health_monitor():
            response = kubernetes_ndra_workload.repair_agent_grpc("TriggerWorkflow", request)
            assert response.get("status") == "ACCEPTED", response
            invocation = kubernetes_ndra_workload.wait_for_invocation(
                response.get("invocationId"), WORKFLOW_TIMEOUT_SECONDS
            )
        assert invocation.get("state") == "SUCCEEDED", invocation
        assert wait_until(60, 5, 0, _restarted, minikube_duthost, unit, original_pid), (
            "{} is not active with a new main PID after {}".format(unit, RESTART_WORKFLOW)
        )
    finally:
        state, _ = _unit_state(minikube_duthost, unit)
        if state != "active":
            logger.warning("Starting %s because it is %s after the workflow", unit, state or "unknown")
            minikube_duthost.shell(
                "sudo systemctl reset-failed {0}; sudo systemctl start {0}".format(shlex.quote(unit)),
                module_ignore_errors=True,
            )
