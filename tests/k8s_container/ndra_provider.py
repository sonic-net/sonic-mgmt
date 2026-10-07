"""Kubernetes Network Device Repair Agent (NDRA) provider for container infrastructure tests."""

import json
import logging
import shlex
import time
import uuid
from contextlib import contextmanager
from urllib.parse import unquote

import pytest

from tests.common.helpers.dut_utils import creds_on_dut
from tests.common.minikube import DEFAULT_PROFILE
from tests.common.minikube import MinikubeLockHeldError
from tests.k8s_container.container_spec import SPEC_DIRECTORY
from tests.k8s_container.container_spec import load_container_spec
from tests.k8s_container.gnmi_provider import PAUSE_IMAGE
from tests.k8s_container.gnmi_provider import _image_id
from tests.k8s_container.gnmi_provider import _normalized_image_id
from tests.k8s_container.gnmi_provider import _runtime_image_id
from tests.k8s_container.gnmi_provider import _stage_images
from tests.k8s_container.lifecycle import OWNED_HOST_PATH_PREFIX
from tests.k8s_container.lifecycle import CommandResult
from tests.k8s_container.lifecycle import MinikubeCommandBoundary
from tests.k8s_container.lifecycle import deploy_workload
from tests.k8s_container.workload import ContainerSpec
from tests.k8s_container.workload import WorkloadBundle


pytest_plugins = ("tests.common.fixtures.minikube",)

logger = logging.getLogger(__name__)
SPEC_PATH = SPEC_DIRECTORY / "ndra.yaml"
HEALTH_MONITOR = "sonic-health-monitor"
NODE_PROBLEM_DETECTOR = "sonic-node-problem-detector"
REPAIR_AGENT = "sonic-repair-agent"
CONTAINER_NAMES = (HEALTH_MONITOR, NODE_PROBLEM_DETECTOR, REPAIR_AGENT)
REPAIR_AGENT_ENDPOINT = "127.0.0.1:9090"
REPAIR_AGENT_SERVICE = "sonic.watchdog.v1.WatchdogService"
REPAIR_AGENT_READY_TIMEOUT_SECONDS = 120
TERMINAL_INVOCATION_STATES = ("SUCCEEDED", "FAILED", "SKIPPED")
# Production hostPath state directories. Each run starts without them, so any
# existing copy is set aside for the run and restored afterwards.
HEALTH_MONITOR_STATE_DIRECTORY = "/var/lib/sonic-health-monitor"
REPAIR_AGENT_STATE_DIRECTORY = "/var/lib/sonic-repair-agent"
# Production DirectoryOrCreate hostPath; removed afterwards only when the run created it.
JOURNAL_DIRECTORY = "/var/log/journal"
MONITOR_PID_FILE = "monitor-daemon.pid"
_SET_ASIDE_SCRIPT = r"""set -eu
path="$1" backup="$2"
if [ -e "$path" ] || [ -L "$path" ]; then
  mv -T -- "$path" "$backup"
  echo moved
else
  echo absent
fi
"""
_RESTORE_SCRIPT = r"""set -eu
path="$1" backup="$2"
rm -rf --one-file-system -- "$path"
if [ -n "$backup" ]; then
  mv -T -- "$backup" "$path"
fi
"""
_REMOVE_CREATED_DIRECTORY_SCRIPT = r"""set -eu
if [ -d "$1" ] && [ ! -L "$1" ]; then
  rmdir -- "$1"
fi
"""


class RepairAgentGrpcError(RuntimeError):
    """Raised when one repair-agent gRPC call cannot be completed."""


class NdraCleanupError(RuntimeError):
    """Raised when NDRA-specific host preparation cannot be reverted."""


def _option(request, name, default):
    try:
        return request.config.getoption(name)
    except ValueError:
        return default


def _sudo_script(duthost, script, *arguments):
    return duthost.shell(
        "sudo sh -c {} sh {}".format(
            shlex.quote(script), " ".join(shlex.quote(argument) for argument in arguments)
        ),
        module_ignore_errors=True,
    )


def _candidate_image(golden_image, golden_version, version):
    repository, _, tag = golden_image.rpartition(":")
    if not tag.startswith(golden_version):
        pytest.fail("Golden NDRA image {} does not carry version {}".format(golden_image, golden_version))
    return "{}:{}{}".format(repository, version, tag[len(golden_version):])


def _selected_images(request, duthost, spec):
    role = _option(request, "--k8s-ndra-role", "golden")
    version = _option(request, "--k8s-ndra-image-version", None)
    machine = duthost.shell("uname -m", module_ignore_errors=True)
    architecture = machine.get("stdout", "").strip()
    if machine.get("rc", 1) != 0 or not architecture:
        pytest.fail("unable to determine DUT architecture for NDRA images")
    try:
        images = {
            name: spec.golden_image(name, architecture)
            for name in spec.container_names
        }
    except ValueError as error:
        pytest.fail(str(error))
    if role == "candidate":
        if not version:
            pytest.fail("--k8s-ndra-image-version is required for the NDRA candidate role")
        # Both NDRA images share one build version. Like the golden images, amd64 tags
        # carry the bare version and other architectures append "-<arch>".
        images = {
            name: _candidate_image(image, spec.golden_images[name]["amd64"].rpartition(":")[2], version)
            for name, image in images.items()
        }
    elif version:
        pytest.fail("the NDRA golden role uses checked-in soniccr1 tags, not --k8s-ndra-image-version")
    for name, image in images.items():
        ContainerSpec(name=name, image=image)
    return images


def _image_version(image):
    tag = image.rsplit("/", 1)[-1].partition(":")[2]
    if not tag:
        pytest.fail("NDRA images must use a version tag: {}".format(image))
    return "{}.kube".format(tag)


def _running_container_ids(duthost, pod_uid, container_name):
    result = duthost.shell(
        "docker ps -q --no-trunc --filter {} --filter {}".format(
            shlex.quote("label=io.kubernetes.pod.uid={}".format(pod_uid)),
            shlex.quote("label=io.kubernetes.container.name={}".format(container_name)),
        ),
        module_ignore_errors=True,
    )
    if result.get("rc", 1) != 0:
        return None
    return result.get("stdout", "").split()


def _running_container_id(duthost, pod_uid, container_name):
    container_ids = _running_container_ids(duthost, pod_uid, container_name)
    if not container_ids or len(container_ids) != 1:
        pytest.fail("Unable to resolve one running Kubernetes {} container".format(container_name))
    return container_ids[0]


def _attempt_history_workflow(file_name):
    """Return the workflow encoded in one repair-agent attempt history file name.

    The agent stores attempts as attempts/w_<workflow>[__c_<check>].json and
    percent-encodes every non-alphanumeric character except '-'.
    """
    if not file_name.startswith("w_") or not file_name.endswith(".json"):
        return None
    workflow = file_name[len("w_"):-len(".json")].split("__c_", 1)[0]
    return unquote(workflow) or None


class NdraDeployment:
    """One ready NDRA workload on the DUT.

    run_root is the test-owned directory that replaces the production emptyDir
    volumes mounted at /run/dpd and /generated-config.
    """

    def __init__(self, workload, duthost, run_root):
        self.workload = workload
        self.duthost = duthost
        self.run_root = run_root
        self.initial_container_ids = {
            name: self.running_container_id(name)
            for name in CONTAINER_NAMES
        }

    def running_container_id(self, container_name):
        return _running_container_id(self.duthost, self.workload.pod_uid, container_name)

    def exec(self, container_name, command):
        """Run a command in a workload container through the DUT's Docker runtime.

        kubectl exec is not used: the API server reaches the kubelet at the node's
        InternalIP, which can be an IPv6 address the Minikube host cannot route.
        """
        container_ids = _running_container_ids(self.duthost, self.workload.pod_uid, container_name)
        if not container_ids or len(container_ids) != 1:
            return CommandResult(1, "", "no single running {} container".format(container_name))
        result = self.duthost.shell(
            "docker exec {} {}".format(
                shlex.quote(container_ids[0]), " ".join(shlex.quote(part) for part in command)
            ),
            module_ignore_errors=True,
        )
        return CommandResult(result.get("rc", 1), result.get("stdout", ""), result.get("stderr", ""))

    def node_problem_detector_serving_metrics(self):
        """Return whether NPD serves the Prometheus endpoint that health-monitor scrapes."""
        result = self.exec(
            NODE_PROBLEM_DETECTOR,
            ["wget", "-q", "-T", "10", "-O", "/dev/null", "http://127.0.0.1:20257/metrics"],
        )
        return result.rc == 0

    def repair_agent_grpc(self, method, request=None, max_time_seconds=10):
        command = ["grpcurl", "-plaintext", "-max-time", str(max_time_seconds)]
        if request is not None:
            command.extend(["-d", json.dumps(request, sort_keys=True)])
        command.extend([REPAIR_AGENT_ENDPOINT, "{}/{}".format(REPAIR_AGENT_SERVICE, method)])
        result = self.exec(REPAIR_AGENT, command)
        if result.rc != 0:
            raise RepairAgentGrpcError(
                "{} failed (rc={}): {}".format(method, result.rc, (result.stderr or result.stdout).strip())
            )
        try:
            response = json.loads(result.stdout or "{}")
        except ValueError:
            raise RepairAgentGrpcError("{} returned invalid JSON: {!r}".format(method, result.stdout))
        if not isinstance(response, dict):
            raise RepairAgentGrpcError("{} returned a non-object response".format(method))
        return response

    def wait_for_repair_agent(self, timeout_seconds=REPAIR_AGENT_READY_TIMEOUT_SECONDS):
        deadline = time.time() + timeout_seconds
        while True:
            try:
                health = self.repair_agent_grpc("HealthCheck")
                if health.get("status") == "OK":
                    return health
                last_error = "unexpected HealthCheck response {}".format(health)
            except RepairAgentGrpcError as error:
                last_error = str(error)
            if time.time() >= deadline:
                pytest.fail("repair-agent gRPC did not become healthy: {}".format(last_error))
            time.sleep(5)

    def wait_for_invocation(self, invocation_id, timeout_seconds):
        """Poll one invocation until it reaches a terminal state or the timeout expires."""
        deadline = time.time() + timeout_seconds
        while True:
            try:
                invocation = self.repair_agent_grpc("GetInvocation", {"invocationId": invocation_id})
            except RepairAgentGrpcError as error:
                invocation = {"id": invocation_id, "error": str(error)}
            if invocation.get("state") in TERMINAL_INVOCATION_STATES or time.time() >= deadline:
                return invocation
            time.sleep(5)

    @contextmanager
    def kill_switch(self):
        """Engage the repair-agent kill switch at its production host path."""
        path = "{}/killswitch".format(REPAIR_AGENT_STATE_DIRECTORY)
        result = self.duthost.shell("sudo touch -- {}".format(shlex.quote(path)), module_ignore_errors=True)
        if result.get("rc", 1) != 0:
            pytest.fail("Unable to engage the NDRA kill switch at {}".format(path))
        try:
            yield path
        finally:
            result = self.duthost.shell("sudo rm -f -- {}".format(shlex.quote(path)), module_ignore_errors=True)
            if result.get("rc", 1) != 0:
                raise NdraCleanupError("Unable to release the NDRA kill switch at {}".format(path))

    @contextmanager
    def paused_health_monitor(self):
        """Stop health-monitor reporting so only explicitly triggered workflows run."""
        path = "{}/{}".format(self.run_root, MONITOR_PID_FILE)
        script = 'pid="$(cat "$1")"; test -n "$pid"; kill -STOP "$pid"; echo "$pid"'
        result = _sudo_script(self.duthost, script, path)
        pid = result.get("stdout", "").strip()
        if result.get("rc", 1) != 0 or not pid.isdigit():
            pytest.fail("Unable to pause the health-monitor daemon")
        try:
            yield pid
        finally:
            result = self.duthost.shell("sudo kill -CONT {}".format(pid), module_ignore_errors=True)
            if result.get("rc", 1) != 0:
                logger.warning("Unable to resume health-monitor daemon PID %s", pid)

    def attempted_workflows(self):
        """Return the workflows the repair agent accepted since this workload started."""
        directory = "{}/attempts".format(REPAIR_AGENT_STATE_DIRECTORY)
        script = 'test ! -d "$1" || find "$1" -mindepth 1 -maxdepth 1 -type f -name "*.json" -printf "%f\\n"'
        result = _sudo_script(self.duthost, script, directory)
        if result.get("rc", 1) != 0:
            pytest.fail("Unable to read repair-agent attempt history")
        workflows = set()
        for file_name in result.get("stdout", "").split():
            workflow = _attempt_history_workflow(file_name)
            if workflow is None:
                pytest.fail("Unrecognized repair-agent attempt history file {}".format(file_name))
            workflows.add(workflow)
        return tuple(sorted(workflows))


@contextmanager
def _isolated_host_state(duthost, ownership_id):
    """Start the workload without NDRA host state and restore the DUT afterwards."""
    backups = {}
    journal_was_absent = False
    primary_error = None
    try:
        for path in (HEALTH_MONITOR_STATE_DIRECTORY, REPAIR_AGENT_STATE_DIRECTORY):
            backup = "{}.sonic-mgmt-{}".format(path, ownership_id)
            result = _sudo_script(duthost, _SET_ASIDE_SCRIPT, path, backup)
            outcome = result.get("stdout", "").strip()
            if result.get("rc", 1) != 0 or outcome not in ("moved", "absent"):
                pytest.fail("Unable to set aside existing NDRA state at {}".format(path))
            backups[path] = backup if outcome == "moved" else ""
        journal = _sudo_script(duthost, 'test -e "$1" || test -L "$1"', JOURNAL_DIRECTORY)
        journal_was_absent = journal.get("rc", 1) != 0
        yield
    except BaseException as error:
        primary_error = error
        raise
    finally:
        if primary_error is not None and getattr(primary_error, "preserve_workload_dependencies", False):
            logger.error("NDRA host state retained because workload cleanup failed")
        else:
            cleanup_errors = []
            for path, backup in backups.items():
                if _sudo_script(duthost, _RESTORE_SCRIPT, path, backup).get("rc", 1) != 0:
                    cleanup_errors.append("unable to restore NDRA state at {}".format(path))
            if journal_was_absent:
                if _sudo_script(duthost, _REMOVE_CREATED_DIRECTORY_SCRIPT, JOURNAL_DIRECTORY).get("rc", 1) != 0:
                    cleanup_errors.append("unable to remove {} created by the workload".format(JOURNAL_DIRECTORY))
            if cleanup_errors:
                if primary_error is not None:
                    logger.error("NDRA host state cleanup failed: %s", "; ".join(cleanup_errors))
                else:
                    raise NdraCleanupError("; ".join(cleanup_errors))


@contextmanager
def _deployed_ndra_workload(request, duthost, joined_minikube_dut, spec, images):
    role = _option(request, "--k8s-ndra-role", "golden")
    ownership_id = str(uuid.uuid4())
    run_root = "{}{}".format(OWNED_HOST_PATH_PREFIX, ownership_id)
    platform = str(duthost.facts.get("platform", ""))
    if not platform:
        pytest.fail("DUT platform is required for the NDRA container family")
    bundle = spec.build_bundle(
        name="ndra-{}".format(role),
        images=images,
        runtime_values={
            "HEALTH_MONITOR_IMAGE_VERSION": _image_version(images[HEALTH_MONITOR]),
            "NDRA_RUN_DIR": run_root,
            "NODE_NAME": joined_minikube_dut.node_name,
            "PLATFORM": platform,
            "REPAIR_AGENT_IMAGE_VERSION": _image_version(images[REPAIR_AGENT]),
        },
    )
    bundle = WorkloadBundle(
        name=bundle.name,
        containers=bundle.containers,
        host_network=True,
        host_pid=True,
        host_ipc=True,
        hostname="sonic",
    )
    expected_image_ids = {}
    for container_name, image in images.items():
        image_id = _image_id(duthost, image)
        if image_id is None:
            pytest.fail("Selected {} image is not present on the DUT".format(container_name))
        expected_image_ids[container_name] = image_id

    with _isolated_host_state(duthost, ownership_id):
        with deploy_workload(
            MinikubeCommandBoundary.from_joined_dut(joined_minikube_dut),
            bundle,
            "default",
            joined_minikube_dut.node_name,
            ownership_id,
            owned_host_paths=(run_root,),
        ) as workload:
            for container_name in spec.container_names:
                actual_image_id = _runtime_image_id(duthost, workload.pod_uid, container_name)
                if _normalized_image_id(actual_image_id) != _normalized_image_id(
                    expected_image_ids[container_name]
                ):
                    pytest.fail("Kubernetes started a different {} image ID".format(container_name))
            deployment = NdraDeployment(workload, duthost, run_root)
            logger.info(
                "Kubernetes NDRA target role=%s images=%s dut=%s node=%s namespace=%s pod=%s resource=%s run=%s",
                role,
                images,
                duthost.hostname,
                workload.node_name,
                workload.namespace,
                workload.pod_name,
                workload.resource_name,
                run_root,
            )
            deployment.wait_for_repair_agent()
            yield deployment


@pytest.fixture(scope="module")
def kubernetes_ndra_workload(request, minikube_duthost):
    if _option(request, "--minikube-profile", DEFAULT_PROFILE) != DEFAULT_PROFILE:
        pytest.fail("Kubernetes NDRA image staging requires the default serialized Minikube profile")
    vmhosts = tuple(request.getfixturevalue("vmhosts") or ())
    if len(vmhosts) != 1:
        pytest.skip("Kubernetes NDRA qualification requires exactly one associated test server")
    try:
        minikube_cluster = request.getfixturevalue("minikube_cluster")
    except MinikubeLockHeldError as error:
        pytest.fail(
            "Minikube setup cannot use the associated test server: {}".format(error)
        )
    creds = creds_on_dut(minikube_duthost)
    spec = load_container_spec(SPEC_PATH)
    images = _selected_images(request, minikube_duthost, spec)
    staged_images = tuple(images.values()) + (PAUSE_IMAGE,)
    with minikube_cluster.joined_dut(minikube_duthost) as joined:
        try:
            with _stage_images(minikube_duthost, creds, staged_images):
                with _deployed_ndra_workload(request, minikube_duthost, joined, spec, images) as deployment:
                    yield deployment
        except BaseException as error:
            cleanup_errors = tuple(getattr(error, "cleanup_errors", ()))
            preserve_environment = (
                getattr(error, "preserve_workload_dependencies", False)
                or getattr(error, "preserve_environment", False)
            )
            if cleanup_errors and preserve_environment:
                joined.mark_workload_unclean(
                    "provider cleanup failed: {}".format("; ".join(cleanup_errors))
                )
            raise
