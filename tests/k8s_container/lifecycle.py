"""Owned Minikube workload lifecycle with an injectable command boundary."""

import json
import logging
import re
import shlex
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple

from tests.k8s_container.workload import WorkloadBundle
from tests.k8s_container.workload import ownership_node_label
from tests.k8s_container.workload import render_daemonset_json
from tests.k8s_container.workload import validate_ownership_id


logger = logging.getLogger(__name__)

OWNED_HOST_PATH_PREFIX = "/run/sonic-mgmt-k8s-"


class LifecycleError(RuntimeError):
    """Raised when workload setup, readiness, or cleanup cannot be proven."""


@dataclass(frozen=True)
class CommandResult:
    """Bounded command output returned to feature-native assertions."""

    rc: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class ContainerIdentity:
    """Requested and resolved identity for one ready container."""

    name: str
    requested_image: str
    resolved_image_id: str


@dataclass(frozen=True)
class PodIdentity:
    """The exact ready pod selected on the target node."""

    pod_name: str
    pod_uid: str
    node_name: str
    containers: Tuple[ContainerIdentity, ...]


@dataclass(frozen=True)
class ResourceIdentity:
    uid: str
    resource_version: str


@dataclass(frozen=True)
class DeployedWorkload:
    """Identity and assertion access for one ready workload."""

    dut_name: str
    node_name: str
    namespace: str
    provider: str
    workload_name: str
    resource_name: str
    ownership_id: str
    pod_name: str
    pod_uid: str
    containers: Tuple[ContainerIdentity, ...]
    started_at: datetime
    ready_at: datetime
    _boundary: Any

    def container(self, name: str) -> ContainerIdentity:
        for container in self.containers:
            if container.name == name:
                return container
        raise KeyError(name)

    def exec(self, container_name: str, command: Sequence[str]) -> CommandResult:
        """Execute one feature assertion command in a named workload container."""

        self.container(container_name)
        return self._boundary.exec_in_pod(
            self.namespace,
            self.pod_name,
            container_name,
            command,
        )


def _resource_name(bundle: WorkloadBundle, ownership_id: str) -> str:
    validate_ownership_id(ownership_id)
    return "{}-{}".format(bundle.name, ownership_id)


def _validate_owned_host_paths(paths: Iterable[str], ownership_id: str) -> Tuple[str, ...]:
    validate_ownership_id(ownership_id)
    validated = tuple(paths)
    run_root = "{}{}".format(OWNED_HOST_PATH_PREFIX, ownership_id)
    if any(not isinstance(path, str) or ".." in path.split("/") for path in validated):
        raise ValueError("owned host paths must be normalized strings")
    if validated:
        if validated[0] != run_root:
            raise ValueError("first owned host path must equal {}".format(run_root))
        if any(path != run_root and not path.startswith(run_root + "/") for path in validated[1:]):
            raise ValueError("owned host paths must remain below the per-run root")
    return validated


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@contextmanager
def deploy_workload(
    boundary: Any,
    bundle: WorkloadBundle,
    namespace: str,
    node_name: str,
    ownership_id: str,
    owned_host_paths: Sequence[str] = (),
    clock: Any = _utcnow,
):
    """Deploy, identify, and always remove one test-owned DaemonSet."""

    validate_ownership_id(ownership_id)
    paths = _validate_owned_host_paths(owned_host_paths, ownership_id)
    resource_name = _resource_name(bundle, ownership_id)
    started_at = clock()
    label_applied = False
    apply_attempted = False
    resource_uid = None
    pod_name = None
    primary_error = None
    acquired_paths = []
    host_path_identities = {}
    workload_absent = True
    label_key = ownership_node_label(ownership_id)
    label_value = ownership_id

    try:
        boundary.preflight(namespace, node_name)
        conflicting_nodes = boundary.nodes_with_label(label_key, label_value)
        if conflicting_nodes:
            raise LifecycleError(
                "ownership label {}={} already selects {}".format(
                    label_key,
                    label_value,
                    ", ".join(conflicting_nodes),
                )
            )
        previous_label = boundary.node_label(node_name, label_key)
        if previous_label is not None:
            raise LifecycleError(
                "target node {} already has ownership label {}={}".format(
                    node_name,
                    label_key,
                    previous_label,
                )
            )
        if boundary.daemonset_uid(namespace, resource_name, ownership_id) is not None:
            raise LifecycleError("DaemonSet already exists: {}/{}".format(namespace, resource_name))

        for path in paths:
            if boundary.owned_host_path_exists(path):
                raise LifecycleError("owned host path already exists: {}".format(path))
        for path in paths:
            identity = boundary.create_owned_host_path(path, ownership_id)
            acquired_paths.append(path)
            host_path_identities[path] = identity
        try:
            boundary.set_node_label(node_name, label_key, label_value)
            label_applied = True
        except Exception:
            label_applied = boundary.node_label(node_name, label_key) == label_value
            raise

        manifest = render_daemonset_json(bundle, namespace, node_name, ownership_id)
        apply_attempted = True
        workload_absent = False
        resource_uid = boundary.create_manifest(namespace, resource_name, manifest, ownership_id)
        boundary.wait_daemonset_ready(namespace, resource_name)
        identity = boundary.resolve_pod_identity(namespace, resource_name, node_name, bundle)
        pod_name = identity.pod_name
        ready_at = clock()

        yield DeployedWorkload(
            dut_name=boundary.dut_name,
            node_name=node_name,
            namespace=namespace,
            provider="minikube",
            workload_name=bundle.name,
            resource_name=resource_name,
            ownership_id=ownership_id,
            pod_name=identity.pod_name,
            pod_uid=identity.pod_uid,
            containers=identity.containers,
            started_at=started_at,
            ready_at=ready_at,
            _boundary=boundary,
        )
    except BaseException as error:
        primary_error = error
        if apply_attempted:
            try:
                boundary.collect_diagnostics(namespace, resource_name, pod_name)
            except Exception as diagnostic_error:
                logger.warning("Diagnostic collection failed: %s", diagnostic_error)
        raise
    finally:
        cleanup_errors = []
        cleanup_warnings = []
        pod_identities = ((pod_name, identity.pod_uid),) if pod_name else ()
        pod_capture_proven = not apply_attempted
        if apply_attempted:
            try:
                if resource_uid is None:
                    resource_uid = boundary.daemonset_uid(namespace, resource_name, ownership_id)
                if resource_uid is not None:
                    observed_pods = boundary.selected_pod_names(namespace, resource_uid)
                else:
                    observed_pods = boundary.selected_owned_pod_names(
                        namespace, resource_name, ownership_id
                    )
                pod_identities = tuple(sorted(set(pod_identities) | set(observed_pods)))
                pod_capture_proven = True
            except Exception as error:
                cleanup_errors.append("capture workload identity: {}".format(error))
            try:
                if resource_uid is not None:
                    boundary.delete_daemonset(namespace, resource_name, ownership_id, resource_uid)
            except Exception as error:
                cleanup_warnings.append("delete owned DaemonSet: {}".format(error))
            try:
                boundary.verify_workload_absent(
                    namespace,
                    resource_name,
                    ownership_id,
                    resource_uid,
                    pod_identities,
                )
                workload_absent = pod_capture_proven
                if not pod_capture_proven:
                    cleanup_errors.append("preserved dependencies because pod identity capture failed")
            except Exception as error:
                workload_absent = False
                cleanup_errors.append("verify workload absence: {}".format(error))
        if label_applied and workload_absent:
            try:
                boundary.remove_node_label(node_name, label_key, label_value)
            except Exception as error:
                cleanup_errors.append("remove node label: {}".format(error))
            try:
                if boundary.node_label(node_name, label_key) is not None:
                    raise LifecycleError("ownership label remains on target node")
            except Exception as error:
                cleanup_errors.append("verify label restoration: {}".format(error))
        elif label_applied:
            cleanup_errors.append("preserved node label because workload absence was not proven")
        if workload_absent:
            for path in reversed(acquired_paths):
                try:
                    boundary.remove_owned_host_path(
                        path, ownership_id, host_path_identities[path]
                    )
                except Exception as error:
                    cleanup_errors.append("remove {}: {}".format(path, error))
        elif acquired_paths:
            cleanup_errors.append("preserved host paths because workload absence was not proven")

        if cleanup_warnings:
            logger.warning("Workload cleanup recovered after: %s", "; ".join(cleanup_warnings))
        if cleanup_errors:
            details = cleanup_warnings + cleanup_errors
            message = "workload cleanup failed: {}".format("; ".join(details))
            preserve_dependencies = not workload_absent
            if preserve_dependencies:
                boundary.mark_workload_unclean(message)
            logger.error("%s", message)
            if primary_error is not None:
                existing = tuple(getattr(primary_error, "cleanup_errors", ()))
                setattr(primary_error, "cleanup_errors", existing + tuple(cleanup_errors))
                if preserve_dependencies:
                    setattr(primary_error, "preserve_workload_dependencies", True)
            else:
                cleanup_error = LifecycleError(message)
                setattr(cleanup_error, "cleanup_errors", tuple(cleanup_errors))
                if preserve_dependencies:
                    setattr(cleanup_error, "preserve_workload_dependencies", True)
                raise cleanup_error


class MinikubeCommandBoundary:
    """Ansible-host-backed command boundary for one joined Minikube DUT."""

    def __init__(
        self,
        vmhost: Any,
        duthost: Any,
        profile: str,
        minikube_binary: str,
        command_environment: Dict[str, str],
        vmhost_user: str,
        expected_node_uid: str,
        join_owner_token: str,
        workload_owner: Any,
        timeout_seconds: int = 180,
    ):
        self.vmhost = vmhost
        self.duthost = duthost
        self.dut_name = duthost.hostname
        self.profile = profile
        self.minikube_binary = minikube_binary
        self.command_environment = dict(command_environment)
        self.vmhost_user = vmhost_user
        self.expected_node_uid = expected_node_uid
        self.join_owner_token = join_owner_token
        self.workload_owner = workload_owner
        self.timeout_seconds = timeout_seconds

    @classmethod
    def from_joined_dut(cls, joined):
        if not joined.cluster._entered or not joined.node_uid:
            raise LifecycleError("workload boundary requires a ready joined DUT")
        cluster = joined.cluster
        return cls(
            cluster.vmhost,
            joined.duthost,
            profile=cluster.spec.profile,
            minikube_binary=cluster.spec.binary_path,
            command_environment=cluster.command_environment,
            vmhost_user=cluster.vmhost_user,
            expected_node_uid=joined.node_uid,
            join_owner_token=joined.ownership_token,
            workload_owner=joined,
            timeout_seconds=min(180, cluster.spec.timeout_seconds),
        )

    def _minikube(self, arguments: Sequence[str]) -> str:
        environment = " ".join(
            "{}={}".format(key, shlex.quote(value))
            for key, value in sorted(self.command_environment.items())
            if value
        )
        command = (self.minikube_binary, "--profile", self.profile) + tuple(arguments)
        inner = "{} {}".format(
            environment,
            " ".join(shlex.quote(str(argument)) for argument in command),
        ).strip()
        return "sudo --user={} --set-home sh -c {}".format(
            shlex.quote(self.vmhost_user), shlex.quote(inner)
        )

    def _kubectl(self, arguments: Sequence[str], ignore_errors: bool = False) -> CommandResult:
        command = self._minikube(("kubectl", "--") + tuple(arguments))
        result = self.vmhost.shell(command, module_ignore_errors=True, verbose=False)
        normalized = CommandResult(
            rc=result.get("rc", 1),
            stdout=result.get("stdout", ""),
            stderr=result.get("stderr", ""),
        )
        if normalized.rc != 0 and not ignore_errors:
            raise LifecycleError(
                "kubectl command failed (rc={}): {}".format(normalized.rc, normalized.stderr.strip())
            )
        return normalized

    def _run_vm(
        self,
        command: str,
        stdin: Optional[str] = None,
    ) -> CommandResult:
        result = self.vmhost.shell(
            command,
            stdin=stdin,
            module_ignore_errors=True,
            verbose=False,
        )
        return CommandResult(result.get("rc", 1), result.get("stdout", ""), result.get("stderr", ""))

    def _run_dut(self, command: str, stdin: Optional[str] = None) -> CommandResult:
        result = self.duthost.shell(
            command,
            stdin=stdin,
            module_ignore_errors=True,
        )
        return CommandResult(result.get("rc", 1), result.get("stdout", ""), result.get("stderr", ""))

    def _kubectl_mutate(self, arguments: Sequence[str], stdin: Optional[str] = None) -> CommandResult:
        result = self._run_vm(
            self._minikube(("kubectl", "--") + tuple(arguments)),
            stdin=stdin,
        )
        if result.rc != 0:
            raise LifecycleError("kubectl mutation failed: {}".format(result.stderr.strip()))
        return result

    def _kubectl_json(self, arguments: Sequence[str]) -> Dict[str, Any]:
        result = self._kubectl(tuple(arguments) + ("-o", "json"))
        try:
            return json.loads(result.stdout)
        except ValueError as error:
            raise LifecycleError("kubectl returned invalid JSON: {}".format(error))

    def _joined_node(self, node_name: str) -> Dict[str, Any]:
        data = self._kubectl_json(("get", "node", node_name))
        metadata = data.get("metadata", {})
        if metadata.get("name") != node_name:
            raise LifecycleError("Kubernetes node name changed from the joined DUT")
        if metadata.get("uid") != self.expected_node_uid:
            raise LifecycleError("Kubernetes node UID changed from the joined DUT")
        owner = metadata.get("labels", {}).get("sonic-mgmt.test/join-owner")
        if owner != self.join_owner_token:
            raise LifecycleError("Kubernetes node join owner changed from the joined DUT")
        return data

    def mark_workload_unclean(self, message: str) -> None:
        self.workload_owner.mark_workload_unclean(message)

    def preflight(self, namespace: str, node_name: str) -> None:
        minikube = self.vmhost.shell(
            self._minikube(("status", "--output=json")),
            module_ignore_errors=True,
            verbose=False,
        )
        try:
            status = json.loads(minikube.get("stdout", ""))
        except ValueError as error:
            raise LifecycleError("Minikube status returned invalid JSON: {}".format(error))
        if minikube.get("rc", 1) != 0 or status.get("APIServer") != "Running":
            raise LifecycleError("Minikube API server is not running")

        server_version = self._kubectl_json(("version",))
        git_version = server_version.get("serverVersion", {}).get("gitVersion", "")
        if git_version != "v1.22.2":
            raise LifecycleError("expected Kubernetes v1.22.2, found {}".format(git_version))

        self._kubectl(("get", "namespace", namespace))
        node = self._joined_node(node_name)
        if node.get("metadata", {}).get("name") != self.dut_name:
            raise LifecycleError("Kubernetes node does not match the selected DUT")
        ready = any(
            condition.get("type") == "Ready" and condition.get("status") == "True"
            for condition in node.get("status", {}).get("conditions", ())
        )
        if not ready or node.get("spec", {}).get("unschedulable"):
            raise LifecycleError("selected DUT node is not ready and schedulable")
        runtime = node.get("status", {}).get("nodeInfo", {}).get("containerRuntimeVersion", "")
        if not runtime.startswith("docker://"):
            raise LifecycleError("expected Docker runtime on selected DUT node, found {}".format(runtime))
        blocking_taints = {
            taint.get("key")
            for taint in node.get("spec", {}).get("taints", ())
            if taint.get("effect") in ("NoSchedule", "NoExecute")
        }
        if blocking_taints:
            raise LifecycleError("selected DUT node has blocking taints: {}".format(", ".join(sorted(blocking_taints))))

    def nodes_with_label(self, key: str, value: str) -> Tuple[str, ...]:
        self._joined_node(self.dut_name)
        data = self._kubectl_json(("get", "nodes", "-l", "{}={}".format(key, value)))
        names = tuple(item["metadata"]["name"] for item in data.get("items", ()))
        return names

    def node_label(self, node_name: str, key: str) -> Optional[str]:
        try:
            data = self._joined_node(node_name)
        except LifecycleError as error:
            if "NotFound" in str(error):
                return None
            raise
        return data.get("metadata", {}).get("labels", {}).get(key)

    def set_node_label(self, node_name: str, key: str, value: str) -> None:
        node = self._joined_node(node_name)
        if key in node.get("metadata", {}).get("labels", {}):
            raise LifecycleError("node label already exists: {}".format(key))
        patch = [
            {
                "op": "test",
                "path": "/metadata/uid",
                "value": self.expected_node_uid,
            },
            {
                "op": "test",
                "path": "/metadata/labels/sonic-mgmt.test~1join-owner",
                "value": self.join_owner_token,
            },
            {
                "op": "add",
                "path": "/metadata/labels/{}".format(self._json_pointer(key)),
                "value": value,
            },
        ]
        self._kubectl_mutate(("patch", "node", node_name, "--type=json", "-p", json.dumps(patch)))

    def remove_node_label(self, node_name: str, key: str, expected_value: str) -> None:
        try:
            node = self._joined_node(node_name)
        except LifecycleError as error:
            if "NotFound" in str(error):
                return
            raise
        current_value = node.get("metadata", {}).get("labels", {}).get(key)
        if current_value != expected_value:
            raise LifecycleError(
                "refusing to remove node label {}: expected {}, found {}".format(
                    key,
                    expected_value,
                    current_value,
                )
            )
        path = "/metadata/labels/{}".format(self._json_pointer(key))
        patch = [
            {
                "op": "test",
                "path": "/metadata/uid",
                "value": self.expected_node_uid,
            },
            {
                "op": "test",
                "path": "/metadata/labels/sonic-mgmt.test~1join-owner",
                "value": self.join_owner_token,
            },
            {"op": "test", "path": path, "value": expected_value},
            {"op": "remove", "path": path},
        ]
        self._kubectl_mutate(("patch", "node", node_name, "--type=json", "-p", json.dumps(patch)))

    @staticmethod
    def _json_pointer(value: str) -> str:
        return value.replace("~", "~0").replace("/", "~1")

    @staticmethod
    def _host_root(ownership_id: str) -> str:
        validate_ownership_id(ownership_id)
        return "{}{}".format(OWNED_HOST_PATH_PREFIX, ownership_id)

    def _verify_host_path(self, path: str, ownership_id: str, path_identity: str) -> None:
        root = self._host_root(ownership_id)
        if path != root and not path.startswith(root + "/"):
            raise LifecycleError("owned host path is outside its root")
        marker = "{}/.sonic-mgmt-owner".format(path)
        result = self.duthost.shell(
            "sudo sh -c 'test -d \"$1\" && test ! -L \"$1\" && "
            "test -f \"$2\" && test ! -L \"$2\" && "
            "test \"$(cat \"$2\")\" = \"$3\" && "
            "test \"$(stat -c %d:%i \"$1\")\" = \"$4\" && "
            "test \"$(stat -c %u:%g:%a \"$2\")\" = 0:0:600' sh {} {} {} {}".format(
                shlex.quote(path), shlex.quote(marker), shlex.quote(ownership_id), shlex.quote(path_identity)
            ),
            module_ignore_errors=True,
        )
        if result.get("rc", 1) != 0:
            raise LifecycleError("owned host root marker or immutable identity changed")

    def create_owned_host_path(
        self,
        path: str,
        ownership_id: str,
    ) -> str:
        root = self._host_root(ownership_id)
        if path != root and not path.startswith(root + "/"):
            raise LifecycleError("owned child path is outside the exact root")
        marker = "{}/.sonic-mgmt-owner".format(path)
        script = r"""set -eu
path="$1" marker="$2" token="$3"
mkdir -m 0755 -- "$path"
cleanup() {
  if [ -f "$marker" ] && [ ! -L "$marker" ] && [ "$(cat "$marker")" = "$token" ]; then
    rm -f -- "$marker"
    rmdir -- "$path" 2>/dev/null || true
  fi
}
trap cleanup EXIT
umask 077
printf '%s\n' "$token" > "$marker"
chown root:root "$marker"
chmod 0600 "$marker"
test ! -L "$path"
stat -c '%d:%i' "$path"
trap - EXIT
"""
        result = self._run_dut(
            "sudo sh -c {} sh {} {} {}".format(
                shlex.quote(script), shlex.quote(path), shlex.quote(marker), shlex.quote(ownership_id)
            ),
        )
        identity = result.stdout.strip()
        if result.rc != 0 or not identity:
            raise LifecycleError("unable to create marked owned host path {}".format(path))
        self._verify_host_path(path, ownership_id, identity)
        return identity

    def owned_host_path_exists(self, path: str) -> bool:
        result = self.duthost.shell("test -e {}".format(shlex.quote(path)), module_ignore_errors=True)
        return result.get("rc", 1) == 0

    def remove_owned_host_path(self, path: str, ownership_id: str, path_identity: str) -> None:
        root = self._host_root(ownership_id)
        if path != root and not path.startswith(root + "/"):
            raise LifecycleError("refusing to remove a path outside its ownership root")
        marker = "{}/.sonic-mgmt-owner".format(path)
        result = self._run_dut(
            "sudo sh -c 'test -d \"$1\" && test ! -L \"$1\" && "
            "test \"$(readlink -f \"$1\")\" = \"$1\" && test -f \"$2\" && test ! -L \"$2\" && "
            "test \"$(cat \"$2\")\" = \"$3\" && test \"$(stat -c %d:%i \"$1\")\" = \"$4\" && "
            "test \"$(stat -c %u:%g:%a \"$2\")\" = 0:0:600 && "
            "rm -rf --one-file-system -- \"$1\"' sh {} {} {} {}".format(
                shlex.quote(path), shlex.quote(marker), shlex.quote(ownership_id), shlex.quote(path_identity)
            )
        )
        if result.rc != 0:
            raise LifecycleError("owned host path removal failed")
        if self.owned_host_path_exists(path):
            raise LifecycleError("owned host path remains: {}".format(path))

    def daemonset_uid(self, namespace: str, resource_name: str, ownership_id: str) -> Optional[str]:
        identity = self.daemonset_identity(namespace, resource_name, ownership_id)
        return identity.uid if identity is not None else None

    def daemonset_identity(
        self,
        namespace: str,
        resource_name: str,
        ownership_id: str,
    ) -> Optional[ResourceIdentity]:
        result = self._kubectl(
            ("get", "daemonset/{}".format(resource_name), "--namespace", namespace, "-o", "json"),
            ignore_errors=True,
        )
        if result.rc != 0:
            if "Error from server (NotFound)" in result.stderr:
                return None
            raise LifecycleError("unable to inspect DaemonSet: {}".format(result.stderr.strip()))
        try:
            data = json.loads(result.stdout)
        except ValueError as error:
            raise LifecycleError("DaemonSet lookup returned invalid JSON: {}".format(error))
        owner = data.get("metadata", {}).get("labels", {}).get("sonic-mgmt.test/owner")
        if owner != ownership_id:
            raise LifecycleError("DaemonSet name is occupied by a resource owned by {}".format(owner))
        template = data.get("spec", {}).get("template", {})
        node_name = template.get("metadata", {}).get("annotations", {}).get("sonic-mgmt.test/node-name")
        label_key = "sonic-mgmt.test/owner-{}".format(ownership_id)
        selector = template.get("spec", {}).get("nodeSelector", {})
        if node_name != self.dut_name or selector.get(label_key) != ownership_id:
            raise LifecycleError("DaemonSet owner does not bind to the exact joined DUT")
        metadata = data.get("metadata", {})
        uid = metadata.get("uid")
        resource_version = metadata.get("resourceVersion")
        if not uid or not resource_version:
            raise LifecycleError("DaemonSet identity is missing UID or resourceVersion")
        return ResourceIdentity(uid, resource_version)

    def create_manifest(
        self,
        namespace: str,
        resource_name: str,
        manifest: str,
        ownership_id: str,
    ) -> str:
        command = self._minikube((
            "kubectl",
            "--",
            "create",
            "-f",
            "-",
            "--namespace",
            namespace,
            "-o",
            "json",
        ))
        result = self._run_vm(command, stdin=manifest)
        if result.rc != 0:
            raise LifecycleError("DaemonSet creation failed: {}".format(result.stderr.strip()))
        try:
            created = json.loads(result.stdout)
        except ValueError as error:
            raise LifecycleError("DaemonSet creation returned invalid JSON: {}".format(error))
        metadata = created.get("metadata", {})
        if metadata.get("name") != resource_name:
            raise LifecycleError("DaemonSet creation returned an unexpected resource name")
        if metadata.get("labels", {}).get("sonic-mgmt.test/owner") != ownership_id:
            raise LifecycleError("DaemonSet creation returned an unexpected owner")
        resource_uid = metadata.get("uid")
        if not resource_uid:
            raise LifecycleError("created DaemonSet has no UID")
        return resource_uid

    def wait_daemonset_ready(self, namespace: str, resource_name: str) -> None:
        deadline = time.time() + self.timeout_seconds
        while time.time() < deadline:
            data = self._kubectl_json((
                "get",
                "daemonset/{}".format(resource_name),
                "--namespace",
                namespace,
            ))
            metadata = data.get("metadata", {})
            status = data.get("status", {})
            if (
                status.get("observedGeneration") == metadata.get("generation")
                and status.get("desiredNumberScheduled") == 1
                and status.get("currentNumberScheduled") == 1
                and status.get("numberReady") == 1
                and status.get("numberAvailable") == 1
                and status.get("numberMisscheduled", 0) == 0
            ):
                return
            time.sleep(2)
        raise LifecycleError("DaemonSet did not become ready on the selected DUT")

    def resolve_pod_identity(
        self,
        namespace: str,
        resource_name: str,
        node_name: str,
        bundle: WorkloadBundle,
    ) -> PodIdentity:
        self._joined_node(node_name)
        data = self._kubectl_json((
            "get",
            "pods",
            "--namespace",
            namespace,
            "--selector",
            "app.kubernetes.io/instance={}".format(resource_name),
            "--field-selector",
            "spec.nodeName={}".format(node_name),
        ))
        pods = data.get("items", ())
        if len(pods) != 1:
            raise LifecycleError("expected one workload pod on {}, found {}".format(node_name, len(pods)))
        pod = pods[0]
        statuses = {
            status["name"]: status
            for status in pod.get("status", {}).get("containerStatuses", ())
        }
        identities = []
        for container in bundle.containers:
            status = statuses.get(container.name)
            if status is None or not status.get("ready") or not status.get("imageID"):
                raise LifecycleError("container {} is not ready with a resolved image ID".format(container.name))
            identities.append(ContainerIdentity(container.name, container.image, status["imageID"]))
        return PodIdentity(
            pod_name=pod["metadata"]["name"],
            pod_uid=pod["metadata"]["uid"],
            node_name=pod["spec"]["nodeName"],
            containers=tuple(identities),
        )

    def exec_in_pod(
        self,
        namespace: str,
        pod_name: str,
        container_name: str,
        command: Sequence[str],
    ) -> CommandResult:
        if not isinstance(command, (tuple, list)) or not command:
            raise ValueError("command must be a non-empty list or tuple")
        return self._kubectl((
            "exec",
            "--namespace",
            namespace,
            pod_name,
            "--container",
            container_name,
            "--",
        ) + tuple(command), ignore_errors=True)

    def collect_diagnostics(self, namespace: str, resource_name: str, pod_name: Optional[str]) -> None:
        diagnostics = {"daemonset": None, "pods": [], "events": []}
        daemonset = self._kubectl(
            ("get", "daemonset/{}".format(resource_name), "--namespace", namespace, "-o", "json"),
            ignore_errors=True,
        )
        if daemonset.rc == 0:
            data = self._safe_json(daemonset.stdout)
            diagnostics["daemonset"] = {
                "name": data.get("metadata", {}).get("name"),
                "uid": data.get("metadata", {}).get("uid"),
                "generation": data.get("metadata", {}).get("generation"),
                "status": {
                    key: data.get("status", {}).get(key)
                    for key in (
                        "currentNumberScheduled", "desiredNumberScheduled", "numberAvailable",
                        "numberMisscheduled", "numberReady", "numberUnavailable", "observedGeneration",
                    )
                },
            }
        elif daemonset.stderr:
            diagnostics["daemonsetError"] = self._sanitize_text(daemonset.stderr)
        pods = self._kubectl(
            (
                "get", "pods", "--namespace", namespace, "--selector",
                "app.kubernetes.io/instance={}".format(resource_name), "-o", "json",
            ),
            ignore_errors=True,
        )
        if pods.rc == 0:
            for pod in self._safe_json(pods.stdout).get("items", ())[:20]:
                diagnostics["pods"].append({
                    "name": pod.get("metadata", {}).get("name"),
                    "uid": pod.get("metadata", {}).get("uid"),
                    "node": pod.get("spec", {}).get("nodeName"),
                    "phase": pod.get("status", {}).get("phase"),
                    "conditions": [
                        {
                            "type": condition.get("type"),
                            "status": condition.get("status"),
                            "reason": self._sanitize_text(condition.get("reason", "")),
                            "message": self._sanitize_text(condition.get("message", "")),
                        }
                        for condition in pod.get("status", {}).get("conditions", ())[:20]
                    ],
                    "containers": [
                        {
                            "name": status.get("name"),
                            "ready": status.get("ready"),
                            "restartCount": status.get("restartCount"),
                            "state": self._container_state(status.get("state", {})),
                        }
                        for status in pod.get("status", {}).get("containerStatuses", ())[:20]
                    ],
                })
        elif pods.stderr:
            diagnostics["podsError"] = self._sanitize_text(pods.stderr)
        events = self._kubectl(
            (
                "get", "events", "--namespace", namespace, "--field-selector",
                "involvedObject.name={}".format(pod_name or resource_name), "-o", "json",
            ),
            ignore_errors=True,
        )
        if events.rc == 0:
            diagnostics["events"] = [
                {
                    "reason": self._sanitize_text(item.get("reason", "")),
                    "message": self._sanitize_text(item.get("message", "")),
                    "count": item.get("count"),
                    "type": item.get("type"),
                }
                for item in self._safe_json(events.stdout).get("items", ())[-20:]
            ]
        elif events.stderr:
            diagnostics["eventsError"] = self._sanitize_text(events.stderr)
        logger.warning("Workload diagnostic status: %s", json.dumps(diagnostics, sort_keys=True)[:8192])

    @staticmethod
    def _safe_json(value: str) -> Dict[str, Any]:
        try:
            document = json.loads(value)
        except ValueError:
            return {}
        return document if isinstance(document, dict) else {}

    @classmethod
    def _sanitize_text(cls, value: Any) -> str:
        text = str(value).replace("\n", " ")[:512]
        return re.sub(
            r"(?i)(password|passwd|token|secret|authorization|credential|private[_ -]?key)\s*[:=]\s*\S+",
            r"\1=<redacted>",
            text,
        )

    @classmethod
    def _container_state(cls, state: Mapping[str, Any]) -> Dict[str, Any]:
        for name in ("waiting", "terminated", "running"):
            value = state.get(name)
            if isinstance(value, dict):
                return {
                    "type": name,
                    "reason": cls._sanitize_text(value.get("reason", "")),
                    "message": cls._sanitize_text(value.get("message", "")),
                    "exitCode": value.get("exitCode"),
                }
        return {}

    def selected_pod_names(self, namespace: str, daemonset_uid: str) -> Tuple[Tuple[str, str], ...]:
        data = self._kubectl_json(("get", "pods", "--namespace", namespace))
        identities = []
        for item in data.get("items", ()):
            owners = item.get("metadata", {}).get("ownerReferences", ())
            if any(owner.get("uid") == daemonset_uid for owner in owners):
                identities.append((item["metadata"]["name"], item["metadata"]["uid"]))
        return tuple(identities)

    def selected_owned_pod_names(
        self,
        namespace: str,
        resource_name: str,
        ownership_id: str,
    ) -> Tuple[Tuple[str, str], ...]:
        selector = "app.kubernetes.io/instance={},sonic-mgmt.test/owner={}".format(
            resource_name, ownership_id
        )
        data = self._kubectl_json(("get", "pods", "--namespace", namespace, "--selector", selector))
        identities = []
        for item in data.get("items", ()):
            metadata = item.get("metadata", {})
            labels = metadata.get("labels", {})
            node_name = metadata.get("annotations", {}).get("sonic-mgmt.test/node-name")
            if (
                labels.get("app.kubernetes.io/instance") != resource_name
                or labels.get("sonic-mgmt.test/owner") != ownership_id
                or node_name != self.dut_name
                or not metadata.get("name")
                or not metadata.get("uid")
            ):
                raise LifecycleError("owned pod identity is invalid")
            identities.append((metadata["name"], metadata["uid"]))
        return tuple(identities)

    def delete_owned_pod(self, namespace: str, pod_name: str, expected_uid: str) -> None:
        result = self._kubectl(
            ("get", "pod/{}".format(pod_name), "--namespace", namespace, "-o", "json"),
            ignore_errors=True,
        )
        if result.rc != 0:
            if "Error from server (NotFound)" in result.stderr:
                return
            raise LifecycleError("unable to inspect owned pod: {}".format(result.stderr.strip()))
        try:
            pod = json.loads(result.stdout)
        except ValueError as error:
            raise LifecycleError("owned pod lookup returned invalid JSON: {}".format(error))
        if pod.get("metadata", {}).get("uid") != expected_uid:
            raise LifecycleError("refusing to delete a changed pod UID")
        options = {
            "apiVersion": "v1",
            "gracePeriodSeconds": 0,
            "kind": "DeleteOptions",
            "preconditions": {"uid": expected_uid},
            "propagationPolicy": "Background",
        }
        url = "/api/v1/namespaces/{}/pods/{}".format(namespace, pod_name)
        command = self._minikube(("kubectl", "--", "delete", "--raw", url, "-f", "-"))
        deletion = self._run_vm(command, stdin=json.dumps(options))
        if deletion.rc != 0 and "NotFound" not in deletion.stderr:
            raise LifecycleError("UID-preconditioned pod deletion failed: {}".format(deletion.stderr.strip()))

    def delete_daemonset(
        self,
        namespace: str,
        resource_name: str,
        ownership_id: str,
        expected_uid: str,
    ) -> None:
        current = self.daemonset_identity(namespace, resource_name, ownership_id)
        if current is None:
            return
        if current.uid != expected_uid:
            raise LifecycleError(
                "refusing to delete DaemonSet UID {}; expected {}".format(current.uid, expected_uid)
            )
        delete_options = {
            "apiVersion": "v1",
            "kind": "DeleteOptions",
            "preconditions": {"uid": expected_uid, "resourceVersion": current.resource_version},
            "propagationPolicy": "Foreground",
        }
        url = "/apis/apps/v1/namespaces/{}/daemonsets/{}".format(namespace, resource_name)
        command = self._minikube(("kubectl", "--", "delete", "--raw", url, "-f", "-"))
        result = self._run_vm(command, stdin=json.dumps(delete_options))
        if result.rc != 0:
            raise LifecycleError("UID-preconditioned DaemonSet deletion failed: {}".format(
                result.stderr.strip()
            ))

    def verify_workload_absent(
        self,
        namespace: str,
        resource_name: str,
        ownership_id: str,
        daemonset_uid: Optional[str],
        pod_identities: Sequence[Tuple[str, str]],
    ) -> None:
        deadline = time.time() + self.timeout_seconds
        observed_pods = set(pod_identities)
        removal_attempted = set()
        while time.time() < deadline:
            current_uid = self.daemonset_uid(namespace, resource_name, ownership_id)
            remaining_pods = (
                self.selected_pod_names(namespace, daemonset_uid)
                if daemonset_uid
                else self.selected_owned_pod_names(namespace, resource_name, ownership_id)
            )
            observed_pods.update(remaining_pods)
            if current_uid is None and not remaining_pods:
                break
            if current_uid is None:
                for _, pod_uid in remaining_pods:
                    if pod_uid in removal_attempted:
                        continue
                    result = self.duthost.shell(
                        "docker ps -aq --filter {}".format(
                            shlex.quote("label=io.kubernetes.pod.uid={}".format(pod_uid))
                        ),
                        module_ignore_errors=True,
                    )
                    container_ids = result.get("stdout", "").split()
                    if result.get("rc", 1) == 0 and container_ids:
                        removal = self.duthost.shell(
                            "docker rm --force {}".format(
                                " ".join(shlex.quote(value) for value in container_ids)
                            ),
                            module_ignore_errors=True,
                        )
                        if removal.get("rc", 1) == 0:
                            removal_attempted.add(pod_uid)
            for pod_name, pod_uid in remaining_pods:
                self.delete_owned_pod(namespace, pod_name, pod_uid)
            time.sleep(2)
        else:
            raise LifecycleError("DaemonSet or owned pods remain after deletion")

        runtime_deadline = time.time() + self.timeout_seconds
        removal_attempted = set()
        while time.time() < runtime_deadline:
            remaining = []
            query_failed = []
            for pod_name, pod_uid in sorted(observed_pods):
                result = self.duthost.shell(
                    "docker ps -aq --filter {}".format(
                        shlex.quote("label=io.kubernetes.pod.uid={}".format(pod_uid))
                    ),
                    module_ignore_errors=True,
                )
                if result.get("rc", 1) != 0:
                    query_failed.append(pod_name)
                elif result.get("stdout", "").strip():
                    remaining.append(pod_name)
                    if pod_uid not in removal_attempted:
                        container_ids = result.get("stdout", "").split()
                        removal = self.duthost.shell(
                            "docker rm --force {}".format(
                                " ".join(shlex.quote(value) for value in container_ids)
                            ),
                            module_ignore_errors=True,
                        )
                        if removal.get("rc", 1) == 0:
                            removal_attempted.add(pod_uid)
            if not remaining and not query_failed:
                return
            time.sleep(2)
        if query_failed:
            raise LifecycleError("unable to verify host-container absence for pods {}".format(
                ", ".join(query_failed)
            ))
        raise LifecycleError("host containers remain for pods {}".format(", ".join(remaining)))
