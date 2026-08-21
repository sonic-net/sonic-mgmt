"""Validated workload declarations and deterministic Kubernetes rendering."""

import json
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple, Union


_DNS_LABEL = re.compile(r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$")
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_PORT_NAME = re.compile(r"^[a-z0-9](?:[a-z0-9]|-(?!-))*[a-z0-9]$|^[a-z0-9]$")
_IMAGE_TAG = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
_IMAGE_REPOSITORY_COMPONENT = re.compile(r"^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$")
_IMAGE_DOMAIN_COMPONENT = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_IMAGE_DIGEST_LENGTHS = {"sha256": 64, "sha384": 96, "sha512": 128}
_INT32_MAX = 2 ** 31 - 1
_INT64_MAX = 2 ** 63 - 1
_FIELD_PATHS = {
    "metadata.name",
    "metadata.namespace",
    "metadata.uid",
    "spec.nodeName",
    "spec.serviceAccountName",
    "status.hostIP",
    "status.podIP",
    "status.podIPs",
}
_HOST_PATH_TYPES = {
    "BlockDevice",
    "CharDevice",
    "Directory",
    "DirectoryOrCreate",
    "File",
    "FileOrCreate",
    "Socket",
}
_IMAGE_PULL_POLICIES = {"Always", "IfNotPresent", "Never"}


def _validate_dns_label(value: str, field_name: str) -> None:
    if not isinstance(value, str) or len(value) > 63 or not _DNS_LABEL.fullmatch(value):
        raise ValueError("{} must be a Kubernetes DNS label".format(field_name))


def _validate_dns_subdomain(value: str, field_name: str) -> None:
    if not isinstance(value, str) or len(value) > 253:
        raise ValueError("{} must be a Kubernetes DNS subdomain".format(field_name))
    if any(len(label) > 63 or not _DNS_LABEL.fullmatch(label) for label in value.split(".")):
        raise ValueError("{} must be a Kubernetes DNS subdomain".format(field_name))


def _validate_bool(value: bool, field_name: str) -> None:
    if type(value) is not bool:
        raise ValueError("{} must be a boolean".format(field_name))


def _validate_ordered_sequence(value: Sequence[Any], field_name: str) -> None:
    if not isinstance(value, (list, tuple)):
        raise ValueError("{} must be a list or tuple".format(field_name))


def _validate_absolute_path(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value.startswith("/") or ".." in value.split("/"):
        raise ValueError("{} must be absolute and cannot contain '..'".format(field_name))


def _validate_image_registry(registry: str) -> None:
    host, separator, port = registry.rpartition(":")
    if not separator:
        host = registry
    elif not port.isdigit() or not 0 < int(port) <= 65535:
        raise ValueError("image registry port is invalid")

    if host == "localhost":
        return
    if not host or any(not _IMAGE_DOMAIN_COMPONENT.fullmatch(label) for label in host.split(".")):
        raise ValueError("image registry is invalid")


def _validate_image_repository(repository: str) -> None:
    if not repository or len(repository) > 255 or repository.startswith("/") or repository.endswith("/"):
        raise ValueError("image repository is invalid")
    components = repository.split("/")
    if any(not component for component in components):
        raise ValueError("image repository is invalid")

    if len(components) > 1 and ("." in components[0] or ":" in components[0] or components[0] == "localhost"):
        _validate_image_registry(components.pop(0))
    if any(not _IMAGE_REPOSITORY_COMPONENT.fullmatch(component) for component in components):
        raise ValueError("image repository is invalid")


def _validate_image(image: str) -> None:
    if not isinstance(image, str) or not image or any(character.isspace() for character in image):
        raise ValueError("image must be a non-empty reference without whitespace")

    if "@" in image:
        if image.count("@") != 1:
            raise ValueError("image digest reference is invalid")
        repository, digest = image.split("@", 1)
        _validate_image_repository(repository)
        if ":" not in digest:
            raise ValueError("image digest must include an algorithm and hexadecimal value")
        algorithm, hexadecimal = digest.split(":", 1)
        expected_length = _IMAGE_DIGEST_LENGTHS.get(algorithm)
        if (
            expected_length is None
            or len(hexadecimal) != expected_length
            or not re.fullmatch(r"[0-9a-f]+", hexadecimal)
        ):
            raise ValueError("image digest is invalid")
        return

    last_slash = image.rfind("/")
    tag_separator = image.rfind(":")
    if tag_separator <= last_slash:
        raise ValueError("image must use an explicit non-latest tag or digest")
    repository, tag = image[:tag_separator], image[tag_separator + 1:]
    _validate_image_repository(repository)
    if not _IMAGE_TAG.fullmatch(tag) or tag.lower() == "latest":
        raise ValueError("image must use an explicit non-latest tag or digest")


def validate_ownership_id(ownership_id: str) -> str:
    """Return one canonical UUID ownership token or raise ValueError."""

    try:
        parsed = uuid.UUID(ownership_id)
    except (AttributeError, TypeError, ValueError):
        raise ValueError("ownership_id must be a canonical UUID")
    if str(parsed) != ownership_id:
        raise ValueError("ownership_id must be a canonical UUID")
    return ownership_id


def ownership_node_label(ownership_id: str) -> str:
    """Return the per-run node label key used by one workload."""

    validate_ownership_id(ownership_id)
    label_name = "owner-{}".format(ownership_id)
    _validate_dns_label(label_name, "ownership node label")
    return "sonic-mgmt.test/{}".format(label_name)


@dataclass(frozen=True)
class EnvVar:
    """A literal environment value or Kubernetes downward-API field reference."""

    name: str
    value: Optional[str] = None
    field_path: Optional[str] = None

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not _ENV_NAME.fullmatch(self.name):
            raise ValueError("environment variable name is invalid")
        if (self.value is None) == (self.field_path is None):
            raise ValueError("environment variable must set exactly one of value or field_path")
        if self.value is not None and not isinstance(self.value, str):
            raise ValueError("environment variable value must be a string")
        if self.field_path is not None and self.field_path not in _FIELD_PATHS:
            raise ValueError("unsupported environment field_path")


@dataclass(frozen=True)
class HostPathMount:
    """A named host path and its mount point inside one container."""

    name: str
    host_path: str
    mount_path: str
    read_only: bool = False
    host_path_type: Optional[str] = None

    def __post_init__(self) -> None:
        _validate_dns_label(self.name, "mount name")
        _validate_absolute_path(self.host_path, "host_path")
        _validate_absolute_path(self.mount_path, "mount_path")
        _validate_bool(self.read_only, "read_only")
        if self.host_path_type is not None and self.host_path_type not in _HOST_PATH_TYPES:
            raise ValueError("unsupported host_path_type: {}".format(self.host_path_type))


@dataclass(frozen=True)
class SecurityContext:
    """The security settings required by a workload container."""

    privileged: Optional[bool] = None
    run_as_user: Optional[int] = None
    read_only_root_filesystem: Optional[bool] = None
    capabilities_add: Tuple[str, ...] = field(default_factory=tuple)
    seccomp_profile_type: Optional[str] = None
    apparmor_profile_type: Optional[str] = None

    def __post_init__(self) -> None:
        if self.privileged is not None:
            _validate_bool(self.privileged, "privileged")
        if self.run_as_user is not None and (
            type(self.run_as_user) is not int or not 0 <= self.run_as_user <= _INT64_MAX
        ):
            raise ValueError("run_as_user must be a non-negative int64")
        if self.read_only_root_filesystem is not None:
            _validate_bool(self.read_only_root_filesystem, "read_only_root_filesystem")
        object.__setattr__(self, "capabilities_add", tuple(self.capabilities_add))
        if any(not isinstance(value, str) or not value for value in self.capabilities_add):
            raise ValueError("capabilities_add must contain non-empty strings")
        if len(self.capabilities_add) != len(set(self.capabilities_add)):
            raise ValueError("capabilities_add must contain unique values")
        if self.seccomp_profile_type not in (None, "RuntimeDefault", "Unconfined"):
            raise ValueError("unsupported seccomp profile type")
        if self.apparmor_profile_type not in (None, "RuntimeDefault", "Unconfined"):
            raise ValueError("unsupported AppArmor profile type")

    @classmethod
    def from_kubernetes(cls, declaration: Mapping[str, Any]) -> "SecurityContext":
        declaration = dict(declaration)
        capabilities = declaration.pop("capabilities", {})
        seccomp = declaration.pop("seccompProfile", {})
        apparmor = declaration.pop("appArmorProfile", {})
        unknown = sorted(
            set(declaration) - {"privileged", "runAsUser", "readOnlyRootFilesystem"}
        )
        if unknown:
            raise ValueError("unsupported securityContext fields: {}".format(unknown))
        if set(capabilities) - {"add"}:
            raise ValueError("only capabilities.add is supported")
        if set(seccomp) - {"type"} or set(apparmor) - {"type"}:
            raise ValueError("security profiles support only type")
        return cls(
            privileged=declaration.get("privileged"),
            run_as_user=declaration.get("runAsUser"),
            read_only_root_filesystem=declaration.get("readOnlyRootFilesystem"),
            capabilities_add=tuple(capabilities.get("add", ())),
            seccomp_profile_type=seccomp.get("type"),
            apparmor_profile_type=apparmor.get("type"),
        )


@dataclass(frozen=True)
class ExecReadinessProbe:
    """A bounded Kubernetes exec readiness probe."""

    command: Tuple[str, ...]
    initial_delay_seconds: int = 0
    period_seconds: int = 10
    timeout_seconds: int = 1
    failure_threshold: int = 3
    success_threshold: int = 1

    def __post_init__(self) -> None:
        _validate_ordered_sequence(self.command, "readiness command")
        object.__setattr__(self, "command", tuple(self.command))
        if not self.command or any(not isinstance(part, str) or not part for part in self.command):
            raise ValueError("readiness command must contain non-empty strings")
        for name in ("period_seconds", "timeout_seconds", "failure_threshold", "success_threshold"):
            if type(getattr(self, name)) is not int or not 0 < getattr(self, name) <= _INT32_MAX:
                raise ValueError("{} must be a positive int32".format(name))
        if type(self.initial_delay_seconds) is not int or not 0 <= self.initial_delay_seconds <= _INT32_MAX:
            raise ValueError("initial_delay_seconds must be a non-negative int32")


@dataclass(frozen=True)
class ContainerPort:
    """One Kubernetes container port."""

    container_port: int
    name: Optional[str] = None
    protocol: str = "TCP"

    def __post_init__(self) -> None:
        if type(self.container_port) is not int or not 0 < self.container_port <= 65535:
            raise ValueError("container_port must be between 1 and 65535")
        if self.name is not None and (
            not isinstance(self.name, str)
            or len(self.name) > 15
            or not _PORT_NAME.fullmatch(self.name)
            or not any(character.isalpha() for character in self.name)
        ):
            raise ValueError("container port name must be a valid IANA service name")
        if self.protocol not in ("TCP", "UDP", "SCTP"):
            raise ValueError("container port protocol must be TCP, UDP, or SCTP")


@dataclass(frozen=True)
class HttpReadinessProbe:
    """A bounded Kubernetes HTTP readiness probe."""

    path: str
    port: Union[int, str]
    host: Optional[str] = None
    scheme: str = "HTTP"
    initial_delay_seconds: int = 0
    period_seconds: int = 10
    timeout_seconds: int = 1
    failure_threshold: int = 3
    success_threshold: int = 1

    def __post_init__(self) -> None:
        _validate_absolute_path(self.path, "readiness HTTP path")
        named_port = (
            isinstance(self.port, str)
            and len(self.port) <= 15
            and _PORT_NAME.fullmatch(self.port)
        )
        if not named_port and (type(self.port) is not int or not 0 < self.port <= 65535):
            raise ValueError("readiness HTTP port must be a number or IANA service name")
        if self.host is not None and (not isinstance(self.host, str) or not self.host):
            raise ValueError("readiness HTTP host must be a non-empty string")
        if self.scheme not in ("HTTP", "HTTPS"):
            raise ValueError("readiness HTTP scheme must be HTTP or HTTPS")
        for name in ("period_seconds", "timeout_seconds", "failure_threshold", "success_threshold"):
            if type(getattr(self, name)) is not int or not 0 < getattr(self, name) <= _INT32_MAX:
                raise ValueError("{} must be a positive int32".format(name))
        if type(self.initial_delay_seconds) is not int or not 0 <= self.initial_delay_seconds <= _INT32_MAX:
            raise ValueError("initial_delay_seconds must be a non-negative int32")


@dataclass(frozen=True)
class ContainerSpec:
    """One version-pinned container in a workload bundle."""

    name: str
    image: str
    image_pull_policy: str = "IfNotPresent"
    environment: Tuple[EnvVar, ...] = field(default_factory=tuple)
    mounts: Tuple[HostPathMount, ...] = field(default_factory=tuple)
    ports: Tuple[ContainerPort, ...] = field(default_factory=tuple)
    security_context: Optional[SecurityContext] = None
    tty: bool = False
    liveness_probe: Optional[Union[ExecReadinessProbe, HttpReadinessProbe]] = None
    readiness_probe: Optional[Union[ExecReadinessProbe, HttpReadinessProbe]] = None

    def __post_init__(self) -> None:
        _validate_dns_label(self.name, "container name")
        _validate_image(self.image)
        if self.image_pull_policy not in _IMAGE_PULL_POLICIES:
            raise ValueError("unsupported image_pull_policy: {}".format(self.image_pull_policy))
        _validate_ordered_sequence(self.environment, "environment")
        _validate_ordered_sequence(self.mounts, "mounts")
        _validate_ordered_sequence(self.ports, "ports")
        object.__setattr__(self, "environment", tuple(self.environment))
        object.__setattr__(self, "mounts", tuple(self.mounts))
        object.__setattr__(self, "ports", tuple(self.ports))
        if any(not isinstance(variable, EnvVar) for variable in self.environment):
            raise ValueError("environment must contain EnvVar values")
        if any(not isinstance(mount, HostPathMount) for mount in self.mounts):
            raise ValueError("mounts must contain HostPathMount values")
        if any(not isinstance(port, ContainerPort) for port in self.ports):
            raise ValueError("ports must contain ContainerPort values")
        if self.security_context is not None and not isinstance(self.security_context, SecurityContext):
            raise ValueError("security_context must be a SecurityContext")
        _validate_bool(self.tty, "tty")
        if self.liveness_probe is not None and not isinstance(
            self.liveness_probe, (ExecReadinessProbe, HttpReadinessProbe)
        ):
            raise ValueError("liveness_probe must be an exec or HTTP probe")
        if self.readiness_probe is not None and not isinstance(
            self.readiness_probe, (ExecReadinessProbe, HttpReadinessProbe)
        ):
            raise ValueError("readiness_probe must be an exec or HTTP readiness probe")

        environment_names = [variable.name for variable in self.environment]
        if len(environment_names) != len(set(environment_names)):
            raise ValueError("container environment variable names must be unique")
        mount_paths = [mount.mount_path for mount in self.mounts]
        if len(mount_paths) != len(set(mount_paths)):
            raise ValueError("container mount paths must be unique")
        port_names = [port.name for port in self.ports if port.name is not None]
        if len(port_names) != len(set(port_names)):
            raise ValueError("container port names must be unique")
        if (
            isinstance(self.readiness_probe, HttpReadinessProbe)
            and isinstance(self.readiness_probe.port, str)
            and self.readiness_probe.port not in port_names
        ):
            raise ValueError("named readiness HTTP port must reference a declared container port")
        if (
            isinstance(self.liveness_probe, HttpReadinessProbe)
            and isinstance(self.liveness_probe.port, str)
            and self.liveness_probe.port not in port_names
        ):
            raise ValueError("named liveness HTTP port must reference a declared container port")


@dataclass(frozen=True)
class WorkloadBundle:
    """A node-scoped group of one or more SONiC containers."""

    name: str
    containers: Tuple[ContainerSpec, ...]
    host_network: bool = False
    host_pid: bool = False
    host_ipc: bool = False
    hostname: Optional[str] = None
    image_pull_secret: Optional[str] = None

    def __post_init__(self) -> None:
        _validate_dns_label(self.name, "bundle name")
        _validate_ordered_sequence(self.containers, "containers")
        object.__setattr__(self, "containers", tuple(self.containers))
        if not self.containers:
            raise ValueError("workload bundle must contain at least one container")
        if any(not isinstance(container, ContainerSpec) for container in self.containers):
            raise ValueError("containers must contain ContainerSpec values")

        container_names = [container.name for container in self.containers]
        if len(container_names) != len(set(container_names)):
            raise ValueError("container names must be unique")
        port_names = [
            port.name
            for container in self.containers
            for port in container.ports
            if port.name is not None
        ]
        if len(port_names) != len(set(port_names)):
            raise ValueError("container port names must be unique across the pod")
        if self.image_pull_secret is not None:
            _validate_dns_label(self.image_pull_secret, "image pull secret")
        if self.hostname is not None:
            _validate_dns_label(self.hostname, "hostname")
        for name in ("host_network", "host_pid", "host_ipc"):
            _validate_bool(getattr(self, name), name)

        volumes = {}
        for container in self.containers:
            for mount in container.mounts:
                source = (mount.host_path, mount.host_path_type)
                if mount.name in volumes and volumes[mount.name] != source:
                    raise ValueError("mount name {!r} refers to multiple host paths".format(mount.name))
                volumes[mount.name] = source


def _render_environment(environment: Sequence[EnvVar]) -> Sequence[Dict[str, Any]]:
    rendered = []
    for variable in environment:
        item: Dict[str, Any] = {"name": variable.name}
        if variable.value is not None:
            item["value"] = variable.value
        else:
            item["valueFrom"] = {
                "fieldRef": {
                    "apiVersion": "v1",
                    "fieldPath": variable.field_path,
                }
            }
        rendered.append(item)
    return rendered


def _render_security_context(context: SecurityContext) -> Dict[str, Any]:
    rendered = {}
    if context.privileged is not None:
        rendered["privileged"] = context.privileged
    if context.run_as_user is not None:
        rendered["runAsUser"] = context.run_as_user
    if context.read_only_root_filesystem is not None:
        rendered["readOnlyRootFilesystem"] = context.read_only_root_filesystem
    if context.capabilities_add:
        rendered["capabilities"] = {"add": list(context.capabilities_add)}
    if context.seccomp_profile_type is not None:
        rendered["seccompProfile"] = {"type": context.seccomp_profile_type}
    return rendered


def _render_readiness_probe(probe: Any) -> Dict[str, Any]:
    rendered = {
        "failureThreshold": probe.failure_threshold,
        "initialDelaySeconds": probe.initial_delay_seconds,
        "periodSeconds": probe.period_seconds,
        "successThreshold": probe.success_threshold,
        "timeoutSeconds": probe.timeout_seconds,
    }
    if isinstance(probe, ExecReadinessProbe):
        rendered["exec"] = {"command": list(probe.command)}
    else:
        http_get = {
            "path": probe.path,
            "port": probe.port,
            "scheme": probe.scheme,
        }
        if probe.host is not None:
            http_get["host"] = probe.host
        rendered["httpGet"] = http_get
    return rendered


def _render_container(container: ContainerSpec) -> Dict[str, Any]:
    rendered: Dict[str, Any] = {
        "image": container.image,
        "imagePullPolicy": container.image_pull_policy,
        "name": container.name,
    }
    if container.tty:
        rendered["tty"] = True
    if container.environment:
        rendered["env"] = _render_environment(container.environment)
    if container.mounts:
        rendered["volumeMounts"] = [
            {
                "mountPath": mount.mount_path,
                "name": mount.name,
                "readOnly": mount.read_only,
            }
            for mount in container.mounts
        ]
    if container.ports:
        rendered["ports"] = [
            {
                **({"name": port.name} if port.name is not None else {}),
                "containerPort": port.container_port,
                "protocol": port.protocol,
            }
            for port in container.ports
        ]
    if container.security_context is not None:
        rendered["securityContext"] = _render_security_context(container.security_context)
    if container.liveness_probe is not None:
        rendered["livenessProbe"] = _render_readiness_probe(container.liveness_probe)
    if container.readiness_probe is not None:
        rendered["readinessProbe"] = _render_readiness_probe(container.readiness_probe)
    return rendered


def render_daemonset(
    bundle: WorkloadBundle,
    namespace: str,
    node_name: str,
    ownership_id: str,
) -> Dict[str, Any]:
    """Render a DaemonSet selecting the unique ownership label applied to the target node."""

    _validate_dns_label(namespace, "namespace")
    _validate_dns_subdomain(node_name, "node name")
    validate_ownership_id(ownership_id)
    resource_name = "{}-{}".format(bundle.name, ownership_id)
    _validate_dns_label(resource_name, "resource name")

    labels = {
        "app.kubernetes.io/instance": resource_name,
        "app.kubernetes.io/managed-by": "sonic-mgmt-pytest",
        "app.kubernetes.io/name": bundle.name,
        "sonic-mgmt.test/owner": ownership_id,
    }
    annotations = {"sonic-mgmt.test/node-name": node_name}
    for container in bundle.containers:
        context = container.security_context
        if context is not None and context.apparmor_profile_type is not None:
            profile = {
                "RuntimeDefault": "runtime/default",
                "Unconfined": "unconfined",
            }[context.apparmor_profile_type]
            annotations[
                "container.apparmor.security.beta.kubernetes.io/{}".format(container.name)
            ] = profile
    pod_spec: Dict[str, Any] = {
        "automountServiceAccountToken": False,
        "containers": [_render_container(container) for container in bundle.containers],
        "nodeSelector": {ownership_node_label(ownership_id): ownership_id},
    }
    if bundle.host_network:
        pod_spec["hostNetwork"] = True
        pod_spec["dnsPolicy"] = "ClusterFirstWithHostNet"
    if bundle.host_pid:
        pod_spec["hostPID"] = True
    if bundle.host_ipc:
        pod_spec["hostIPC"] = True
    if bundle.hostname is not None:
        pod_spec["hostname"] = bundle.hostname
    if bundle.image_pull_secret is not None:
        pod_spec["imagePullSecrets"] = [{"name": bundle.image_pull_secret}]

    volumes = {}
    for container in bundle.containers:
        for mount in container.mounts:
            host_path = {"path": mount.host_path}
            if mount.host_path_type is not None:
                host_path["type"] = mount.host_path_type
            volumes.setdefault(mount.name, {"hostPath": host_path, "name": mount.name})
    if volumes:
        pod_spec["volumes"] = [volumes[name] for name in sorted(volumes)]

    return {
        "apiVersion": "apps/v1",
        "kind": "DaemonSet",
        "metadata": {
            "labels": labels,
            "name": resource_name,
            "namespace": namespace,
        },
        "spec": {
            "selector": {"matchLabels": labels},
            "template": {
                "metadata": {"annotations": annotations, "labels": labels},
                "spec": pod_spec,
            },
            "updateStrategy": {"type": "OnDelete"},
        },
    }


def render_daemonset_json(
    bundle: WorkloadBundle,
    namespace: str,
    node_name: str,
    ownership_id: str,
) -> str:
    """Render byte-stable JSON, which is also accepted as a Kubernetes manifest."""

    manifest = render_daemonset(bundle, namespace, node_name, ownership_id)
    return json.dumps(manifest, indent=2, sort_keys=True) + "\n"
