"""Load container-owner Kubernetes specifications."""

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

import yaml
from yaml.composer import ComposerError
from yaml.constructor import ConstructorError
from yaml.events import AliasEvent

from tests.k8s_container.lifecycle import OWNED_HOST_PATH_PREFIX
from tests.k8s_container.workload import ContainerPort
from tests.k8s_container.workload import ContainerSpec
from tests.k8s_container.workload import EnvVar
from tests.k8s_container.workload import ExecReadinessProbe
from tests.k8s_container.workload import HostPathMount
from tests.k8s_container.workload import HttpReadinessProbe
from tests.k8s_container.workload import SecurityContext
from tests.k8s_container.workload import WorkloadBundle
from tests.k8s_container.workload import validate_ownership_id


SPEC_DIRECTORY = Path(__file__).with_name("container_specs")
_PLACEHOLDER = re.compile(r"\$\{([A-Z][A-Z0-9_]*)\}")
_ARCHITECTURE_ALIASES = {
    "x86_64": "amd64",
    "arm": "armhf",
    "armv7l": "armhf",
    "aarch64": "arm64",
}
_IMAGE_PULL_POLICY = "Never"
_COMMON_ENVIRONMENT = (
    ("NAMESPACE_ID", ""),
    ("NAMESPACE_PREFIX", "asic"),
    ("NAMESPACE_COUNT", "1"),
    ("DEV", ""),
    ("SYSLOG_TARGET_IP", "127.0.0.1"),
    ("PLATFORM", "${PLATFORM}"),
)
_PROBE_TIMING = {
    "initialDelaySeconds": "initial_delay_seconds",
    "periodSeconds": "period_seconds",
    "timeoutSeconds": "timeout_seconds",
    "failureThreshold": "failure_threshold",
    "successThreshold": "success_threshold",
}


class _StrictSafeLoader(yaml.SafeLoader):
    def compose_node(self, parent, index):
        event = self.peek_event()
        if isinstance(event, AliasEvent):
            raise ComposerError(None, None, "YAML aliases are not supported", event.start_mark)
        if getattr(event, "anchor", None) is not None:
            raise ComposerError(None, None, "YAML anchors are not supported", event.start_mark)
        if getattr(event, "tag", None) is not None:
            raise ComposerError(None, None, "explicit YAML tags are not supported", event.start_mark)
        return super().compose_node(parent, index)

    def construct_mapping(self, node, deep=False):
        mapping = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key == "<<":
                raise ConstructorError(None, None, "YAML merge keys are not supported", key_node.start_mark)
            try:
                duplicate = key in mapping
            except TypeError:
                raise ConstructorError(None, None, "YAML mapping keys must be scalar", key_node.start_mark)
            if duplicate:
                raise ConstructorError(None, None, "duplicate YAML mapping key {!r}".format(key), key_node.start_mark)
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def _object(value: Any, field_name: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("{} must be an object".format(field_name))
    return value


def _list(value: Any, field_name: str) -> Sequence[Any]:
    if not isinstance(value, list):
        raise ValueError("{} must be a list".format(field_name))
    return value


def _string(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("{} must be a non-empty string".format(field_name))
    return value


def _probe(value: Optional[Mapping[str, Any]], field_name: str) -> Optional[Any]:
    if value is None:
        return None
    declaration = dict(_object(value, field_name))
    timing = {
        target: declaration.pop(source)
        for source, target in _PROBE_TIMING.items()
        if source in declaration
    }
    if "exec" in declaration and set(declaration) == {"exec"}:
        execution = dict(_object(declaration["exec"], "{}.exec".format(field_name)))
        if set(execution) != {"command"}:
            raise ValueError("{}.exec must contain only command".format(field_name))
        command = tuple(_list(execution["command"], "{}.exec.command".format(field_name)))
        return ExecReadinessProbe(command=command, **timing)
    if "httpGet" in declaration and set(declaration) == {"httpGet"}:
        target = dict(_object(declaration["httpGet"], "{}.httpGet".format(field_name)))
        if set(target) - {"path", "port", "host", "scheme"}:
            raise ValueError("{}.httpGet contains unsupported fields".format(field_name))
        return HttpReadinessProbe(
            path=target["path"],
            port=target["port"],
            host=target.get("host"),
            scheme=target.get("scheme", "HTTP"),
            **timing
        )
    raise ValueError("{} must contain exactly one of exec or httpGet".format(field_name))


def _substitute(value: Any, substitutions: Mapping[str, str], field_name: str) -> Any:
    if isinstance(value, str):
        names = set(_PLACEHOLDER.findall(value))
        unknown = sorted(names - set(substitutions))
        if unknown:
            raise ValueError("{} has unresolved placeholders {}".format(field_name, unknown))
        for name in names:
            value = value.replace("${{{}}}".format(name), substitutions[name])
        return value
    if isinstance(value, list):
        return [
            _substitute(item, substitutions, "{}[{}]".format(field_name, index))
            for index, item in enumerate(value)
        ]
    if isinstance(value, dict):
        return {
            key: _substitute(item, substitutions, "{}.{}".format(field_name, key))
            for key, item in value.items()
        }
    return value


def _with_infrastructure_defaults(container: Mapping[str, Any]) -> Dict[str, Any]:
    declaration = dict(container)
    environment = list(declaration.get("env", []))
    names = {item["name"] for item in environment}
    infrastructure_names = {name for name, _ in _COMMON_ENVIRONMENT}
    if names & infrastructure_names:
        raise ValueError("container env cannot override infrastructure values")
    container_name = declaration["name"]
    for name, value in (("CONTAINER_NAME", container_name),) + _COMMON_ENVIRONMENT:
        if name not in names:
            environment.append({"name": name, "value": value})
    declaration["env"] = environment
    return declaration


@dataclass(frozen=True)
class ContainerFamilySpec:
    """One container-owner family with exact golden images and required volumes."""

    path: Path
    family: str
    golden_images: Mapping[str, Mapping[str, str]]
    runtime_placeholders: Tuple[str, ...]
    containers: Tuple[Mapping[str, Any], ...]
    volumes: Mapping[str, Mapping[str, Any]]
    host_path_overrides: Mapping[str, Mapping[str, str]]

    def golden_image(self, container_name: str, architecture: str) -> str:
        architecture = _ARCHITECTURE_ALIASES.get(architecture, architecture)
        try:
            return self.golden_images[container_name][architecture]
        except KeyError:
            raise ValueError(
                "no golden {} image for architecture {}".format(container_name, architecture)
            )

    @property
    def container_names(self) -> Tuple[str, ...]:
        return tuple(container["name"] for container in self.containers)

    def build_bundle(
        self,
        name: str,
        images: Mapping[str, str],
        runtime_values: Optional[Mapping[str, str]] = None,
    ) -> WorkloadBundle:
        runtime_values = dict(runtime_values or {})
        if set(images) != set(self.container_names):
            raise ValueError("images must match {}".format(sorted(self.container_names)))
        if set(runtime_values) != set(self.runtime_placeholders):
            raise ValueError(
                "runtime values must match {}".format(sorted(self.runtime_placeholders))
            )
        if any(
            not isinstance(value, str) or not value or _PLACEHOLDER.search(value)
            for value in runtime_values.values()
        ):
            raise ValueError("runtime values must be non-empty strings without placeholders")

        volumes = _substitute(self.volumes, runtime_values, "volumes")
        for volume_name, contract in self.host_path_overrides.items():
            host_path = volumes[volume_name]["hostPath"]["path"]
            prefix = contract["required_prefix"]
            if not host_path.startswith(prefix):
                raise ValueError("host path override must start with {!r}".format(prefix))
            try:
                validate_ownership_id(host_path[len(prefix):])
            except ValueError:
                raise ValueError("host path override must end with one canonical ownership UUID")

        containers = []
        declarations = _substitute(list(self.containers), runtime_values, "containers")
        for declaration in declarations:
            mounts = tuple(
                HostPathMount(
                    name=mount["name"],
                    host_path=volumes[mount["name"]]["hostPath"]["path"],
                    mount_path=mount["mountPath"],
                    read_only=mount.get("readOnly", False),
                    host_path_type=volumes[mount["name"]]["hostPath"].get("type"),
                )
                for mount in declaration.get("volumeMounts", [])
            )
            containers.append(
                ContainerSpec(
                    name=declaration["name"],
                    image=images[declaration["name"]],
                    image_pull_policy=_IMAGE_PULL_POLICY,
                    command=tuple(declaration.get("command", ())),
                    args=tuple(declaration.get("args", ())),
                    environment=tuple(
                        EnvVar(name=item["name"], value=item["value"])
                        for item in declaration.get("env", [])
                    ),
                    mounts=mounts,
                    ports=tuple(
                        ContainerPort(
                            name=item.get("name"),
                            container_port=item["containerPort"],
                            protocol=item.get("protocol", "TCP"),
                        )
                        for item in declaration.get("ports", [])
                    ),
                    security_context=SecurityContext.from_kubernetes(
                        declaration.get("securityContext", {})
                    ),
                    tty=declaration.get("tty", False),
                    liveness_probe=_probe(
                        declaration.get("livenessProbe"),
                        "container {!r} livenessProbe".format(declaration["name"]),
                    ),
                    readiness_probe=_probe(
                        declaration.get("readinessProbe"),
                        "container {!r} readinessProbe".format(declaration["name"]),
                    ),
                )
            )
        return WorkloadBundle(name=name, containers=tuple(containers))


def load_container_spec(path: Path) -> ContainerFamilySpec:
    path = Path(path)
    with path.open(encoding="utf-8") as stream:
        try:
            document = _object(yaml.load(stream, Loader=_StrictSafeLoader), "specification")
        except yaml.YAMLError as error:
            raise ValueError("invalid container specification YAML: {}".format(error))
    if type(document.get("schema_version")) is not int or document["schema_version"] != 1:
        raise ValueError("unsupported container specification version")
    expected_keys = {
        "schema_version",
        "golden_images",
        "containers",
        "volumes",
    }
    optional_keys = {"host_path_overrides"}
    if set(document) - optional_keys != expected_keys:
        raise ValueError(
            "container specification keys must match {} with optional {}".format(
                sorted(expected_keys), sorted(optional_keys)
            )
        )
    family = _string(path.stem, "specification filename")
    golden_images = _object(document.get("golden_images"), "golden_images")
    containers = tuple(
        _with_infrastructure_defaults(_object(value, "container"))
        for value in _list(document.get("containers"), "containers")
    )
    volume_declarations = tuple(
        _object(item, "volume") for item in _list(document.get("volumes"), "volumes")
    )
    volumes = {value["name"]: value for value in volume_declarations}
    if len(volumes) != len(volume_declarations):
        raise ValueError("volume names must be unique")
    for name, volume in volumes.items():
        if set(volume) != {"name", "hostPath"} or name != volume["name"]:
            raise ValueError("volume declarations must contain name and hostPath")
        host_path = _object(volume["hostPath"], "volume hostPath")
        if set(host_path) - {"path", "type"} or "path" not in host_path:
            raise ValueError("volume hostPath fields are invalid")
    overrides = _object(document.get("host_path_overrides", {}), "host_path_overrides")
    names = tuple(container.get("name") for container in containers)
    if len(names) != len(set(names)) or set(golden_images) != set(names):
        raise ValueError("container and golden image names must match and be unique")
    if any(mount["name"] not in volumes for container in containers for mount in container.get("volumeMounts", [])):
        raise ValueError("container mount references an unknown volume")
    allowed_container_fields = {
        "name",
        "tty",
        "command",
        "args",
        "env",
        "securityContext",
        "volumeMounts",
        "ports",
        "livenessProbe",
        "readinessProbe",
    }
    for container in containers:
        unknown = sorted(set(container) - allowed_container_fields)
        if unknown or "name" not in container:
            raise ValueError("container fields are invalid; unknown={}".format(unknown))
        _string(container["name"], "container.name")
        for field_name in ("command", "args"):
            for part in _list(container.get(field_name, []), "container.{}".format(field_name)):
                _string(part, "container.{} entry".format(field_name))
        for item in container.get("env", []):
            if set(item) != {"name", "value"}:
                raise ValueError("container env entries must contain name and value")
        for mount in container.get("volumeMounts", []):
            if set(mount) - {"name", "mountPath", "readOnly"} or not {
                "name",
                "mountPath",
            }.issubset(mount):
                raise ValueError("container volumeMount fields are invalid")
        SecurityContext.from_kubernetes(container.get("securityContext", {}))
        _probe(container.get("livenessProbe"), "container livenessProbe")
        _probe(container.get("readinessProbe"), "container readinessProbe")
    serialized = json.dumps({"containers": containers, "volumes": volumes})
    runtime_placeholders = tuple(sorted(set(_PLACEHOLDER.findall(serialized))))
    for container_name, mappings in golden_images.items():
        if not isinstance(mappings, dict) or set(mappings) != {"amd64", "armhf", "arm64"}:
            raise ValueError("golden image mappings must contain amd64, armhf, and arm64")
        for image in mappings.values():
            _string(image, "golden image")
    if set(overrides) - set(volumes):
        raise ValueError("host path overrides reference unknown volumes")
    host_path_placeholders = {}
    for volume_name, volume in volumes.items():
        placeholders = set(_PLACEHOLDER.findall(volume["hostPath"]["path"]))
        if placeholders:
            host_path_placeholders[volume_name] = placeholders
    if set(overrides) != set(host_path_placeholders):
        raise ValueError("every runtime host path must have exactly one ownership override")
    for volume_name, contract in overrides.items():
        if set(contract) != {"placeholder", "required_prefix"}:
            raise ValueError("host path override fields are invalid")
        placeholder = _string(contract["placeholder"], "host path override placeholder")
        if host_path_placeholders[volume_name] != {placeholder}:
            raise ValueError("host path override must name its only placeholder")
        if volumes[volume_name]["hostPath"]["path"] != "${{{}}}".format(placeholder):
            raise ValueError("runtime host path must consist only of its placeholder")
        if contract["required_prefix"] != OWNED_HOST_PATH_PREFIX:
            raise ValueError("runtime host paths must use the lifecycle-owned prefix")

    spec = ContainerFamilySpec(
        path=path,
        family=family,
        golden_images=golden_images,
        runtime_placeholders=runtime_placeholders,
        containers=containers,
        volumes=volumes,
        host_path_overrides=overrides,
    )
    runtime_values = {name: "validation" for name in runtime_placeholders}
    for contract in overrides.values():
        runtime_values[contract["placeholder"]] = "{}00000000-0000-0000-0000-000000000000".format(
            contract["required_prefix"]
        )
    for architecture in ("amd64", "armhf", "arm64"):
        spec.build_bundle(
            name=family,
            images={name: golden_images[name][architecture] for name in names},
            runtime_values=runtime_values,
        )
    return spec
