"""Shared Minikube and SONiC DUT contexts for container tests."""

import base64
import ipaddress
import json
import logging
import re
import shlex
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple


MINIKUBE_VERSION = "v1.34.0"
MINIKUBE_SHA256 = "c4a625f9b4a4523e74b745b6aac8b0bf45062472be72cd38a23c91ec04d534c9"
KUBERNETES_VERSION = "v1.22.2"
DEFAULT_PROFILE = "sonic-mgmt-k8s"
DEFAULT_API_DNS = "control-plane.minikube.internal"
DEFAULT_API_PORT = 6443
KUBELET_CLIENT_CA = "/etc/kubernetes/pki/ca.crt"
JOIN_OWNER_LABEL = "sonic-mgmt.test/join-owner"
BASELINE_ROOT = "/var/lib/sonic-mgmt-minikube/runs"
LEGACY_CONTRACT_ROOT = "/var/lib/sonic-mgmt-minikube/profiles"
LOCK_ROOT = "/run/lock/sonic-mgmt-minikube"
KUBECONFIG_ROOT = "/var/tmp/sonic-mgmt-minikube-kubeconfigs"

logger = logging.getLogger(__name__)

_PROFILE_NAME = re.compile(r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$")


class MinikubeError(RuntimeError):
    """The requested environment operation was unsafe or did not converge."""


class MinikubeCleanupError(MinikubeError):
    """Normal context cleanup attempted every safe step but did not finish."""

    def __init__(self, message: str, cleanup_errors: Sequence[str]):
        super().__init__(message)
        self.cleanup_errors = tuple(cleanup_errors)


class MinikubeLockHeldError(MinikubeError):
    """Raised when the selected Minikube profile lock is unavailable."""


@dataclass(frozen=True)
class HostResult:
    rc: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class MinikubeSpec:
    profile: str = DEFAULT_PROFILE
    minikube_version: str = MINIKUBE_VERSION
    minikube_sha256: str = MINIKUBE_SHA256
    kubernetes_version: str = KUBERNETES_VERSION
    driver: str = "docker"
    api_port: int = DEFAULT_API_PORT
    api_dns: str = DEFAULT_API_DNS
    kubelet_client_ca: str = KUBELET_CLIENT_CA
    binary_path: str = "/usr/local/bin/minikube"
    timeout_seconds: int = 600

    def __post_init__(self) -> None:
        if not isinstance(self.profile, str) or len(self.profile) > 63 or not _PROFILE_NAME.fullmatch(self.profile):
            raise ValueError("Minikube profile must be a Kubernetes DNS label")
        if (
            self.minikube_version != MINIKUBE_VERSION
            or self.minikube_sha256 != MINIKUBE_SHA256
            or self.kubernetes_version != KUBERNETES_VERSION
            or self.driver != "docker"
            or self.api_port != DEFAULT_API_PORT
            or self.api_dns != DEFAULT_API_DNS
            or self.kubelet_client_ca != KUBELET_CLIENT_CA
        ):
            raise ValueError("MinikubeSpec must use the pinned test contract")
        if type(self.timeout_seconds) is not int or self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be a positive integer")

    @property
    def kubeconfig_directory(self) -> str:
        return "{}/{}".format(KUBECONFIG_ROOT, self.profile)

    @property
    def kubeconfig_path(self) -> str:
        return "{}/config".format(self.kubeconfig_directory)


@dataclass(frozen=True)
class MinikubeProfileState:
    running: bool
    minikube_version: str
    kubernetes_version: str
    driver: str
    api_port: int
    kubelet_client_ca: str
    profile_identity: str
    kube_proxy_present: bool
    coredns_present: bool
    enabled_addons: Tuple[str, ...]
    api_dns_present: bool

    def incompatibilities(self, spec: MinikubeSpec) -> Tuple[str, ...]:
        checks = (
            (self.running, "profile is not running"),
            (self.minikube_version == spec.minikube_version, "Minikube version differs"),
            (self.kubernetes_version == spec.kubernetes_version, "Kubernetes version differs"),
            (self.driver == spec.driver, "driver differs"),
            (self.kubelet_client_ca == spec.kubelet_client_ca, "kubelet client CA differs"),
            (not self.kube_proxy_present, "kube-proxy is installed"),
            (not self.coredns_present, "CoreDNS is installed"),
            (not self.enabled_addons, "Minikube addons are enabled"),
            (self.api_dns_present, "API certificate DNS name is absent"),
        )
        return tuple(message for valid, message in checks if not valid)


@dataclass(frozen=True)
class KubernetesNode:
    name: str
    uid: str
    resource_version: str
    owner: Optional[str]
    ready: bool
    runtime: str


@dataclass(frozen=True)
class DutBaseline:
    directory: str
    critical_health: Mapping[str, bool]


def select_minikube_vmhost(vmhosts: Sequence[Any], explicit_name: Optional[str] = None) -> Any:
    hosts = tuple(vmhosts or ())
    if explicit_name:
        matches = tuple(host for host in hosts if getattr(host, "hostname", None) == explicit_name)
        if len(matches) != 1:
            raise MinikubeError("--minikube-vmhost must name exactly one associated server")
        return matches[0]
    if len(hosts) != 1:
        raise MinikubeError("Minikube requires one associated server or --minikube-vmhost")
    return hosts[0]


def select_minikube_duthost(duthosts: Sequence[Any], explicit_name: Optional[str] = None) -> Any:
    hosts = tuple(duthosts or ())
    if explicit_name:
        matches = tuple(host for host in hosts if getattr(host, "hostname", None) == explicit_name)
        if len(matches) != 1:
            raise MinikubeError("--minikube-dut must name exactly one selected DUT")
        return matches[0]
    if len(hosts) != 1:
        raise MinikubeError("Minikube requires one selected DUT or --minikube-dut")
    return hosts[0]


def merge_proxy_environment(
    proxy_environment: Optional[Mapping[str, Any]],
    extra_no_proxy: Sequence[str],
) -> Dict[str, str]:
    source = dict(proxy_environment or {})
    no_proxy = []
    for key in ("no_proxy", "NO_PROXY"):
        for value in str(source.get(key, "")).split(","):
            if value.strip() and value.strip() not in no_proxy:
                no_proxy.append(value.strip())
    for value in extra_no_proxy:
        if value and value not in no_proxy:
            no_proxy.append(value)
    result = {
        key: str(source[key])
        for key in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY")
        if source.get(key)
    }
    result["no_proxy"] = result["NO_PROXY"] = ",".join(no_proxy)
    return result


def _result(value: Mapping[str, Any]) -> HostResult:
    return HostResult(int(value.get("rc", 1)), str(value.get("stdout", "")), str(value.get("stderr", "")))


def _json(result: HostResult, purpose: str) -> Any:
    if result.rc != 0:
        raise MinikubeError("{} failed: {}".format(purpose, result.stderr.strip()))
    try:
        return json.loads(result.stdout)
    except ValueError as error:
        raise MinikubeError("{} returned invalid JSON: {}".format(purpose, error))


def _env(environment: Mapping[str, str]) -> str:
    return " ".join("{}={}".format(key, shlex.quote(value)) for key, value in sorted(environment.items()) if value)


class AnsibleMinikubeRunner:
    def __init__(
        self,
        vmhost: Any,
        vmhost_user: str,
        clock: Any = time.monotonic,
        sleep: Any = time.sleep,
    ):
        self.vmhost = vmhost
        if not isinstance(vmhost_user, str) or not vmhost_user or any(
            character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
            for character in vmhost_user
        ):
            raise ValueError("Minikube VM host user is invalid")
        self.vmhost_user = vmhost_user
        self.clock = clock
        self.sleep = sleep

    def run(self, command: str, stdin: Optional[str] = None, private: bool = False) -> HostResult:
        kwargs = {"module_ignore_errors": True, "verbose": not private}
        if stdin is not None:
            kwargs["stdin"] = stdin
        return _result(self.vmhost.shell(command, **kwargs))

    def minikube(self, spec: MinikubeSpec, environment: Mapping[str, str], arguments: Sequence[str]) -> str:
        command = (spec.binary_path, "--profile", spec.profile) + tuple(arguments)
        inner = "{} {}".format(
            _env(environment),
            " ".join(shlex.quote(str(item)) for item in command),
        ).strip()
        return "sudo --user={} --set-home sh -c {}".format(
            shlex.quote(self.vmhost_user), shlex.quote(inner)
        )

    def kubectl(
        self,
        spec: MinikubeSpec,
        environment: Mapping[str, str],
        arguments: Sequence[str],
        stdin: Optional[str] = None,
    ) -> HostResult:
        return self.run(
            self.minikube(
                spec,
                environment,
                ("kubectl", "--", "--request-timeout=15s") + tuple(arguments),
            ),
            stdin,
            True,
        )

    def profile_container_network(self, spec: MinikubeSpec) -> Tuple[str, int, str]:
        inspect = _json(
            self.run("sudo docker inspect {}".format(shlex.quote(spec.profile)), private=True),
            "Minikube container",
        )
        try:
            identity = inspect[0]["Id"]
            port = int(inspect[0]["NetworkSettings"]["Ports"]["6443/tcp"][0]["HostPort"])
            networks = inspect[0]["NetworkSettings"]["Networks"]
            if not isinstance(networks, dict):
                raise ValueError
            addresses = tuple(
                value.get("IPAddress", "")
                for value in networks.values()
                if isinstance(value, dict)
                and isinstance(value.get("IPAddress"), str)
                and value.get("IPAddress")
            )
            if len(addresses) != 1:
                raise ValueError
            address = addresses[0]
            ipaddress.ip_address(address)
            return identity, port, address
        except (IndexError, KeyError, TypeError, ValueError):
            raise MinikubeError("Minikube container network identity is unreadable")

    def profile_container_id(self, spec: MinikubeSpec) -> str:
        inspect = _json(
            self.run("sudo docker inspect {}".format(shlex.quote(spec.profile)), private=True),
            "Minikube container",
        )
        try:
            return inspect[0]["Id"]
        except (IndexError, KeyError, TypeError):
            raise MinikubeError("Minikube container identity is unreadable")

    def profile_container_identity(self, spec: MinikubeSpec) -> Tuple[str, int]:
        identity, port, _ = self.profile_container_network(spec)
        return identity, port

    def acquire_lock(self, spec: MinikubeSpec, token: str) -> None:
        lock = "{}/{}.lock".format(LOCK_ROOT, spec.profile)
        script = (
            "install -d -m 0700 -o root -g root \"$1\" && "
            "mkdir -m 0700 \"$2\" && "
            "printf '%s\\n' \"$3\" > \"$2/owner-token\" && "
            "chmod 0600 \"$2/owner-token\""
        )
        result = self.run(
            "sudo sh -c {} sh {} {} {}".format(
                shlex.quote(script), shlex.quote(LOCK_ROOT), shlex.quote(lock), shlex.quote(token)
            ),
            private=True,
        )
        if result.rc != 0:
            raise MinikubeLockHeldError("Minikube profile lock is unavailable")

    def release_lock(self, spec: MinikubeSpec, token: str) -> None:
        lock = "{}/{}.lock".format(LOCK_ROOT, spec.profile)
        result = self.run(
            "sudo sh -c 'test \"$(cat \"$1/owner-token\")\" = \"$2\" && rm -rf -- \"$1\"' sh {} {}".format(
                shlex.quote(lock), shlex.quote(token)
            ),
            private=True,
        )
        if result.rc != 0:
            raise MinikubeError("Minikube profile lock could not be released")

    def ensure_binary(self, spec: MinikubeSpec, environment: Mapping[str, str]) -> None:
        digest = self.run("sha256sum {}".format(shlex.quote(spec.binary_path)), private=True)
        if digest.rc == 0:
            if digest.stdout.split()[0] != spec.minikube_sha256:
                raise MinikubeError("Minikube binary path contains an unexpected binary")
            return
        temporary = "{}.{}.download".format(spec.binary_path, uuid.uuid4())
        url = "https://github.com/kubernetes/minikube/releases/download/{}/minikube-linux-amd64".format(
            spec.minikube_version
        )
        command = (
            "{env} curl --fail --location --max-time 360 --output {tmp} {url} && "
            "printf '%s  %s\\n' {digest} {tmp} | sha256sum --check --status && "
            "chmod 0755 {tmp} && mv -T {tmp} {binary}; rc=$?; rm -f -- {tmp}; exit $rc"
        ).format(
            env=_env(environment), tmp=shlex.quote(temporary), url=shlex.quote(url),
            digest=shlex.quote(spec.minikube_sha256), binary=shlex.quote(spec.binary_path),
        )
        if self.run(command, private=True).rc != 0:
            raise MinikubeError("Pinned Minikube download or checksum failed")

    def prepare_kubeconfig(self, spec: MinikubeSpec) -> None:
        script = (
            "set -eu; root=\"$1\"; path=\"$2\"; owner=\"$3\"; "
            "if [ -e \"$root\" ] || [ -L \"$root\" ]; then "
            "test -d \"$root\"; test ! -L \"$root\"; "
            "test \"$(stat -c '%u:%g:%a' -- \"$root\")\" = '0:0:711'; "
            "else install -d -m 0711 -o root -g root -- \"$root\"; fi; "
            "test ! -e \"$path\"; test ! -L \"$path\"; "
            "mkdir -m 0700 -- \"$path\"; chown -- \"$owner\" \"$path\""
        )
        result = self.run(
            "sudo sh -c {} sh {} {} {}".format(
                shlex.quote(script),
                shlex.quote(KUBECONFIG_ROOT),
                shlex.quote(spec.kubeconfig_directory),
                shlex.quote(self.vmhost_user),
            ),
            private=True,
        )
        if result.rc != 0:
            raise MinikubeError("isolated Minikube kubeconfig could not be prepared")

    def reset_profile(self, spec: MinikubeSpec, environment: Mapping[str, str]) -> None:
        legacy_environment = dict(environment)
        legacy_environment.pop("KUBECONFIG", None)
        for delete_environment in (environment, legacy_environment):
            self.run(
                self.minikube(spec, delete_environment, ("delete",)),
                private=True,
            )

        script = r"""set -eu
profile="$1"
user="$2"
kubeconfig_root="$3"
kubeconfig="$4"
legacy_contract="$5"
home="$(getent passwd "$user" | cut -d: -f6)"
test -n "$home"
profile_containers="$(docker ps -aq --filter "label=name.minikube.sigs.k8s.io=$profile")"
if [ -n "$profile_containers" ]; then
    printf '%s\n' "$profile_containers" | xargs docker rm -f
fi
docker rm -f "$profile" >/dev/null 2>&1 || true
docker network rm "$profile" >/dev/null 2>&1 || true
docker volume rm -f "$profile" >/dev/null 2>&1 || true
rm -rf -- "$home/.minikube/profiles/$profile" "$home/.minikube/machines/$profile"
if [ -e "$kubeconfig_root" ] || [ -L "$kubeconfig_root" ]; then
    test -d "$kubeconfig_root"
    test ! -L "$kubeconfig_root"
    test "$(stat -c '%u:%g:%a' -- "$kubeconfig_root")" = "0:0:711"
    rm -rf -- "$kubeconfig"
fi
rm -f -- "$legacy_contract"
profile_containers="$(docker ps -aq --filter "label=name.minikube.sigs.k8s.io=$profile")"
named_containers="$(docker ps -aq --filter "name=^/${profile}$")"
profile_networks="$(docker network ls -q --filter "name=^${profile}$")"
profile_volumes="$(docker volume ls -q --filter "name=^${profile}$")"
test -z "$profile_containers"
test -z "$named_containers"
test -z "$profile_networks"
test -z "$profile_volumes"
test ! -e "$home/.minikube/profiles/$profile"
test ! -e "$home/.minikube/machines/$profile"
test ! -e "$kubeconfig"
test ! -e "$legacy_contract"
"""
        legacy_contract = "{}/{}.json".format(LEGACY_CONTRACT_ROOT, spec.profile)
        result = self.run(
            "sudo sh -c {} sh {} {} {} {} {}".format(
                shlex.quote(script),
                shlex.quote(spec.profile),
                shlex.quote(self.vmhost_user),
                shlex.quote(KUBECONFIG_ROOT),
                shlex.quote(spec.kubeconfig_directory),
                shlex.quote(legacy_contract),
            ),
            private=True,
        )
        if result.rc != 0:
            raise MinikubeError("Minikube profile reset failed")

    @staticmethod
    def _not_found(result: HostResult) -> bool:
        return "Error from server (NotFound)" in result.stderr

    def inspect_profile(self, spec: MinikubeSpec, environment: Mapping[str, str]) -> Optional[MinikubeProfileState]:
        profiles = _json(
            self.run(self.minikube(spec, environment, ("profile", "list", "--output=json")), private=True),
            "Minikube profile list",
        )
        if not isinstance(profiles, dict) or set(profiles) != {"valid", "invalid"}:
            raise MinikubeError("Minikube profile list has an invalid schema")
        valid = profiles["valid"]
        invalid = profiles["invalid"]
        if not isinstance(valid, list) or not isinstance(invalid, list):
            raise MinikubeError("Minikube profile list has an invalid schema")
        if any(item.get("Name") == spec.profile for item in invalid if isinstance(item, dict)):
            raise MinikubeError("Minikube profile exists but is unreadable")
        matches = [item for item in valid if isinstance(item, dict) and item.get("Name") == spec.profile]
        if not matches:
            return None
        if len(matches) != 1 or not isinstance(matches[0].get("Config"), dict):
            raise MinikubeError("Minikube profile entry has an invalid schema")

        status = _json(
            self.run(self.minikube(spec, environment, ("status", "--output=json")), private=True),
            "Minikube status",
        )
        version = _json(self.kubectl(spec, environment, ("version", "-o", "json")), "Kubernetes version")
        configmap = _json(
            self.kubectl(
                spec,
                environment,
                ("get", "configmap", "kubelet-config-1.22", "-n", "kube-system", "-o", "json"),
            ),
            "kubelet ConfigMap",
        )
        match = re.search(r"(?m)^\s*clientCAFile:\s*([^\s#]+)", configmap.get("data", {}).get("kubelet", ""))
        identity, port = self.profile_container_identity(spec)
        kube_proxy = self.kubectl(
            spec,
            environment,
            ("get", "daemonset", "kube-proxy", "-n", "kube-system", "-o", "name"),
        )
        coredns = self.kubectl(spec, environment, ("get", "deployment", "coredns", "-n", "kube-system", "-o", "name"))
        for result, name in ((kube_proxy, "kube-proxy"), (coredns, "CoreDNS")):
            if result.rc != 0 and not self._not_found(result):
                raise MinikubeError("{} lookup failed".format(name))
        addons = _json(
            self.run(self.minikube(spec, environment, ("addons", "list", "--output=json")), private=True),
            "Minikube addons",
        )
        if not isinstance(addons, dict) or any(
            not isinstance(value, dict) or not isinstance(value.get("Status"), str)
            for value in addons.values()
        ):
            raise MinikubeError("Minikube addon list has an invalid schema")
        certificate_command = (
            "sudo docker exec {} openssl x509 -in /var/lib/minikube/certs/apiserver.crt "
            "-noout -ext subjectAltName"
        ).format(shlex.quote(spec.profile))
        certificate = self.run(
            certificate_command,
            private=True,
        )
        if certificate.rc != 0 or match is None:
            raise MinikubeError("Minikube certificate or kubelet CA is unreadable")
        config = matches[0]["Config"]
        return MinikubeProfileState(
            running=all(status.get(key) == "Running" for key in ("Host", "Kubelet", "APIServer")),
            minikube_version=_json(
                self.kubectl(spec, environment, ("get", "node", spec.profile, "-o", "json")),
                "control-plane node",
            ).get("metadata", {}).get("labels", {}).get("minikube.k8s.io/version", ""),
            kubernetes_version=version.get("serverVersion", {}).get("gitVersion", ""),
            driver=str(matches[0].get("Driver", config.get("Driver", config.get("driver", "")))).lower(),
            api_port=port,
            kubelet_client_ca=match.group(1),
            profile_identity=identity,
            kube_proxy_present=kube_proxy.rc == 0,
            coredns_present=coredns.rc == 0,
            enabled_addons=tuple(
                sorted(name for name, value in addons.items() if value["Status"].lower() == "enabled")
            ),
            api_dns_present="DNS:{}".format(spec.api_dns) in certificate.stdout.replace(" ", ""),
        )

    def start_profile(self, spec: MinikubeSpec, environment: Mapping[str, str], vmhost_ip: str) -> str:
        args = (
            "start", "--driver=docker", "--listen-address=0.0.0.0", "--apiserver-port=6443",
            "--extra-config=kubeadm.skip-phases=addon/kube-proxy,addon/coredns",
            "--install-addons=false", "--kubernetes-version={}".format(spec.kubernetes_version),
            "--apiserver-ips={}".format(vmhost_ip), "--apiserver-names={}".format(spec.api_dns), "--force",
        )
        creation = self.run(self.minikube(spec, environment, args), private=True)
        if creation.rc != 0:
            detail = (creation.stderr or creation.stdout).strip()[-2048:]
            raise MinikubeError("Minikube profile creation failed: {}".format(detail))
        return self.profile_container_id(spec)

    def configure_profile(self, spec: MinikubeSpec, environment: Mapping[str, str]) -> None:
        deadline = self.clock() + spec.timeout_seconds
        configmap_result = HostResult(1, "", "Minikube API did not respond")
        while self.clock() < deadline:
            configmap_result = self.kubectl(
                spec,
                environment,
                ("get", "configmap", "kubelet-config-1.22", "-n", "kube-system", "-o", "json"),
            )
            if configmap_result.rc == 0:
                break
            remaining = deadline - self.clock()
            if remaining > 0:
                self.sleep(min(5, remaining))
        configmap = _json(configmap_result, "kubelet ConfigMap")
        kubelet, count = re.subn(
            r"(?m)^(\s*clientCAFile:\s*)[^\s#]+",
            r"\g<1>{}".format(spec.kubelet_client_ca),
            configmap.get("data", {}).get("kubelet", ""),
        )
        if count != 1:
            raise MinikubeError("kubelet ConfigMap has an invalid client CA field")
        patch_args = (
            "patch",
            "configmap",
            "kubelet-config-1.22",
            "-n",
            "kube-system",
            "--type=merge",
            "-p",
            json.dumps({"data": {"kubelet": kubelet}}),
        )
        patched = False
        while self.clock() < deadline:
            if self.kubectl(spec, environment, patch_args).rc == 0:
                patched = True
                break
            remaining = deadline - self.clock()
            if remaining > 0:
                self.sleep(min(5, remaining))
        if not patched:
            raise MinikubeError("kubelet ConfigMap update failed")

    def api_credentials(self, spec: MinikubeSpec) -> Tuple[str, str]:
        values = []
        for path in ("/var/lib/minikube/certs/apiserver.crt", "/var/lib/minikube/certs/apiserver.key"):
            result = self.run(
                "sudo docker exec {} base64 -w0 {}".format(
                    shlex.quote(spec.profile), shlex.quote(path)
                ),
                private=True,
            )
            if result.rc != 0:
                raise MinikubeError("Minikube API credential retrieval failed")
            values.append(base64.b64decode(result.stdout.strip(), validate=True).decode("ascii"))
        return values[0], values[1]

    def node(self, spec: MinikubeSpec, environment: Mapping[str, str], name: str) -> Optional[KubernetesNode]:
        result = self.kubectl(spec, environment, ("get", "node", name, "-o", "json"))
        if result.rc != 0:
            if self._not_found(result):
                return None
            raise MinikubeError("Kubernetes node lookup failed")
        data = _json(result, "Kubernetes node")
        metadata = data.get("metadata", {})
        ready = any(
            item.get("type") == "Ready" and item.get("status") == "True"
            for item in data.get("status", {}).get("conditions", ())
        )
        return KubernetesNode(
            name=metadata.get("name", ""),
            uid=metadata.get("uid", ""),
            resource_version=metadata.get("resourceVersion", ""),
            owner=metadata.get("labels", {}).get(JOIN_OWNER_LABEL),
            ready=ready and not data.get("spec", {}).get("unschedulable", False),
            runtime=data.get("status", {}).get("nodeInfo", {}).get("containerRuntimeVersion", ""),
        )

    def wait_node_ready(self, spec: MinikubeSpec, environment: Mapping[str, str], name: str) -> KubernetesNode:
        deadline = self.clock() + spec.timeout_seconds
        while self.clock() < deadline:
            node = self.node(spec, environment, name)
            if node and node.ready and node.runtime.startswith("docker://"):
                return node
            self.sleep(2)
        raise MinikubeError("exact DUT node did not become ready")

    def claim_node(self, spec: MinikubeSpec, environment: Mapping[str, str], node: KubernetesNode, owner: str) -> None:
        path = JOIN_OWNER_LABEL.replace("~", "~0").replace("/", "~1")
        patch = [
            {"op": "test", "path": "/metadata/uid", "value": node.uid},
            {"op": "add", "path": "/metadata/labels/{}".format(path), "value": owner},
        ]
        result = self.kubectl(
            spec,
            environment,
            ("patch", "node", node.name, "--type=json", "-p", json.dumps(patch)),
        )
        if result.rc != 0:
            raise MinikubeError("DUT node ownership claim failed")

    def delete_owned_node(
        self,
        spec: MinikubeSpec,
        environment: Mapping[str, str],
        name: str,
        uid: str,
        owner: str,
    ) -> None:
        node = self.node(spec, environment, name)
        if node is None:
            return
        if node.uid != uid or node.owner != owner:
            raise MinikubeError("refusing to delete a changed or foreign DUT node")
        options = json.dumps({
            "apiVersion": "v1",
            "kind": "DeleteOptions",
            "preconditions": {"uid": uid},
            "propagationPolicy": "Foreground",
        })
        result = self.kubectl(
            spec,
            environment,
            ("delete", "--raw", "/api/v1/nodes/{}".format(name), "-f", "-"),
            options,
        )
        if result.rc != 0:
            raise MinikubeError("owned DUT node deletion failed")

    def wait_node_absent(self, spec: MinikubeSpec, environment: Mapping[str, str], name: str) -> None:
        deadline = self.clock() + spec.timeout_seconds
        while self.clock() < deadline:
            if self.node(spec, environment, name) is None:
                return
            self.sleep(2)
        raise MinikubeError("exact DUT node remains after cleanup")


class MinikubeCluster:
    def __init__(
        self,
        vmhost: Any,
        spec: Optional[MinikubeSpec] = None,
        proxy_environment: Optional[Mapping[str, Any]] = None,
        vmhost_user: Optional[str] = None,
        runner: Optional[Any] = None,
        ownership_token: Optional[str] = None,
    ):
        self.vmhost = vmhost
        self.spec = spec or MinikubeSpec()
        if runner is None and not vmhost_user:
            raise ValueError("MinikubeCluster requires the VM host user")
        self.runner = runner or AnsibleMinikubeRunner(vmhost, str(vmhost_user))
        self.vmhost_user = str(vmhost_user or getattr(self.runner, "vmhost_user", ""))
        self.ownership_token = ownership_token or str(uuid.uuid4())
        self.vmhost_ip = str(getattr(vmhost, "mgmt_ip", ""))
        ipaddress.ip_address(self.vmhost_ip)
        self.command_environment = merge_proxy_environment(
            proxy_environment,
            ("localhost", "127.0.0.1", self.vmhost_ip, "192.168.49.2", self.spec.api_dns),
        )
        self.command_environment["KUBECONFIG"] = self.spec.kubeconfig_path
        self.created = False
        self.profile_identity = None
        self.api_port = None
        self._locked = False
        self._entered = False
        self._binary_verified = False
        self._joined_duts = set()

    def __enter__(self) -> "MinikubeCluster":
        try:
            self.runner.acquire_lock(self.spec, self.ownership_token)
            self._locked = True
            self.runner.ensure_binary(self.spec, self.command_environment)
            self._binary_verified = True
            self.runner.reset_profile(self.spec, self.command_environment)
            self.runner.prepare_kubeconfig(self.spec)
            self.profile_identity = self.runner.start_profile(
                self.spec, self.command_environment, self.vmhost_ip
            )
            self.created = True
            identity, api_port, container_ip = self.runner.profile_container_network(self.spec)
            if identity != self.profile_identity:
                raise MinikubeError("created Minikube profile identity changed")
            self.api_port = api_port
            self.command_environment = merge_proxy_environment(
                self.command_environment,
                (container_ip,),
            )
            self.command_environment["KUBECONFIG"] = self.spec.kubeconfig_path
            self.runner.configure_profile(self.spec, self.command_environment)
            state = self.runner.inspect_profile(self.spec, self.command_environment)
            if state is None:
                raise MinikubeError("created Minikube profile is absent")
            if state.profile_identity != self.profile_identity or state.api_port != self.api_port:
                raise MinikubeError("created Minikube profile identity or API port changed")
            errors = state.incompatibilities(self.spec)
            if errors:
                raise MinikubeError("created Minikube profile is incompatible: {}".format("; ".join(errors)))
            self.profile_identity = state.profile_identity
            self.api_port = state.api_port
            self._entered = True
            return self
        except BaseException as error:
            cleanup_errors = self._cleanup_profile()
            if cleanup_errors:
                existing = tuple(getattr(error, "cleanup_errors", ()))
                setattr(error, "cleanup_errors", existing + tuple(cleanup_errors))
            raise

    def _cleanup_profile(self) -> Sequence[str]:
        errors = []
        if self._joined_duts:
            errors.append(
                "joined DUT cleanup is incomplete: {}".format(
                    ", ".join(sorted(self._joined_duts))
                )
            )
            return errors
        if self._locked:
            if self._binary_verified:
                try:
                    self.runner.reset_profile(self.spec, self.command_environment)
                    self.created = False
                    self.profile_identity = None
                    self.api_port = None
                except Exception as error:
                    errors.append("reset Minikube profile: {}".format(error))
            try:
                self.runner.release_lock(self.spec, self.ownership_token)
                self._locked = False
            except Exception as error:
                errors.append("release profile lock: {}".format(error))
        return errors

    def __exit__(self, exc_type: Any, exc: Optional[BaseException], traceback: Any) -> bool:
        errors = self._cleanup_profile()
        if errors:
            if exc is not None:
                existing = tuple(getattr(exc, "cleanup_errors", ()))
                setattr(exc, "cleanup_errors", existing + tuple(errors))
            else:
                raise MinikubeCleanupError("Minikube cleanup failed: {}".format("; ".join(errors)), errors)
        return False

    def joined_dut(
        self,
        duthost: Any,
        runner: Optional[Any] = None,
        ownership_token: Optional[str] = None,
    ) -> "JoinedMinikubeDut":
        if not self._entered:
            raise MinikubeError("MinikubeCluster must be entered before joining a DUT")
        return JoinedMinikubeDut(self, duthost, runner, ownership_token)


class AnsibleDutJoinRunner:
    def __init__(self, duthost: Any, clock: Any = time.monotonic, sleep: Any = time.sleep, timeout_seconds: int = 180):
        self.duthost = duthost
        self.clock = clock
        self.sleep = sleep
        self.timeout_seconds = timeout_seconds

    def run(self, command: str, stdin: Optional[str] = None, private: bool = False) -> HostResult:
        kwargs = {"module_ignore_errors": True, "verbose": not private}
        if stdin is not None:
            kwargs["stdin"] = stdin
        return _result(self.duthost.shell(command, **kwargs))

    def _hash(self, database: int) -> Dict[str, str]:
        data = _json(
            self.run("redis-cli -n {} --json HGETALL 'KUBERNETES_MASTER|SERVER'".format(database), private=True),
            "Kubernetes table",
        )
        if isinstance(data, dict):
            return {str(key): str(value) for key, value in data.items()}
        if isinstance(data, list) and len(data) % 2 == 0:
            return {str(data[index]): str(data[index + 1]) for index in range(0, len(data), 2)}
        raise MinikubeError("Kubernetes table has an invalid representation")

    def connected(self) -> bool:
        value = {key.lower(): item.lower() for key, item in self._hash(6).items()}.get("connected")
        if value is None:
            return False
        if value not in ("true", "false"):
            raise MinikubeError("SONiC Kubernetes connected state is unreadable")
        return value == "true"

    def preflight(self) -> None:
        if self.run("grep -q 'sonic-dri' /etc/motd", private=True).rc != 0:
            raise MinikubeError("DUT join requires an internal SONiC image")
        version = self.run("kubeadm version -o short", private=True)
        if version.rc != 0 or version.stdout.strip() != KUBERNETES_VERSION:
            raise MinikubeError("DUT kubeadm must be exactly {}".format(KUBERNETES_VERSION))
        config = {key.lower(): value for key, value in self._hash(4).items()}
        state = {key.lower(): value for key, value in self._hash(6).items()}
        if (
            config.get("ip", config.get("server_ip", "")).strip()
            or config.get("disable", "true").lower() not in ("true", "on")
            or state.get("connected", "false").lower() == "true"
            or self.connected()
        ):
            raise MinikubeError("DUT already has a Kubernetes association")
        if self.run(
            "sudo iptables-save -t nat | grep -q 'sonic-mgmt-minikube-'",
            private=True,
        ).rc == 0:
            raise MinikubeError("DUT has a stale Minikube API redirect")

    def capture_baseline(self, token: str) -> DutBaseline:
        directory = "{}/{}".format(BASELINE_ROOT, token)
        health = dict(self.duthost.critical_services_status())
        if not health or not all(health.values()):
            raise MinikubeError("DUT critical services are not healthy before join")
        script = r"""set -eu
umask 077
root="$1" baseline="$2"
install -d -m 0700 -o root -g root "$root"
mkdir -m 0700 "$baseline"
if [ -e /etc/sonic/credentials ]; then
  test -d /etc/sonic/credentials
  touch "$baseline/credentials.present"
  tar --acls --xattrs --numeric-owner --sort=name -cpf "$baseline/credentials.tar" -C /etc/sonic credentials
  (cd /etc/sonic &&
   find credentials -printf '%P|%y|%m|%U|%G|' -exec sha256sum {} \; 2>/dev/null |
   sort) > "$baseline/credentials.manifest"
else touch "$baseline/credentials.absent"; fi
for item in hosts:/etc/hosts kubelet:/etc/default/kubelet; do
  name=${item%%:*}; path=${item#*:}
  if [ -e "$path" ]; then
    test -f "$path"; touch "$baseline/$name.present"
    cat "$path" > "$baseline/$name.bytes"; stat -c '%a %u %g' "$path" > "$baseline/$name.meta"
  else touch "$baseline/$name.absent"; fi
done
for item in config:4 state:6; do
  name=${item%%:*}; db=${item#*:}; type=$(redis-cli -n "$db" --raw TYPE 'KUBERNETES_MASTER|SERVER')
  test "$type" = none -o "$type" = hash
  if [ "$type" = hash ]; then touch "$baseline/$name.present"; else touch "$baseline/$name.absent"; fi
  redis-cli -n "$db" --json HGETALL 'KUBERNETES_MASTER|SERVER' > "$baseline/$name.json"
done
iptables -t nat -S >/dev/null; ip6tables -t nat -S >/dev/null
iptables-save > "$baseline/iptables.raw.v4"
ip6tables-save > "$baseline/iptables.raw.v6"
if ! grep -qx '\*nat' "$baseline/iptables.raw.v4"; then iptables-save -t nat >> "$baseline/iptables.raw.v4"; fi
if ! grep -qx '\*nat' "$baseline/iptables.raw.v6"; then ip6tables-save -t nat >> "$baseline/iptables.raw.v6"; fi
grep -v '^#' "$baseline/iptables.raw.v4" | sed -E '/^:/s/\[[0-9]+:[0-9]+\]/[0:0]/' > "$baseline/iptables.v4"
grep -v '^#' "$baseline/iptables.raw.v6" | sed -E '/^:/s/\[[0-9]+:[0-9]+\]/[0:0]/' > "$baseline/iptables.v6"
rm -f "$baseline/iptables.raw.v4" "$baseline/iptables.raw.v6"
for service in ctrmgrd kubelet; do
  systemctl is-active "$service" > "$baseline/$service.active" || true
  systemctl is-enabled "$service" > "$baseline/$service.enabled" || true
done
chmod 0600 "$baseline"/*
"""
        result = self.run(
            "sudo sh -c {} sh {} {}".format(
                shlex.quote(script), shlex.quote(BASELINE_ROOT), shlex.quote(directory)
            ),
            private=True,
        )
        if result.rc != 0:
            self.run("sudo rm -rf -- {}".format(shlex.quote(directory)), private=True)
            raise MinikubeError("DUT baseline capture failed")
        return DutBaseline(directory, health)

    def install_credentials(self, baseline: DutBaseline, certificate: str, key: str, token: str) -> None:
        for name, content in (("crt", certificate), ("key", key)):
            target = "/etc/sonic/credentials/restapiserver.{}".format(name)
            temporary = "/etc/sonic/credentials/.restapiserver.{}.{}.tmp".format(name, token)
            script = (
                "install -d -m 0755 -o root -g root /etc/sonic/credentials; "
                "umask 077; cat > \"$1\"; chown root:root \"$1\"; "
                "chmod 0600 \"$1\"; mv -fT \"$1\" \"$2\""
            )
            if self.run(
                "sudo sh -c {} sh {} {}".format(shlex.quote(script), shlex.quote(temporary), shlex.quote(target)),
                stdin=content,
                private=True,
            ).rc != 0:
                raise MinikubeError("DUT API credential installation failed")

    def install_hosts(self, vmhost_ip: str, dns_name: str, token: str) -> None:
        line = "{} {}".format(vmhost_ip, dns_name)
        script = r"""set -eu
line="$1" dns="$2" token="$3"
path=/etc/hosts
tmp="/etc/.hosts.$token.tmp"
if awk -v dns="$dns" -v expected="$line" '
  $0 !~ /^[[:space:]]*#/ {
    for (i=2; i<=NF; i++) if ($i==dns && $0!=expected) found=1
  }
  END {exit found ? 0 : 1}
' "$path"; then exit 20; fi
if grep -Fqx "$line" "$path"; then exit 0; fi
cp --archive --no-dereference "$path" "$tmp"; printf '\n%s\n' "$line" >> "$tmp"; mv -fT "$tmp" "$path"
"""
        if self.run(
            "sudo sh -c {} sh {} {} {}".format(
                shlex.quote(script), shlex.quote(line), shlex.quote(dns_name), shlex.quote(token)
            ),
            private=True,
        ).rc != 0:
            raise MinikubeError("DUT hosts entry installation failed")

    def needs_node_ip_override(self) -> bool:
        result = self.run(
            "grep -q -- '--node-ip=::' /etc/default/kubelet",
            private=True,
        )
        if result.rc not in (0, 1):
            raise MinikubeError(
                "DUT kubelet node IP configuration is unreadable"
            )
        return result.rc == 0

    def install_node_ip(self, node_ip: str, token: str) -> None:
        ipaddress.ip_address(node_ip)
        script = r"""set -eu
source=/etc/default/kubelet; tmp="/etc/default/.kubelet.$2.tmp"
cp --archive --no-dereference "$source" "$tmp"
python3 - "$tmp" "$1" <<'PY'
import sys

path, node_ip = sys.argv[1:]
data = open(path, "rb").read()
old = b"--node-ip=::"
if data.count(old) != 1:
    raise SystemExit(20)
open(path, "wb").write(data.replace(old, ("--node-ip=" + node_ip).encode()))
PY
mv -fT "$tmp" "$source"; systemctl daemon-reload
"""
        if self.run(
            "sudo sh -c {} sh {} {}".format(shlex.quote(script), shlex.quote(node_ip), shlex.quote(token)),
            private=True,
        ).rc != 0:
            raise MinikubeError("DUT kubelet node IP update failed")

    def disable(self) -> None:
        if self.run("sudo config kube server disable on", private=True).rc != 0:
            raise MinikubeError("DUT Kubernetes association could not be disabled")

    def set_server_ip(self, address: str) -> None:
        ipaddress.ip_address(address)
        if self.run("sudo config kube server ip {}".format(shlex.quote(address)), private=True).rc != 0:
            raise MinikubeError("DUT Kubernetes server IP could not be configured")

    def set_server_port(self, port: int) -> None:
        if type(port) is not int or port <= 0 or port >= 65536:
            raise MinikubeError("DUT Kubernetes server port is invalid")
        if self.run("sudo config kube server port {}".format(port), private=True).rc != 0:
            raise MinikubeError("DUT Kubernetes server port could not be configured")

    def install_api_port_redirect(self, address: str, port: int, token: str) -> None:
        if ipaddress.ip_address(address).version != 4:
            raise MinikubeError("DUT Kubernetes API redirect currently requires IPv4 management")
        if type(port) is not int or port <= 0 or port >= 65536:
            raise MinikubeError("DUT Kubernetes redirect port is invalid")
        comment = "sonic-mgmt-minikube-{}".format(token)
        result = self.run(
            "sudo iptables -t nat -I OUTPUT 1 -p tcp -d {} --dport {} "
            "-m comment --comment {} -j DNAT --to-destination {}:{}".format(
                shlex.quote(address),
                DEFAULT_API_PORT,
                shlex.quote(comment),
                shlex.quote(address),
                port,
            ),
            private=True,
        )
        if result.rc != 0:
            raise MinikubeError("DUT Kubernetes API redirect could not be installed")

    def enable(self) -> None:
        if self.run("sudo config kube server disable off", private=True).rc != 0:
            raise MinikubeError("DUT Kubernetes association could not be enabled")

    def wait_connected(self, expected: bool) -> None:
        deadline = self.clock() + self.timeout_seconds
        while self.clock() < deadline:
            if self.connected() is expected:
                return
            self.sleep(2)
        config = self._hash(4)
        state = self._hash(6)
        server = config.get("ip", "")
        port = config.get("port", "")
        try:
            ipaddress.ip_address(server)
            port_number = int(port)
            if port_number <= 0 or port_number >= 65536:
                raise ValueError
        except ValueError:
            port_number = 0
        reachability = self.run(
            "timeout 3 bash -c {}".format(
                shlex.quote("</dev/tcp/{}/{}".format(server, port_number))
            ),
            private=True,
        ) if port_number else HostResult(2, "", "invalid endpoint")
        journal = self.run(
            "sudo journalctl -u ctrmgrd -n 80 --no-pager | grep -E 'kube|server:|join:' | tail -n 40",
            private=True,
        )
        raise MinikubeError(
            "SONiC Kubernetes connected state did not converge; config={}; state={}; "
            "tcp_rc={}; ctrmgrd={}".format(
                config,
                state,
                reachability.rc,
                journal.stdout.strip()[-2048:],
            )
        )

    def restore(self, baseline: DutBaseline, token: str) -> None:
        script = r"""set -eu
baseline="$1" token="$2"
systemctl stop kubelet ctrmgrd
if [ -f "$baseline/credentials.present" ]; then
  find /etc/sonic/credentials -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
  tar --acls --xattrs --numeric-owner -xpf "$baseline/credentials.tar" -C /etc/sonic
else rm -rf -- /etc/sonic/credentials; fi
for item in hosts:/etc/hosts kubelet:/etc/default/kubelet; do
  name=${item%%:*}; path=${item#*:}; tmp="${path%/*}/.$name.$token.tmp"
  if [ -f "$baseline/$name.present" ]; then
    set -- $(cat "$baseline/$name.meta")
    install -m "$1" -o "$2" -g "$3" "$baseline/$name.bytes" "$tmp"
    mv -fT "$tmp" "$path"
  else rm -f -- "$path"; fi
done
systemctl daemon-reload
python3 -c 'import json,sys
for path in sys.argv[1:]:
 d=json.load(open(path));
 if not isinstance(d,(dict,list)): raise SystemExit(20)' "$baseline/config.json" "$baseline/state.json"
for item in config:4 state:6; do
  name=${item%%:*}; db=${item#*:}
  redis-cli -n "$db" DEL 'KUBERNETES_MASTER|SERVER' >/dev/null
  if [ -f "$baseline/$name.present" ]; then
    python3 - "$db" 'KUBERNETES_MASTER|SERVER' "$baseline/$name.json" <<'PY'
import json
import subprocess
import sys

data = json.load(open(sys.argv[3]))
data = data if isinstance(data, dict) else dict(zip(data[::2], data[1::2]))
arguments = []
for key in sorted(data):
    arguments.extend((str(key), str(data[key])))
if arguments:
    command = ["redis-cli", "-n", sys.argv[1], "HSET", sys.argv[2]] + arguments
    subprocess.check_call(command, stdout=subprocess.DEVNULL)
PY
  fi
done
iptables-restore < "$baseline/iptables.v4"; ip6tables-restore < "$baseline/iptables.v6"
for service in ctrmgrd kubelet; do
  enabled=$(cat "$baseline/$service.enabled")
  case "$enabled" in
    enabled) systemctl unmask "$service"; systemctl enable "$service" ;;
    disabled) systemctl unmask "$service"; systemctl disable "$service" ;;
    masked) systemctl mask "$service" ;;
    static|indirect|generated|alias|linked|linked-runtime|enabled-runtime|masked-runtime) ;;
    *) exit 21 ;;
  esac
  active=$(cat "$baseline/$service.active")
  if [ "$active" = active ]; then
    systemctl start "$service"
  else
    systemctl stop "$service"
  fi
done
"""
        if self.run(
            "sudo sh -c {} sh {} {}".format(
                shlex.quote(script), shlex.quote(baseline.directory), shlex.quote(token)
            ),
            private=True,
        ).rc != 0:
            raise MinikubeError("DUT baseline restore failed")

    def verify_restore(self, baseline: DutBaseline) -> None:
        script = r"""set -eu
baseline="$1"
if [ -f "$baseline/credentials.present" ]; then
  (cd /etc/sonic &&
   find credentials -printf '%P|%y|%m|%U|%G|' -exec sha256sum {} \; 2>/dev/null |
   sort) > "$baseline/credentials.verify.manifest"
  cmp -s "$baseline/credentials.manifest" "$baseline/credentials.verify.manifest"
  rm -f "$baseline/credentials.verify.manifest"
else test ! -e /etc/sonic/credentials; fi
for item in hosts:/etc/hosts kubelet:/etc/default/kubelet; do
  name=${item%%:*}; path=${item#*:}
  if [ -f "$baseline/$name.present" ]; then
    cmp -s "$baseline/$name.bytes" "$path"
    test "$(tr ' ' ':' < "$baseline/$name.meta")" = "$(stat -c '%a:%u:%g' "$path")"
  else test ! -e "$path"; fi
done
for item in config:4 state:6; do
  name=${item%%:*}; db=${item#*:}
  type=$(redis-cli -n "$db" --raw TYPE 'KUBERNETES_MASTER|SERVER')
  if [ -f "$baseline/$name.present" ]; then test "$type" = hash; else test "$type" = none; fi
  redis-cli -n "$db" --json HGETALL 'KUBERNETES_MASTER|SERVER' > "$baseline/$name.verify.json"
  python3 - "$name" "$baseline/$name.json" "$baseline/$name.verify.json" <<'PY'
from datetime import datetime
import json
import sys

def value(path):
    data = json.load(open(path))
    items = data.items() if isinstance(data, dict) else zip(data[::2], data[1::2])
    return {str(key): str(item) for key, item in items}

name, before_path, after_path = sys.argv[1:]
before = value(before_path)
after = value(after_path)
if name == "state" and "update_time" in before:
    timestamp = after.pop("update_time", "")
    before.pop("update_time")
    datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
raise SystemExit(0 if before == after else 20)
PY
done
iptables-save > "$baseline/iptables.verify.raw.v4"
ip6tables-save > "$baseline/iptables.verify.raw.v6"
if ! grep -qx '\*nat' "$baseline/iptables.verify.raw.v4"; then
  iptables-save -t nat >> "$baseline/iptables.verify.raw.v4"
fi
if ! grep -qx '\*nat' "$baseline/iptables.verify.raw.v6"; then
  ip6tables-save -t nat >> "$baseline/iptables.verify.raw.v6"
fi
grep -v '^#' "$baseline/iptables.verify.raw.v4" |
  sed -E '/^:/s/\[[0-9]+:[0-9]+\]/[0:0]/' > "$baseline/iptables.verify.v4"
grep -v '^#' "$baseline/iptables.verify.raw.v6" |
  sed -E '/^:/s/\[[0-9]+:[0-9]+\]/[0:0]/' > "$baseline/iptables.verify.v6"
rm -f "$baseline/iptables.verify.raw.v4" "$baseline/iptables.verify.raw.v6"
cmp -s "$baseline/iptables.v4" "$baseline/iptables.verify.v4"
cmp -s "$baseline/iptables.v6" "$baseline/iptables.verify.v6"
for service in ctrmgrd kubelet; do
  test "$(systemctl is-active "$service" || true)" = "$(cat "$baseline/$service.active")"
  test "$(systemctl is-enabled "$service" || true)" = "$(cat "$baseline/$service.enabled")"
done
"""
        if self.run(
            "sudo sh -c {} sh {}".format(shlex.quote(script), shlex.quote(baseline.directory)),
            private=True,
        ).rc != 0:
            raise MinikubeError("DUT baseline verification failed")
        current = dict(self.duthost.critical_services_status())
        if current != dict(baseline.critical_health) or not all(current.values()):
            raise MinikubeError("DUT critical service health changed")

    def remove_baseline(self, baseline: DutBaseline) -> None:
        if not baseline.directory.startswith(BASELINE_ROOT + "/"):
            raise MinikubeError("refusing to remove a baseline outside the owned root")
        if self.run("sudo rm -rf -- {}".format(shlex.quote(baseline.directory)), private=True).rc != 0:
            raise MinikubeError("DUT baseline could not be removed")


class JoinedMinikubeDut:
    def __init__(
        self,
        cluster: MinikubeCluster,
        duthost: Any,
        runner: Optional[Any] = None,
        ownership_token: Optional[str] = None,
    ):
        self.cluster = cluster
        self.duthost = duthost
        self.node_name = str(getattr(duthost, "hostname", ""))
        if not self.node_name:
            raise ValueError("joined DUT must expose a hostname")
        self.runner = runner or AnsibleDutJoinRunner(duthost)
        self.ownership_token = ownership_token or str(uuid.uuid4())
        self.node_uid = None
        self._baseline = None
        self._unclean_workloads = []

    def mark_workload_unclean(self, message: str) -> None:
        self._unclean_workloads.append(message)

    def __enter__(self) -> "JoinedMinikubeDut":
        if self.node_name in self.cluster._joined_duts:
            raise MinikubeError("DUT lifecycle is already active: {}".format(self.node_name))
        self.cluster._joined_duts.add(self.node_name)
        try:
            self.runner.preflight()
            if self.cluster.runner.node(
                self.cluster.spec, self.cluster.command_environment, self.node_name
            ) is not None:
                raise MinikubeError("exact DUT node already exists")
            self._baseline = self.runner.capture_baseline(self.ownership_token)
            certificate, key = self.cluster.runner.api_credentials(self.cluster.spec)
            self.runner.install_credentials(self._baseline, certificate, key, self.ownership_token)
            self.runner.install_hosts(self.cluster.vmhost_ip, self.cluster.spec.api_dns, self.ownership_token)
            if self.runner.needs_node_ip_override():
                self.runner.install_node_ip(str(getattr(self.duthost, "mgmt_ip", "")), self.ownership_token)
            self.runner.disable()
            self.runner.set_server_ip(self.cluster.vmhost_ip)
            self.runner.set_server_port(self.cluster.api_port)
            if self.cluster.api_port != DEFAULT_API_PORT:
                self.runner.install_api_port_redirect(
                    self.cluster.vmhost_ip, self.cluster.api_port, self.ownership_token
                )
            self.runner.enable()
            self.runner.wait_connected(True)
            node = self.cluster.runner.wait_node_ready(
                self.cluster.spec, self.cluster.command_environment, self.node_name
            )
            self.cluster.runner.claim_node(
                self.cluster.spec, self.cluster.command_environment, node, self.ownership_token
            )
            self.node_uid = node.uid
            return self
        except BaseException as error:
            if self._baseline is not None:
                cleanup = self._cleanup()
                if cleanup:
                    existing = tuple(getattr(error, "cleanup_errors", ()))
                    setattr(error, "cleanup_errors", existing + tuple(cleanup))
                else:
                    self.cluster._joined_duts.discard(self.node_name)
            else:
                self.cluster._joined_duts.discard(self.node_name)
            raise

    def _cleanup(self) -> Sequence[str]:
        if self._unclean_workloads:
            return ["workload cleanup is incomplete: {}".format("; ".join(self._unclean_workloads))]
        action_errors = []

        def attempt(name: str, function: Any, *args: Any) -> bool:
            try:
                function(*args)
            except Exception as error:
                action_errors.append("{}: {}".format(name, error))
                return False
            return True

        attempt("disable association", self.runner.disable)
        disconnected = attempt("wait disconnected", self.runner.wait_connected, False)
        if self.node_uid:
            attempt(
                "delete owned node",
                self.cluster.runner.delete_owned_node,
                self.cluster.spec,
                self.cluster.command_environment,
                self.node_name,
                self.node_uid,
                self.ownership_token,
            )
        node_absent = attempt(
            "wait node absent",
            self.cluster.runner.wait_node_absent,
            self.cluster.spec,
            self.cluster.command_environment,
            self.node_name,
        )
        if not disconnected or not node_absent:
            action_errors.append("baseline preserved because DUT disconnection or node removal was not proven")
            return action_errors

        if action_errors:
            logger.warning("DUT cleanup recovered after: %s", "; ".join(action_errors))

        restore_errors = []

        def restore_attempt(name: str, function: Any, *args: Any) -> bool:
            try:
                function(*args)
            except Exception as error:
                restore_errors.append("{}: {}".format(name, error))
                return False
            return True

        restored = restore_attempt("restore baseline", self.runner.restore, self._baseline, self.ownership_token)
        verified = restored and restore_attempt("verify baseline", self.runner.verify_restore, self._baseline)
        if verified:
            restore_attempt("remove baseline", self.runner.remove_baseline, self._baseline)
        return restore_errors

    def __exit__(self, exc_type: Any, exc: Optional[BaseException], traceback: Any) -> bool:
        errors = self._cleanup()
        if errors:
            if exc is not None:
                existing = tuple(getattr(exc, "cleanup_errors", ()))
                setattr(exc, "cleanup_errors", existing + tuple(errors))
            else:
                raise MinikubeCleanupError("DUT cleanup failed: {}".format("; ".join(errors)), errors)
        else:
            self.cluster._joined_duts.discard(self.node_name)
        return False
