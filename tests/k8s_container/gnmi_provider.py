"""Kubernetes gNMI provider for container infrastructure tests."""

import json
import inspect
import logging
import re
import shlex
import time
import uuid
from contextlib import contextmanager

import pytest

from tests.common.system_utils.docker import load_docker_registry_info
from tests.common.minikube import DEFAULT_PROFILE
from tests.common.minikube import MinikubeLockHeldError
from tests.common.helpers.dut_utils import creds_on_dut
from tests.common.gu_utils import create_checkpoint
from tests.common.gu_utils import delete_checkpoint
from tests.common.gu_utils import rollback
from tests.common.gu_utils import verify_checkpoints_exist
from tests.common.gnmi_setup import check_system_time_sync
from tests.common.helpers.gnmi_utils import create_gnmi_certs
from tests.common.helpers.gnmi_utils import delete_gnmi_certs
from tests.common.helpers.gnmi_utils import GNMIEnvironment
from tests.k8s_container.container_spec import SPEC_DIRECTORY
from tests.k8s_container.container_spec import load_container_spec
from tests.k8s_container.lifecycle import MinikubeCommandBoundary
from tests.k8s_container.lifecycle import deploy_workload
from tests.k8s_container.workload import ContainerSpec
from tests.k8s_container.workload import WorkloadBundle


pytest_plugins = ("tests.common.fixtures.minikube",)

logger = logging.getLogger(__name__)
SPEC_PATH = SPEC_DIRECTORY / "gnmi.yaml"
PAUSE_IMAGE = "k8s.gcr.io/pause:3.5"
PAUSE_SOURCE_IMAGE = "publicmirror.azurecr.io/pause:3.5"
DUT_CERTIFICATE_PATHS = (
    "/etc/sonic/telemetry/gnmiCA.pem",
    "/etc/sonic/telemetry/gnmiserver.crt",
    "/etc/sonic/telemetry/gnmiserver.key",
    "/etc/sonic/telemetry/gnmiclient.crt",
    "/etc/sonic/telemetry/gnmiclient.key",
)
PTF_CERTIFICATE_PATHS = (
    "/root/gnmiCA.pem",
    "/root/gnmiclient.crt",
    "/root/gnmiclient.key",
    "/root/gnmiclient.revoked.crt",
    "/root/gnmiclient.revoked.key",
    "/root/sonic.crl.pem",
    "/root/crl_server.py",
)


class ProviderCleanupError(RuntimeError):
    def __init__(self, message):
        super().__init__(message)
        self.cleanup_errors = (message,)
        self.preserve_environment = True


def _option(request, name, default):
    try:
        return request.config.getoption(name)
    except ValueError:
        return default


def _selected_images(request, duthost, spec):
    role = _option(request, "--k8s-gnmi-role", "golden")
    candidate = _option(request, "--k8s-gnmi-image", None)
    machine = duthost.shell("uname -m", module_ignore_errors=True)
    architecture = machine.get("stdout", "").strip()
    if machine.get("rc", 1) != 0 or not architecture:
        pytest.fail("unable to determine DUT architecture for gNMI images")
    try:
        images = {
            name: spec.golden_image(name, architecture)
            for name in spec.container_names
        }
    except ValueError as error:
        pytest.fail(str(error))
    if role == "candidate":
        if not candidate:
            pytest.fail("--k8s-gnmi-image is required for the candidate role")
        images["gnmi"] = candidate
    elif candidate:
        pytest.fail("the golden role uses checked-in soniccr1 tags, not --k8s-gnmi-image")
    for name, image in images.items():
        ContainerSpec(name=name, image=image)
    return images


def _normalized_image_id(image_id):
    return image_id.rsplit("sha256:", 1)[-1]


def _runtime_image_id(duthost, pod_uid, container_name):
    result = duthost.shell(
        "docker ps -q --filter {} --filter {}".format(
            shlex.quote("label=io.kubernetes.pod.uid={}".format(pod_uid)),
            shlex.quote("label=io.kubernetes.container.name={}".format(container_name)),
        ),
        module_ignore_errors=True,
    )
    container_ids = result.get("stdout", "").split()
    if result.get("rc", 1) != 0 or len(container_ids) != 1:
        pytest.fail("Unable to resolve one Kubernetes {} runtime container".format(container_name))
    inspection = duthost.shell(
        "docker inspect {}".format(shlex.quote(container_ids[0])),
        module_ignore_errors=True,
    )
    try:
        return json.loads(inspection.get("stdout", ""))[0]["Image"]
    except (ValueError, IndexError, KeyError, TypeError):
        pytest.fail("Kubernetes {} runtime inspection is invalid".format(container_name))


def _remote_file_baseline(host, root, paths, sudo=False):
    command = r"""set -eu
root="$1"; shift; tmp="$root.$$.tmp"; umask 077
test ! -e "$root"; mkdir -m 0700 "$tmp"; trap 'rm -rf -- "$tmp"' EXIT
index=0
for path in "$@"; do
  if [ -e "$path" ]; then
    test -f "$path" -a ! -L "$path"
    touch "$tmp/$index.present"
    cat "$path" > "$tmp/$index.bytes"
    stat -c '%a %u %g' "$path" > "$tmp/$index.meta"
  else
    touch "$tmp/$index.absent"
  fi
  index=$((index + 1))
done
mv -T "$tmp" "$root"; trap - EXIT
"""
    prefix = "sudo " if sudo else ""
    result = host.shell(
        "{}sh -c {} sh {} {}".format(
            prefix,
            shlex.quote(command),
            shlex.quote(root),
            " ".join(shlex.quote(path) for path in paths),
        ),
        module_ignore_errors=True,
        verbose=False,
    )
    if result.get("rc", 1) != 0:
        pytest.fail("Unable to capture certificate file baseline")


def _restore_remote_files(host, root, paths, sudo=False):
    command = r"""set -eu
root="$1"; shift
index=0
for path in "$@"; do
  present="$root/$index.present"; absent="$root/$index.absent"
  if { [ -f "$present" ] && [ -f "$absent" ]; } || { [ ! -f "$present" ] && [ ! -f "$absent" ]; }; then
    exit 23
  fi
  if [ -f "$present" ]; then
    set -- $(cat "$root/$index.meta")
    tmp="${path%/*}/.sonic-mgmt-cert-$index.tmp"
    install -m "$1" -o "$2" -g "$3" "$root/$index.bytes" "$tmp"
    mv -fT "$tmp" "$path"
  else
    rm -f -- "$path"
  fi
  index=$((index + 1))
done
rm -rf -- "$root"
"""
    prefix = "sudo " if sudo else ""
    return host.shell(
        "{}sh -c {} sh {} {}".format(
            prefix,
            shlex.quote(command),
            shlex.quote(root),
            " ".join(shlex.quote(path) for path in paths),
        ),
        module_ignore_errors=True,
        verbose=False,
    )


def _gnmi_processes(duthost, container):
    processes = duthost.shell(
        "docker exec {} ps -ww -eo pid=,args=".format(shlex.quote(container)),
        module_ignore_errors=True,
    )
    if processes.get("rc", 1) != 0:
        raise RuntimeError("Unable to inspect Kubernetes gNMI process state")
    result = set()
    for line in processes.get("stdout", "").splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2 and re.match(r"^/usr/sbin/(?:gnmi|telemetry)(?:\s|$)", parts[1]):
            result.add((parts[0], parts[1]))
    return result


def _supervisor_baseline(duthost):
    container = _resolve_gnmi_container(duthost)
    if not container:
        raise RuntimeError("Unable to resolve Kubernetes gNMI container before TLS setup")
    result = duthost.shell(
        "docker exec {} supervisorctl status".format(shlex.quote(container)),
        module_ignore_errors=True,
    )
    if not result.get("stdout", "").strip():
        raise RuntimeError("Unable to inspect Kubernetes gNMI supervisor state")
    programs = tuple(
        line.split()[0]
        for line in result.get("stdout", "").splitlines()
        if len(line.split()) >= 2 and line.split()[1] == "RUNNING"
    )
    return programs, tuple(sorted(_gnmi_processes(duthost, container)))


def _restore_supervisor_programs(duthost, expected_programs, baseline_processes):
    container = _resolve_gnmi_container(duthost)
    if not container:
        return "unable to resolve Kubernetes gNMI container during TLS cleanup"
    current_processes = _gnmi_processes(duthost, container)
    baseline_commands = {command for _, command in baseline_processes}
    process_cleanup_error = None
    for pid, process in sorted(current_processes):
        if process in baseline_commands:
            continue
        if not pid.isdigit():
            return "unable to identify test-started gNMI process"
        command = r"""set -eu
container="$1" pid="$2" expected="$3"
docker exec "$container" sh -c '
  set -eu
  pid="$1" expected="$2"
  actual=$(ps -ww -p "$pid" -o args= 2>/dev/null || true)
  [ -z "$actual" ] && exit 0
  test "$actual" = "$expected"
  kill "$pid"
' sh "$pid" "$expected"
"""
        result = duthost.shell(
            "sh -c {} sh {} {} {}".format(
                shlex.quote(command),
                shlex.quote(container),
                shlex.quote(pid),
                shlex.quote(process),
            ),
            module_ignore_errors=True,
        )
        if result.get("rc", 1) != 0:
            process_cleanup_error = "test-started gNMI process identity changed before cleanup"
            break
    status = duthost.shell(
        "docker exec {} supervisorctl status".format(shlex.quote(container)),
        module_ignore_errors=True,
    )
    if not status.get("stdout", "").strip():
        return "unable to inspect Kubernetes gNMI supervisor during TLS cleanup"
    current_programs = tuple(
        line.split()[0]
        for line in status.get("stdout", "").splitlines()
        if len(line.split()) >= 2 and line.split()[1] == "RUNNING"
    )
    for program in sorted(set(current_programs) - set(expected_programs)):
        result = duthost.shell(
            "docker exec {} supervisorctl stop {}".format(
                shlex.quote(container), shlex.quote(program)
            ),
            module_ignore_errors=True,
        )
        if result.get("rc", 1) != 0:
            return "unable to stop unexpected supervisor program {}".format(program)
    for program in expected_programs:
        result = duthost.shell(
            "docker exec {} supervisorctl start {}".format(
                shlex.quote(container), shlex.quote(program)
            ),
            module_ignore_errors=True,
        )
        if result.get("rc", 1) != 0 and "already started" not in result.get("stderr", ""):
            return "unable to start baseline supervisor program {}".format(program)
    deadline = time.time() + 60
    programs = ()
    test_processes = set()
    while time.time() < deadline:
        programs, _ = _supervisor_baseline(duthost)
        remaining_processes = _gnmi_processes(duthost, container)
        test_processes = {
            (pid, command)
            for pid, command in remaining_processes
            if command not in baseline_commands
        }
        if set(programs) == set(expected_programs) and not test_processes:
            return process_cleanup_error
        time.sleep(2)
    return process_cleanup_error or (
        "Kubernetes gNMI supervisor state did not return to its baseline; "
        "expected_programs={}; actual_programs={}; remaining_test_processes={}".format(
            sorted(expected_programs), sorted(programs), sorted(test_processes)
        )
    )


def _remove_local_certificates(localhost):
    delete_gnmi_certs(localhost)
    return localhost.shell(
        "rm -f -- crlext.cnf sonic.crl.pem gnmi/crl/index.* gnmi/crl/sonic_crl_number*",
        module_ignore_errors=True,
        verbose=False,
    )


def _apply_tls_runtime(duthost, baseline_processes):
    environment = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    container = environment.gnmi_container
    facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
    subtype = facts["DEVICE_METADATA"]["localhost"].get("subtype")
    status = duthost.shell(
        "docker exec {} supervisorctl status".format(shlex.quote(container)),
        module_ignore_errors=True,
    )
    if not status.get("stdout", "").strip():
        pytest.fail("Unable to inspect Kubernetes gNMI supervisor before TLS setup")
    for line in status.get("stdout", "").splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[1] == "RUNNING":
            result = duthost.shell(
                "docker exec {} supervisorctl stop {}".format(
                    shlex.quote(container), shlex.quote(fields[0])
                ),
                module_ignore_errors=True,
            )
            if result.get("rc", 1) != 0:
                pytest.fail("Unable to stop Kubernetes gNMI supervisor program")
    for pid, process in baseline_processes:
        if process.startswith("/usr/sbin/{0} ".format(environment.gnmi_process)):
            command = r"""set -eu
container="$1" pid="$2" expected="$3"
docker exec "$container" sh -c '
  set -eu
  pid="$1" expected="$2"
  actual=$(ps -ww -p "$pid" -o args= 2>/dev/null || true)
  [ -z "$actual" ] && exit 0
  test "$actual" = "$expected"
  kill "$pid"
' sh "$pid" "$expected"
"""
            result = duthost.shell(
                "sh -c {} sh {} {} {}".format(
                    shlex.quote(command),
                    shlex.quote(container),
                    shlex.quote(pid),
                    shlex.quote(process),
                ),
                module_ignore_errors=True,
            )
            if result.get("rc", 1) != 0:
                pytest.fail("Unable to stop exact Kubernetes gNMI process")
    command = (
        "docker exec {container} bash -c {runtime}"
    ).format(
        container=shlex.quote(container),
        runtime=shlex.quote(
            "/usr/bin/nohup /usr/sbin/{process} -logtostderr --port {port} "
            "--server_crt /etc/sonic/telemetry/gnmiserver.crt "
            "--server_key /etc/sonic/telemetry/gnmiserver.key "
            "--config_table_name GNMI_CLIENT_CERT --client_auth cert --enable_crl=true "
            "{zmq}--ca_crt /etc/sonic/telemetry/gnmiCA.pem -gnmi_native_write=true -v=10 "
            ">/root/gnmi.log 2>&1 &".format(
                process=environment.gnmi_process,
                port=environment.gnmi_port,
                zmq="--zmq_address=tcp://127.0.0.1:8100 " if subtype == "SmartSwitch" else "",
            )
        ),
    )
    result = duthost.shell(command, module_ignore_errors=True)
    if result.get("rc", 1) != 0:
        pytest.fail("Unable to start Kubernetes gNMI TLS runtime")
    role = "gnmi_readwrite,gnmi_config_db_readwrite,gnmi_appl_db_readwrite,gnmi_dpu_appl_db_readwrite,gnoi_readwrite"
    for common_name in ("test.client.gnmi.sonic", "test.client.revoked.gnmi.sonic"):
        result = duthost.shell(
            'sudo sonic-db-cli CONFIG_DB hset "GNMI_CLIENT_CERT|{}" "role@" {}'.format(
                common_name, shlex.quote(role)
            ),
            module_ignore_errors=True,
        )
        if result.get("rc", 1) != 0:
            pytest.fail("Unable to configure Kubernetes gNMI client role")
    deadline = time.time() + 30
    while time.time() < deadline:
        current_processes = _gnmi_processes(duthost, container)
        baseline_commands = {command for _, command in baseline_processes}
        test_processes = {
            (pid, command)
            for pid, command in current_processes
            if command not in baseline_commands
        }
        if len(test_processes) != 1:
            time.sleep(1)
            continue
        test_pid, _ = next(iter(test_processes))
        listening = duthost.shell(
            "sudo ss -ltnp | grep ':{} ' | grep 'pid={},'".format(
                environment.gnmi_port, test_pid
            ),
            module_ignore_errors=True,
        )
        if listening.get("stdout", "").strip():
            if duthost.facts["platform"] != "x86_64-kvm_x86_64-r0" and not check_system_time_sync(duthost):
                pytest.fail("Kubernetes gNMI DUT time is not synchronized")
            return
        time.sleep(3)
    pytest.fail("Kubernetes gNMI TLS runtime did not start")


@contextmanager
def _gnmi_tls_context(duthost, localhost, ptfhost):
    token = str(uuid.uuid4())
    checkpoint = "k8s-gnmi-{}".format(token)
    dut_baseline = "/var/tmp/sonic-mgmt-gnmi-certs-{}".format(token)
    ptf_baseline = "/tmp/sonic-mgmt-gnmi-certs-{}".format(token)
    runtime_mutation_attempted = False
    dut_baseline_created = False
    ptf_baseline_created = False
    primary_error = None
    checkpoint_expected = False
    stopped_programs = ()
    unmanaged_processes = ()
    try:
        _remote_file_baseline(duthost, dut_baseline, DUT_CERTIFICATE_PATHS, sudo=True)
        dut_baseline_created = True
        _remote_file_baseline(ptfhost, ptf_baseline, PTF_CERTIFICATE_PATHS)
        ptf_baseline_created = True
        create_checkpoint(duthost, checkpoint)
        checkpoint_expected = True
        create_gnmi_certs(duthost, localhost, ptfhost)
        stopped_programs, unmanaged_processes = _supervisor_baseline(duthost)
        runtime_mutation_attempted = True
        _apply_tls_runtime(duthost, unmanaged_processes)
        yield
    except BaseException as error:
        primary_error = error
        raise
    finally:
        cleanup_errors = []
        cleanup_warnings = []
        checkpoint_present = False
        try:
            checkpoint_present = verify_checkpoints_exist(duthost, checkpoint)
        except BaseException as error:
            cleanup_errors.append("unable to inspect gNMI TLS checkpoint: {}".format(error))
        if checkpoint_expected and not checkpoint_present:
            cleanup_errors.append("gNMI TLS checkpoint disappeared before cleanup")
        if checkpoint_present:
            try:
                result = rollback(duthost, checkpoint)
                rollback_ok = (
                    result.get("rc", 1) == 0
                    and "Config rolled back successfully" in result.get("stdout", "")
                )
                if rollback_ok:
                    delete_checkpoint(duthost, checkpoint)
                else:
                    cleanup_errors.append("unable to roll back gNMI TLS checkpoint; checkpoint retained")
            except BaseException as error:
                cleanup_errors.append("unable to roll back gNMI TLS checkpoint: {}".format(error))
        for created, host, root, paths, sudo in (
            (dut_baseline_created, duthost, dut_baseline, DUT_CERTIFICATE_PATHS, True),
            (ptf_baseline_created, ptfhost, ptf_baseline, PTF_CERTIFICATE_PATHS, False),
        ):
            if not created:
                continue
            try:
                result = _restore_remote_files(host, root, paths, sudo=sudo)
                if result.get("rc", 1) != 0:
                    cleanup_errors.append("unable to restore certificate files from {}".format(root))
            except BaseException as error:
                cleanup_errors.append("unable to restore certificate files from {}: {}".format(root, error))
        if runtime_mutation_attempted:
            try:
                runtime_error = _restore_supervisor_programs(
                    duthost, stopped_programs, unmanaged_processes
                )
                if runtime_error:
                    cleanup_warnings.append(runtime_error)
            except BaseException as error:
                cleanup_warnings.append("unable to restore gNMI supervisor state: {}".format(error))
        try:
            result = _remove_local_certificates(localhost)
            if result.get("rc", 1) != 0:
                cleanup_errors.append("unable to remove local gNMI certificate files")
        except BaseException as error:
            cleanup_errors.append("unable to remove local gNMI certificate files: {}".format(error))
        if cleanup_warnings:
            logger.warning("gNMI workload runtime cleanup recovered after: %s", "; ".join(cleanup_warnings))
        if cleanup_errors:
            if primary_error is not None:
                existing = tuple(getattr(primary_error, "cleanup_errors", ()))
                setattr(primary_error, "cleanup_errors", existing + tuple(cleanup_errors))
                setattr(primary_error, "preserve_environment", True)
                logger.error("gNMI TLS cleanup failed: %s", "; ".join(cleanup_errors))
            else:
                raise ProviderCleanupError(
                    "gNMI TLS cleanup failed: {}".format("; ".join(cleanup_errors))
                )


@pytest.fixture(scope="module")
def kubernetes_gnmi_tls_context():
    return _gnmi_tls_context


def _resolve_gnmi_container(duthost):
    identity = getattr(duthost, "_kubernetes_gnmi_identity", None)
    if identity is None:
        return None
    result = duthost.shell(
        "docker ps -q --filter {} --filter {}".format(
            shlex.quote("label=io.kubernetes.pod.uid={}".format(identity["pod_uid"])),
            shlex.quote("label=io.kubernetes.container.name=gnmi"),
        ),
        module_ignore_errors=True,
    )
    container_ids = result.get("stdout", "").split()
    if result.get("rc", 1) != 0 or len(container_ids) != 1:
        return None
    inspection = duthost.shell(
        "docker inspect {}".format(shlex.quote(container_ids[0])), module_ignore_errors=True
    )
    try:
        image_id = json.loads(inspection.get("stdout", ""))[0]["Image"]
    except (ValueError, IndexError, KeyError, TypeError):
        return None
    if _normalized_image_id(image_id) != _normalized_image_id(identity["image_id"]):
        return None
    return container_ids[0]


def _generate_gnmi_config(environment, duthost):
    container = _resolve_gnmi_container(duthost)
    if not container:
        logger.warning("Kubernetes gNMI container is not running")
        return False
    environment.gnmi_config_table = "GNMI"
    environment.gnmi_container = container
    environment.gnmi_program = "gnmi-native"
    processes = duthost.shell(
        "docker exec {} ps -ef".format(shlex.quote(container)),
        module_ignore_errors=True,
    )
    environment.gnmi_process = "gnmi" if "/usr/sbin/gnmi" in processes.get("stdout", "") else "telemetry"
    environment._configure_connection_params(duthost)
    return True


@contextmanager
def _patched_public_gnmi_runtime():
    from tests.common.helpers.gnmi_utils import GNMIEnvironment

    original_generate = GNMIEnvironment.generate_gnmi_config
    if tuple(inspect.signature(original_generate).parameters) != ("self", "duthost"):
        pytest.fail("GNMIEnvironment.generate_gnmi_config signature changed")
    GNMIEnvironment.generate_gnmi_config = _generate_gnmi_config
    try:
        yield
    finally:
        GNMIEnvironment.generate_gnmi_config = original_generate


def _image_id(host, image):
    result = host.command(
        argv=["docker", "image", "inspect", image],
        module_ignore_errors=True,
        verbose=False,
    )
    if result.get("rc", 1) != 0:
        return None
    try:
        return json.loads(result.get("stdout", ""))[0]["Id"]
    except (ValueError, IndexError, KeyError, TypeError):
        pytest.fail("Image inspection returned invalid JSON for {}".format(image))


def _registry_host(value):
    host = value.rstrip("/")
    return host[:-4] if host.endswith(":443") else host


def _tagged_image(image):
    last_slash = image.rfind("/")
    separator = image.rfind(":")
    if separator <= last_slash or "@" in image:
        pytest.fail("Nightly image staging requires a version-pinned tag: {}".format(image))
    registry_and_repository = image[:separator]
    registry, found, repository = registry_and_repository.partition("/")
    if not found:
        pytest.fail("Nightly image staging requires an explicit registry: {}".format(image))
    return registry, repository, image[separator + 1:]


def _dut_docker(duthost, docker_config, arguments):
    return duthost.command(
        argv=["env", "DOCKER_CONFIG={}".format(docker_config), "docker"] + list(arguments),
        module_ignore_errors=True,
        verbose=False,
    )


def _pull_private_image(duthost, docker_config, creds, image, logged_in):
    registry_name, repository, tag = _tagged_image(image)
    registry = load_docker_registry_info(duthost, creds)
    if _registry_host(registry.host) != _registry_host(registry_name):
        pytest.fail("Registry credentials do not match {}".format(registry_name))
    if registry_name not in logged_in:
        if not registry.username or not registry.password:
            pytest.fail("Registry credentials are required for {}".format(registry_name))
        result = duthost._run(
            "community.docker.docker_login",
            registry_url=registry_name,
            username=registry.username,
            password=registry.password,
            config_path="{}/config.json".format(docker_config),
            reauthorize=True,
            module_ignore_errors=True,
            verbose=False,
        )
        if result.get("failed", True):
            pytest.fail("Unable to authenticate to {}".format(registry_name))
        logged_in.add(registry_name)
    result = _dut_docker(duthost, docker_config, ["pull", "{}/{}:{}".format(registry_name, repository, tag)])
    if result.get("rc", 1) != 0:
        pytest.fail("Unable to pull {} on the DUT".format(image))


def _restore_image_reference(duthost, image, before_id, staged_id):
    current_id = _image_id(duthost, image)
    if current_id is None:
        if before_id is None:
            return None
        result = duthost.command(
            argv=["docker", "tag", before_id, image],
            module_ignore_errors=True,
            verbose=False,
        )
        restored_id = _image_id(duthost, image)
        if (
            result.get("rc", 1) != 0
            or restored_id is None
            or _normalized_image_id(restored_id) != _normalized_image_id(before_id)
        ):
            return "unable to restore missing image reference {}".format(image)
        return None
    if _normalized_image_id(current_id) != _normalized_image_id(staged_id):
        return "{} changed after staging; preserving it".format(image)
    if before_id is None:
        result = duthost.command(
            argv=["docker", "image", "rm", image],
            module_ignore_errors=True,
            verbose=False,
        )
        if result.get("rc", 1) != 0 or _image_id(duthost, image) is not None:
            return "unable to remove added image reference {}".format(image)
        return None
    result = duthost.command(
        argv=["docker", "tag", before_id, image],
        module_ignore_errors=True,
        verbose=False,
    )
    restored_id = _image_id(duthost, image)
    if (
        result.get("rc", 1) != 0
        or restored_id is None
        or _normalized_image_id(restored_id) != _normalized_image_id(before_id)
    ):
        return "unable to restore image reference {}".format(image)
    return None


@contextmanager
def _stage_images(duthost, creds, images):
    docker_config = "/tmp/sonic-mgmt-k8s-docker-{}".format(uuid.uuid4())
    references = {}
    logged_in = set()
    primary_error = None
    preloaded_only = duthost.facts.get("asic_type") == "vs"
    try:
        duthost.shell(
            "install -d -m 0700 {}".format(shlex.quote(docker_config)),
            module_ignore_errors=False,
            verbose=False,
        )
        for target in sorted(set(images)):
            if preloaded_only:
                target_id = _image_id(duthost, target)
                if target_id is None:
                    pytest.fail("KVM image must be preloaded: {}".format(target))
                references[target] = {"before": target_id, "staged": target_id}
                continue
            source = PAUSE_SOURCE_IMAGE if target == PAUSE_IMAGE else target
            if target not in references:
                references[target] = {"before": _image_id(duthost, target), "staged": None}
            if target == PAUSE_IMAGE and references[target]["before"] is not None:
                references[target]["staged"] = references[target]["before"]
                continue
            if source not in references:
                references[source] = {"before": _image_id(duthost, source), "staged": None}
            if source == PAUSE_SOURCE_IMAGE:
                result = _dut_docker(duthost, docker_config, ["pull", source])
                if result.get("rc", 1) != 0:
                    pytest.fail("Unable to pull {} on the DUT".format(source))
            else:
                _pull_private_image(duthost, docker_config, creds, source, logged_in)
            references[source]["staged"] = _image_id(duthost, source)
            if not references[source]["staged"]:
                pytest.fail("Pulled image is absent: {}".format(source))
            if target != source:
                result = duthost.command(
                    argv=["docker", "tag", source, target],
                    module_ignore_errors=True,
                    verbose=False,
                )
                if result.get("rc", 1) != 0:
                    pytest.fail("Unable to tag {} as {}".format(source, target))
            references[target]["staged"] = _image_id(duthost, target)
            if (
                not references[target]["staged"]
                or _normalized_image_id(references[target]["staged"])
                != _normalized_image_id(references[source]["staged"])
            ):
                pytest.fail("Staged image identity differs for {}".format(target))
        credential_cleanup = duthost.shell(
            "rm -rf -- {0} && test ! -e {0}".format(shlex.quote(docker_config)),
            module_ignore_errors=True,
            verbose=False,
        )
        if credential_cleanup.get("rc", 1) != 0:
            pytest.fail("Unable to remove temporary Docker credentials before test execution")
        yield
    except BaseException as error:
        primary_error = error
        raise
    finally:
        cleanup_errors = []
        preserve = primary_error is not None and getattr(
            primary_error, "preserve_workload_dependencies", False
        )
        if preserve:
            logger.error("Staged image references retained because workload cleanup failed")
        else:
            for image, identity in reversed(tuple(references.items())):
                try:
                    if identity["staged"] is None:
                        identity["staged"] = _image_id(duthost, image)
                    if identity["staged"] is None or identity["staged"] == identity["before"]:
                        continue
                    cleanup_error = _restore_image_reference(
                        duthost, image, identity["before"], identity["staged"]
                    )
                    if cleanup_error:
                        cleanup_errors.append(cleanup_error)
                except BaseException as error:
                    cleanup_errors.append("unable to restore {}: {}".format(image, error))
        try:
            credential_cleanup = duthost.shell(
                "rm -rf -- {0} && test ! -e {0}".format(shlex.quote(docker_config)),
                module_ignore_errors=True,
                verbose=False,
            )
            if credential_cleanup.get("rc", 1) != 0:
                cleanup_errors.append("unable to remove temporary Docker credentials")
        except BaseException as error:
            cleanup_errors.append("unable to remove temporary Docker credentials: {}".format(error))
        if cleanup_errors:
            if primary_error is not None:
                logger.error("Image staging cleanup failed: %s", "; ".join(cleanup_errors))
                existing = tuple(getattr(primary_error, "cleanup_errors", ()))
                setattr(primary_error, "cleanup_errors", existing + tuple(cleanup_errors))
                setattr(primary_error, "preserve_environment", True)
            else:
                raise ProviderCleanupError(
                    "Image staging cleanup failed: {}".format("; ".join(cleanup_errors))
                )


def _host_gnmi_identity(duthost, timeout_seconds=0):
    deadline = time.time() + timeout_seconds
    while True:
        inspection = duthost.shell("docker inspect gnmi", module_ignore_errors=True)
        supervisor = duthost.shell(
            "docker exec gnmi supervisorctl status gnmi-native",
            module_ignore_errors=True,
        )
        if inspection.get("rc", 1) == 0 and supervisor.get("rc", 1) == 0:
            try:
                container = json.loads(inspection.get("stdout", ""))[0]
                process = re.search(
                    r"gnmi-native\s+RUNNING\s+pid\s+(\d+)", supervisor.get("stdout", "")
                )
                if process is not None:
                    return container["Id"], process.group(1), container["Image"]
            except (ValueError, IndexError, KeyError, TypeError):
                pytest.fail("Existing host gNMI container inspection is invalid")
        if time.time() >= deadline:
            pytest.fail("Existing host gNMI container is not healthy")
        time.sleep(2)


@contextmanager
def _preserve_feature_state(duthost):
    directory = "/var/tmp/sonic-mgmt-gnmi-feature-{}".format(uuid.uuid4())
    script = r"""set -eu
baseline="$1"; umask 077; mkdir -m 0700 "$baseline"
for item in config:4 state:6 labels:6; do
  name=${item%%:*}; db=${item#*:}
  case "$name" in labels) key='KUBE_LABELS|SET' ;; *) key='FEATURE|gnmi' ;; esac
  redis-cli -n "$db" --json HGETALL "$key" > "$baseline/$name.json"
done
"""
    result = duthost.shell(
        "sudo sh -c {} sh {}".format(shlex.quote(script), shlex.quote(directory)),
        module_ignore_errors=True,
        verbose=False,
    )
    if result.get("rc", 1) != 0:
        pytest.fail("Unable to capture gNMI feature state")
    restore_allowed = True
    primary_error = None
    try:
        duthost.shell(
            "sudo sonic-db-cli STATE_DB HSET 'FEATURE|gnmi' remote_state ready",
            module_ignore_errors=False,
        )
        yield
    except BaseException as error:
        primary_error = error
        if getattr(error, "preserve_workload_dependencies", False):
            restore_allowed = False
            logger.error("gNMI feature baseline retained at %s because workload cleanup failed", directory)
        raise
    finally:
        if restore_allowed:
            cleanup_errors = []
            restore = r"""set -eu
baseline="$1"
for item in config:4:'FEATURE|gnmi' state:6:'FEATURE|gnmi' labels:6:'KUBE_LABELS|SET'; do
  name=${item%%:*}; rest=${item#*:}; db=${rest%%:*}; key=${rest#*:}
  redis-cli -n "$db" DEL "$key" >/dev/null
  python3 - "$db" "$key" "$baseline/$name.json" <<'PY'
import json
import subprocess
import sys

data = json.load(open(sys.argv[3]))
items = data.items() if isinstance(data, dict) else zip(data[::2], data[1::2])
arguments = []
for key, value in sorted(items):
    arguments.extend((str(key), str(value)))
if arguments:
    subprocess.check_call(["redis-cli", "-n", sys.argv[1], "HSET", sys.argv[2]] + arguments,
                          stdout=subprocess.DEVNULL)
PY
done
rm -rf -- "$baseline"
"""
            try:
                result = duthost.shell(
                    "sudo sh -c {} sh {}".format(shlex.quote(restore), shlex.quote(directory)),
                    module_ignore_errors=True,
                    verbose=False,
                )
            except BaseException as error:
                cleanup_errors.append("Unable to restore gNMI feature state: {}".format(error))
            else:
                if result.get("rc", 1) != 0:
                    cleanup_errors.append("Unable to restore gNMI feature state")
            if cleanup_errors:
                if primary_error is not None:
                    existing = tuple(getattr(primary_error, "cleanup_errors", ()))
                    setattr(primary_error, "cleanup_errors", existing + tuple(cleanup_errors))
                    setattr(primary_error, "preserve_environment", True)
                else:
                    raise ProviderCleanupError("; ".join(cleanup_errors))


@contextmanager
def _preserve_host_gnmi_files(
    duthost, ownership_id, expected_container_id, expected_image_id
):
    directory = "/var/tmp/sonic-mgmt-gnmi-{}".format(ownership_id)
    capture = r"""set -eu
umask 077
baseline="$1"
mkdir -m 0700 "$baseline"
for item in \
  gnmi-sh:/usr/local/bin/gnmi.sh \
  pod-control:/usr/share/sonic/scripts/docker-gnmi-sidecar/k8s_pod_control.sh \
  container-checker:/bin/container_checker \
  service-checker-39:/usr/local/lib/python3.9/dist-packages/health_checker/service_checker.py \
  service-checker-311:/usr/local/lib/python3.11/dist-packages/health_checker/service_checker.py \
  service-checker-313:/usr/local/lib/python3.13/dist-packages/health_checker/service_checker.py \
  gnmi-service:/lib/systemd/system/gnmi.service; do
  name=${item%%:*}; path=${item#*:}
  if [ -e "$path" ]; then
    test -f "$path" -a ! -L "$path"
    touch "$baseline/$name.present"
    cat "$path" > "$baseline/$name.bytes"
    stat -c '%a %u %g' "$path" > "$baseline/$name.meta"
  else
    touch "$baseline/$name.absent"
  fi
done
chmod 0600 "$baseline"/*
"""
    result = duthost.shell(
        "sudo sh -c {} sh {}".format(shlex.quote(capture), shlex.quote(directory)),
        module_ignore_errors=True,
        verbose=False,
    )
    if result.get("rc", 1) != 0:
        pytest.fail("Unable to capture host gNMI file baseline")
    restore_allowed = True
    primary_error = None
    try:
        yield
    except BaseException as error:
        primary_error = error
        if getattr(error, "preserve_workload_dependencies", False):
            restore_allowed = False
            logger.error("Host gNMI baseline retained at %s because workload cleanup failed", directory)
        raise
    finally:
        if restore_allowed:
            cleanup_errors = []
            restore = r"""set -eu
baseline="$1" token="$2" expected_container="$3" expected_image="$4"
systemctl stop gnmi || true
if docker inspect gnmi >/dev/null 2>&1; then
  set -- $(docker inspect gnmi | python3 -c '
import json,sys
d=json.load(sys.stdin)[0]
print(d["Id"], d["Image"], d["Name"], "io.kubernetes.pod.uid" in (d["Config"].get("Labels") or {}))
')
  if [ "$3" != /gnmi ] || [ "$4" != False ]; then
    exit 22
  fi
  if [ "$1" != "$expected_container" ] && [ "${2#sha256:}" != "${expected_image#sha256:}" ]; then
    exit 22
  fi
  docker rm --force gnmi >/dev/null
fi
for item in \
  gnmi-sh:/usr/local/bin/gnmi.sh \
  pod-control:/usr/share/sonic/scripts/docker-gnmi-sidecar/k8s_pod_control.sh \
  container-checker:/bin/container_checker \
  service-checker-39:/usr/local/lib/python3.9/dist-packages/health_checker/service_checker.py \
  service-checker-311:/usr/local/lib/python3.11/dist-packages/health_checker/service_checker.py \
  service-checker-313:/usr/local/lib/python3.13/dist-packages/health_checker/service_checker.py \
  gnmi-service:/lib/systemd/system/gnmi.service; do
  name=${item%%:*}; path=${item#*:}; tmp="${path%/*}/.$name.$token.tmp"
  if [ -f "$baseline/$name.present" ]; then
    set -- $(cat "$baseline/$name.meta")
    install -m "$1" -o "$2" -g "$3" "$baseline/$name.bytes" "$tmp"
    mv -fT "$tmp" "$path"
  else
    rm -f -- "$path"
  fi
done
systemctl daemon-reload
systemctl reset-failed gnmi
systemctl try-restart monit system-health
systemctl restart gnmi
"""
            try:
                result = duthost.shell(
                    "sudo sh -c {} sh {} {} {} {}".format(
                        shlex.quote(restore),
                        shlex.quote(directory),
                        shlex.quote(ownership_id),
                        shlex.quote(expected_container_id),
                        shlex.quote(expected_image_id),
                    ),
                    module_ignore_errors=True,
                    verbose=False,
                )
            except BaseException as error:
                cleanup_errors.append("Unable to restore host gNMI files: {}".format(error))
            else:
                if result.get("rc", 1) != 0:
                    cleanup_errors.append("Unable to restore host gNMI files and service")
                else:
                    try:
                        restored_image_id = _host_gnmi_identity(duthost, timeout_seconds=60)[2]
                        if _normalized_image_id(restored_image_id) != _normalized_image_id(expected_image_id):
                            cleanup_errors.append("Restored host gNMI uses a different image ID")
                    except BaseException as error:
                        cleanup_errors.append("Unable to verify restored host gNMI: {}".format(error))
            if not cleanup_errors:
                try:
                    result = duthost.shell(
                        "sudo rm -rf -- {}".format(shlex.quote(directory)),
                        module_ignore_errors=True,
                        verbose=False,
                    )
                    if result.get("rc", 1) != 0:
                        cleanup_errors.append("Unable to remove host gNMI file baseline")
                except BaseException as error:
                    cleanup_errors.append("Unable to remove host gNMI baseline: {}".format(error))
            if cleanup_errors:
                if primary_error is not None:
                    existing = tuple(getattr(primary_error, "cleanup_errors", ()))
                    setattr(primary_error, "cleanup_errors", existing + tuple(cleanup_errors))
                    setattr(primary_error, "preserve_environment", True)
                else:
                    raise ProviderCleanupError("; ".join(cleanup_errors))


@contextmanager
def _deployed_gnmi_workload(request, minikube_duthost, joined_minikube_dut):
    spec = load_container_spec(SPEC_PATH)
    role = _option(request, "--k8s-gnmi-role", "golden")
    images = _selected_images(request, minikube_duthost, spec)
    host_gnmi_identity = _host_gnmi_identity(joined_minikube_dut.duthost)
    ownership_id = str(uuid.uuid4())
    platform = str(joined_minikube_dut.duthost.facts.get("platform", ""))
    if not platform:
        pytest.fail("DUT platform is required for the gNMI container family")
    bundle = spec.build_bundle(
        name="gnmi-{}".format(role),
        images=images,
        runtime_values={"PLATFORM": platform},
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
        inspection = joined_minikube_dut.duthost.shell(
            "docker image inspect {}".format(shlex.quote(image)),
            module_ignore_errors=True,
        )
        if inspection.get("rc", 1) != 0:
            pytest.fail("Selected {} image is not present on the DUT".format(container_name))
        try:
            expected_image_ids[container_name] = json.loads(inspection.get("stdout", ""))[0]["Id"]
        except (ValueError, IndexError, KeyError, TypeError):
            pytest.fail("Selected {} image inspection is invalid".format(container_name))

    with _preserve_host_gnmi_files(
        joined_minikube_dut.duthost,
        ownership_id,
        host_gnmi_identity[0],
        host_gnmi_identity[2],
    ):
        with _preserve_feature_state(joined_minikube_dut.duthost):
            with deploy_workload(
                MinikubeCommandBoundary.from_joined_dut(joined_minikube_dut),
                bundle,
                "default",
                joined_minikube_dut.node_name,
                ownership_id,
            ) as workload:
                actual_image_ids = {
                    name: _runtime_image_id(joined_minikube_dut.duthost, workload.pod_uid, name)
                    for name in spec.container_names
                }
                for container_name, actual_image_id in actual_image_ids.items():
                    if _normalized_image_id(actual_image_id) != _normalized_image_id(
                        expected_image_ids[container_name]
                    ):
                        pytest.fail(
                            "Kubernetes started a different {} image ID".format(container_name)
                        )
                logger.info(
                    "Kubernetes gNMI target role=%s images=%s image_ids=%s dut=%s node=%s namespace=%s "
                    "pod=%s resource=%s",
                    role,
                    images,
                    actual_image_ids,
                    joined_minikube_dut.duthost.hostname,
                    workload.node_name,
                    workload.namespace,
                    workload.pod_name,
                    workload.resource_name,
                )
                identity = {
                    "pod_uid": workload.pod_uid,
                    "image_id": actual_image_ids["gnmi"],
                }
                setattr(joined_minikube_dut.duthost, "_kubernetes_gnmi_identity", identity)
                try:
                    yield workload
                finally:
                    if getattr(joined_minikube_dut.duthost, "_kubernetes_gnmi_identity", None) is identity:
                        delattr(joined_minikube_dut.duthost, "_kubernetes_gnmi_identity")


@pytest.fixture(scope="module")
def kubernetes_gnmi_workload(request, minikube_duthost, localhost, ptfhost):
    if _option(request, "--minikube-profile", DEFAULT_PROFILE) != DEFAULT_PROFILE:
        pytest.fail("Kubernetes gNMI image staging requires the default serialized Minikube profile")
    vmhosts = tuple(request.getfixturevalue("vmhosts") or ())
    if len(vmhosts) != 1:
        pytest.skip("Kubernetes gNMI qualification requires exactly one associated test server")
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
    with _patched_public_gnmi_runtime():
        with minikube_cluster.joined_dut(minikube_duthost) as joined:
            try:
                with _stage_images(minikube_duthost, creds, staged_images):
                    with _deployed_gnmi_workload(request, minikube_duthost, joined) as workload:
                        with _gnmi_tls_context(minikube_duthost, localhost, ptfhost):
                            yield workload
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
