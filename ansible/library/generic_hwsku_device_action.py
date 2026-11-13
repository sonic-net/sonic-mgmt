#!/usr/bin/python
"""Conditional native running/startup/alias operations for the durable Generic transaction."""

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import tempfile
import time


class DeviceActionError(ValueError):
    """A device operation or its immutable source/recovery state is invalid."""


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def read_running():
    return json.loads(subprocess.check_output(["sonic-cfggen", "-d", "--print-data"], stderr=subprocess.PIPE))


def atomic_bytes(path, value, mode=0o600):
    descriptor, temporary = tempfile.mkstemp(prefix=".generic-", dir=str(path.parent))
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, str(path))
        if os.name == "posix":
            descriptor = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def atomic_json(path, value):
    atomic_bytes(path, (json.dumps(value, sort_keys=True) + "\n").encode())


def write_result(path, value):
    destination = Path(path)
    if any(item.is_symlink() for item in [destination] + list(destination.parents)):
        raise DeviceActionError("Private readback must not traverse symlinks")
    descriptor = os.open(str(destination), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(value, handle, sort_keys=True)
        handle.flush()
        os.fsync(handle.fileno())


def startup_snapshot(path):
    if path.is_symlink():
        raise DeviceActionError("Startup symlink restoration is not supported by this profile")
    info = path.stat()
    if info.st_nlink != 1 or (os.name == "posix" and os.listxattr(str(path))):
        raise DeviceActionError("Startup hardlinks or extended metadata require an explicit restoration adapter")
    return {"bytes_base64": base64.b64encode(path.read_bytes()).decode("ascii"),
            "metadata": {"mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid, "gid": info.st_gid}}


def verify_media_sources(expected, database=None):
    if database is None:
        from sonic_py_common import multi_asic
        from swsscommon.swsscommon import SonicV2Connector

        database = SonicV2Connector(namespace=multi_asic.get_namespace_list()[0])
    database.connect("STATE_DB")
    deadline = time.monotonic() + 300
    while True:
        missing = []
        for port, fields in expected.items():
            actual = database.get_all("STATE_DB", "TRANSCEIVER_INFO|" + port) or {}
            if any(field in actual and actual[field] != value for field, value in fields.items()):
                raise DeviceActionError("Installed service transceiver changed after collection: " + port)
            if any(field not in actual for field in fields):
                missing.append(port)
        if not missing:
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DeviceActionError("Installed service transceiver evidence remains unavailable: " + ", ".join(missing))
        time.sleep(min(5, remaining))


def verify_sources(request):
    sources = request["source_sha256"]
    if not isinstance(sources, dict) or not sources:
        raise DeviceActionError("Native operations require recorded installed source hashes")
    if request.get("media_sources"):
        verify_media_sources(request["media_sources"])
    for filename, expected in sources.items():
        if hashlib.sha256(Path(filename).read_bytes()).hexdigest() != expected:
            raise DeviceActionError("Installed image/platform/parser changed after collection")


def validate_config(config, baseline):
    from sonic_yang import SonicYang

    validator = SonicYang("/usr/local/yang-models", False, False)
    validator.loadYangModel()
    validator.loadData(configdbJson=copy.deepcopy(config))
    changed = {table for table in set(config) | set(baseline) if config.get(table) != baseline.get(table)}
    if changed.intersection(validator.tablesWithOutYang):
        raise DeviceActionError("An altered ConfigDB table has no installed YANG model")
    validator.validate_data_tree()


def reload_config(path, log_path, verify_before_reload):
    deadline = time.monotonic() + 300
    messages = (
        "System is not up. Retry later or use -f to avoid system checks",
        "SwSS container is not ready. Retry later or use -f to avoid system checks",
    )
    if log_path.is_symlink() or log_path.exists() and not log_path.is_file():
        raise DeviceActionError("Native reload evidence is not an ordinary file")
    output = log_path.read_bytes() if log_path.exists() else b""
    attempt = 0
    while True:
        if attempt and time.monotonic() >= deadline:
            raise DeviceActionError("config reload readiness did not converge; private evidence: " + str(log_path))
        verify_before_reload()
        if time.monotonic() >= deadline:
            raise DeviceActionError("config reload readiness did not converge; private evidence: " + str(log_path))
        attempt += 1
        result = subprocess.run(["config", "reload", "-y", str(path)], stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, check=False)
        output += "\nReload attempt {}\n".format(attempt).encode() + result.stdout
        atomic_bytes(log_path, output)
        if result.returncode == 0:
            return
        lines = [line.strip() for line in result.stdout.decode("utf-8", "replace").splitlines() if line.strip()]
        rejected = result.returncode == 1 and any(
            lines == [message] or lines == [
                "Acquired lock on /etc/sonic/reload.lock", message, "Released lock on /etc/sonic/reload.lock"]
            for message in messages)
        if not rejected:
            raise DeviceActionError("config reload failed with rc {}; private evidence: {}".format(
                result.returncode, log_path))
        verify_before_reload()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DeviceActionError("config reload readiness did not converge; private evidence: " + str(log_path))
        time.sleep(min(5, remaining))


def stage(request, directory, startup):
    verify_sources(request)
    record = directory / "request.json"
    if record.exists():
        if json.loads(record.read_text()) != request:
            raise DeviceActionError("An existing device stage belongs to different immutable inputs")
        return
    baseline = request["baseline"]
    if digest(read_running()) != digest(baseline["running"]):
        raise DeviceActionError("Running ConfigDB changed after collection")
    if startup_snapshot(startup) != baseline["startup"]:
        raise DeviceActionError("Startup ConfigDB changed after collection")
    for candidate in request["candidates"].values():
        validate_config(candidate, baseline["running"])
    atomic_json(record, request)


def alias_path(request, name, device_root):
    metadata = request["baseline"]["running"]["DEVICE_METADATA"]["localhost"]
    for value in (metadata["platform"], metadata["hwsku"], name):
        if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9_.-]+", value) is None or value in (".", ".."):
            raise DeviceActionError("Invalid platform/HWSKU path")
    platform = device_root / metadata["platform"]
    source = platform / metadata["hwsku"]
    if not source.is_dir():
        raise DeviceActionError("The verified base HWSKU assets are absent")
    return platform / name, source.resolve(strict=True)


def alias_snapshot(request, name, device_root):
    path, source = alias_path(request, name, device_root)
    if not path.exists() and not path.is_symlink():
        return None
    if not path.is_symlink():
        return {"name": name, "conflict": "not-a-symlink"}
    return {"name": name, "target": str(path.resolve(strict=False))}


def capture(kind, request, startup, device_root, alias_name=None):
    if kind == "running":
        return read_running()
    if kind == "startup":
        return startup_snapshot(startup)
    if kind == "alias":
        return alias_snapshot(request, alias_name, device_root)
    raise DeviceActionError("Unknown device resource kind")


def perform(kind, before, after, operation_id, request, directory, startup, device_root, alias_name=None):
    """Change one declared resource only, with compare-before-write and native ownership receipts."""
    verify_sources(request)
    current = capture(kind, request, startup, device_root, alias_name)
    if current != before:
        raise DeviceActionError("Unexplained {} drift blocks the conditional device write".format(kind))
    intent = {"operation_id": operation_id, "kind": kind, "before": before, "after": after}
    details = {}
    try:
        if kind == "running":
            validate_config(after, request["baseline"]["running"])
            config_path = directory / "candidate-running.json"
            atomic_json(config_path, after)
            original_startup = startup_snapshot(startup)
            reload_log = directory / ("reload-" + digest(operation_id) + ".log")
            details["reload_log"] = str(reload_log)
            atomic_json(directory / (kind + "-intent.json"), intent)

            def verify_before_reload():
                verify_sources(request)
                if read_running() != before or startup_snapshot(startup) != original_startup:
                    raise DeviceActionError("Running or startup drift blocks native reload readiness retry")

            reload_config(config_path, reload_log, verify_before_reload)
            if startup_snapshot(startup) != original_startup:
                raise DeviceActionError("Installed config reload changed an undeclared startup resource")
        elif kind == "startup":
            if (not isinstance(after, dict) or set(after) != {"bytes_base64", "metadata"}
                    or set(after["metadata"]) != {"mode", "uid", "gid"}):
                raise DeviceActionError("Startup operations require exact bytes and mode/uid/gid")
            data = base64.b64decode(after["bytes_base64"], validate=True)
            atomic_json(directory / (kind + "-intent.json"), intent)
            atomic_bytes(startup, data)
            os.chown(str(startup), after["metadata"]["uid"], after["metadata"]["gid"])
            os.chmod(str(startup), after["metadata"]["mode"])
        elif kind == "alias":
            path, source = alias_path(request, alias_name, device_root)
            if after is not None and after != {"name": alias_name, "target": str(source)}:
                raise DeviceActionError("Only a verified base-HWSKU alias is permitted")
            if after is None:
                for config in (read_running(), json.loads(startup.read_bytes())):
                    if config["DEVICE_METADATA"]["localhost"]["hwsku"] == alias_name:
                        raise DeviceActionError("Running/startup configuration still references the created alias")
                receipt_path = directory / "created-alias.json"
                if not receipt_path.is_file():
                    raise DeviceActionError("Alias ownership receipt is missing; retain it for reconciliation")
                owned = json.loads(receipt_path.read_text())
                info = path.lstat()
                if (not path.is_symlink() or info.st_ino != owned["inode"] or info.st_dev != owned["device"]):
                    raise DeviceActionError("Alias ownership changed; refusing another owner's path")
            atomic_json(directory / (kind + "-intent.json"), intent)
            if after is None:
                path.unlink()
            else:
                staging = Path(tempfile.mkdtemp(prefix=".sonic-generic-alias-", dir=str(path.parent)))
                # Private directories require owner traversal, not group/world access.
                os.chmod(str(staging), 0o700)  # nosemgrep: insecure-file-permissions
                staged = staging / "alias"
                os.symlink(str(source), str(staged))
                info = staged.lstat()
                atomic_json(directory / "created-alias.json", {
                    "name": alias_name, "inode": info.st_ino, "device": info.st_dev,
                    "operation_id": operation_id, "staging": str(staging)})
                os.link(str(staged), str(path), follow_symlinks=False)
                staged.unlink()
                staging.rmdir()
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        receipt = dict(details, operation_id=operation_id, completed=False,
                       error_type=type(error).__name__, error=str(error))
        try:
            receipt["observed_sha256"] = digest(capture(kind, request, startup, device_root, alias_name))
        except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.CalledProcessError) as capture_error:
            receipt["capture_error"] = str(capture_error)
        try:
            atomic_json(directory / (kind + "-" + digest(operation_id) + "-receipt.json"), receipt)
            atomic_json(directory / (kind + "-receipt.json"), receipt)
        except OSError as receipt_error:
            raise DeviceActionError("{}; native failure receipt could not be saved: {}".format(
                error, receipt_error)) from error
        raise
    actual = capture(kind, request, startup, device_root, alias_name)
    receipt = dict(details, operation_id=operation_id, observed_sha256=digest(actual), completed=actual == after)
    if actual != after:
        receipt["error"] = "Native command completed but independent readback differs"
    atomic_json(directory / (kind + "-" + digest(operation_id) + "-receipt.json"), receipt)
    atomic_json(directory / (kind + "-receipt.json"), receipt)
    if actual != after:
        raise DeviceActionError("The native write did not converge to its declared resource state")


def validate_identity(scenario, device):
    if (not isinstance(scenario, str) or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", scenario) is None
            or not isinstance(device, str) or re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", device) is None
            or device in (".", "..")):
        raise DeviceActionError("Invalid scenario/device directory identity")


def main():
    import fcntl
    from ansible.module_utils.basic import AnsibleModule

    module = AnsibleModule(argument_spec={
        "action": {"type": "str", "choices": ["stage", "perform", "capture"], "required": True},
        "scenario": {"type": "str", "required": True}, "device": {"type": "str", "required": True},
        "request": {"type": "dict", "no_log": True},
        "kind": {"type": "str", "choices": ["running", "startup", "alias"], "default": "running"},
        "before": {"type": "raw", "no_log": True}, "after": {"type": "raw", "no_log": True},
        "operation_id": {"type": "str"}, "alias_name": {"type": "str"},
        "destination": {"type": "path", "required": True},
    })
    error_directory = None
    try:
        if socket.gethostname().lower() != module.params["device"].lower():
            raise DeviceActionError("Actual device identity differs from the requested action target")
        validate_identity(module.params["scenario"], module.params["device"])
        root = Path("/var/lib/sonic-generic")
        directory = root / module.params["scenario"] / module.params["device"]
        if any(path.is_symlink() for path in [directory] + list(directory.parents)):
            raise DeviceActionError("A device recovery path must not traverse symlinks")
        for path in (root, directory.parent, directory):
            path.mkdir(mode=0o700, exist_ok=True)
            # Private directories require owner traversal, not group/world access.
            os.chmod(str(path), 0o700)  # nosemgrep: insecure-file-permissions
        startup, device_root = Path("/etc/sonic/config_db.json"), Path("/usr/share/sonic/device")
        with open(str(root / ".action.lock"), "a") as lock:
            os.chmod(str(root / ".action.lock"), 0o600)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            error_directory = directory
            if module.params["action"] == "stage":
                stage(module.params["request"], directory, startup)
            request = json.loads((directory / "request.json").read_text())
            verify_sources(request)
            if module.params["action"] == "perform":
                operation = module.params["operation_id"]
                if not isinstance(operation, str) or not operation.startswith(module.params["scenario"] + ":"):
                    raise DeviceActionError("Operation identity does not belong to this scenario")
                perform(module.params["kind"], module.params["before"], module.params["after"], operation,
                        request, directory, startup, device_root, module.params["alias_name"])
            value = capture(module.params["kind"], request, startup, device_root, module.params["alias_name"])
            receipt_path = directory / (module.params["kind"] + "-receipt.json")
            ownership = None
            if receipt_path.is_file():
                receipt = json.loads(receipt_path.read_text())
                if receipt.get("observed_sha256") == digest(value):
                    ownership = receipt["operation_id"]
            write_result(module.params["destination"], {"value": value, "owned_by": ownership})
            module.exit_json(changed=module.params["action"] == "perform", artifact_written=True)
    except (OSError, ValueError, KeyError, TypeError, ImportError,
            RuntimeError, subprocess.CalledProcessError) as error:
        message = "Generic device action failed; recovery artifacts retained: {}".format(error)
        if error_directory is not None:
            failure = {key: module.params.get(key) for key in ("action", "kind", "operation_id")}
            identity = digest(dict(failure, destination=module.params["destination"]))
            failure.update(error_type=type(error).__name__, error=str(error))
            try:
                atomic_json(error_directory / ("failure-" + identity + ".json"), failure)
            except OSError as receipt_error:
                message += "; native failure receipt could not be saved: " + str(receipt_error)
        module.fail_json(msg=message)


if __name__ == "__main__":
    main()
