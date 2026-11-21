"""Run on the DUT. Give the systemd-managed hft container a temporary Docker CMD."""

import fcntl
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from contextvars import ContextVar
from pathlib import Path

SERVICE = "hft"
OWNER_LABEL = "sonic-mgmt.hft-test"
DEVICE_DIR = Path("/usr/share/sonic/device")
ACTIVE = Path("/var/lib/sonic-mgmt-hft")
LEGACY_LOCK = Path("/run/lock/sonic-mgmt-hft")
OTEL_CONFIG = Path("/etc/sonic/otel_config.yml")
OTEL_LABEL = "sonic-mgmt.otel-test"
CREATED_OTEL_FIELDS = {"state": "enabled", "auto_restart": "enabled", "has_global_scope": "True",
                       "has_per_asic_scope": "False"}
UNIT_POLICIES = {"disabled", "enabled", "enabled-runtime", "masked", "masked-runtime"}
FENCE_FDS = ContextVar("hft_fence_fds", default=())


def command(*args):
    # A killed helper must not release its lock while its CLI child is still
    # changing Docker, Redis or systemd. The last copy of the descriptor releases flock.
    return subprocess.check_output(args, text=True, pass_fds=FENCE_FDS.get()).strip()


def wait_for_service_jobs():
    # Even killing systemctl cannot cancel an already queued systemd job.
    deadline = time.monotonic() + 120
    while command("systemctl", "list-jobs", "--no-pager", "--no-legend", "--plain", "hft.service", "otel.service"):
        if time.monotonic() >= deadline:
            raise RuntimeError("Outstanding HFT/OTEL systemd job; retain the journal and retry recovery")
        time.sleep(1)


def lookup(client, name):
    from docker.errors import NotFound

    try:
        return client.containers.get(name)
    except NotFound:
        return None


def feature_state():
    return command("sonic-db-cli", "CONFIG_DB", "HGET", "FEATURE|hft", "state")


def check_hwsku(container):
    # hft.sh removes an existing container instead of starting it if this mount
    # differs. Never present it with a candidate (or original) it would delete.
    platform = command("sonic-cfggen", "-H", "-v", "DEVICE_METADATA.localhost.platform")
    sku = command("sonic-cfggen", "-d", "-v", 'DEVICE_METADATA["localhost"]["hwsku"]')
    mounts = [Path(m["Source"]) for m in container.attrs["Mounts"] if m["Destination"] == "/usr/share/sonic/hwsku"]
    if not platform or not sku or mounts != [DEVICE_DIR / platform / sku]:
        raise RuntimeError(f"Refusing to restart {container.name}: its HwSKU mount does not match the DUT")


def check_source(container):
    if OWNER_LABEL in container.labels or container.attrs["HostConfig"]["AutoRemove"]:
        raise RuntimeError("Refusing to replace a test-owned or auto-remove hft container")
    if container.status not in ("running", "exited", "created"):
        raise RuntimeError("HFT is not in a stable state")
    check_hwsku(container)


def start_service():
    try:
        command("systemctl", "start", "hft.service")
    except subprocess.CalledProcessError:
        # Two test modules can legitimately hit the unit's limit of three starts.
        if command("systemctl", "show", "hft.service", "-p", "Result", "--value") != "start-limit-hit":
            raise
        command("systemctl", "reset-failed", "hft.service")
        command("systemctl", "start", "hft.service")


def unit_policy(service):
    return command("systemctl", "show", service + ".service", "-p", "UnitFileState", "--value")


def require_restartable(service):
    if unit_policy(service) in ("masked", "masked-runtime"):
        raise RuntimeError(f"Enabled {service} unit is masked; refusing to interrupt its running container")


def disabled_policy(service):
    policy = unit_policy(service)
    if policy not in UNIT_POLICIES:
        raise RuntimeError(f"Cannot restore non-standard {service} UnitFileState {policy!r}")
    return policy


def restore_disabled_policy(service, original, *, allow_missing=False, enabled_by_test=False):
    # featured may finish a normal disable asynchronously, or cache 'disabled'
    # after a failed first start. Its reported failure is not ours to overwrite.
    deadline = time.monotonic() + 60
    unit, key = service + ".service", "FEATURE|" + service
    while time.monotonic() < deadline:
        configured = command("sonic-db-cli", "CONFIG_DB", "HGET", key, "state")
        missing = allow_missing and not configured
        if configured != "disabled" and not missing:
            raise RuntimeError(f"{service} feature changed during unit recovery")
        reported = command("sonic-db-cli", "STATE_DB", "HGET", key, "state")
        active = command("systemctl", "show", unit, "-p", "ActiveState", "--value")
        settled = missing or reported in ("", "disabled", "failed")
        if enabled_by_test and original != "masked" and not missing:
            # featured publishes 'disabled' *after* its asynchronous stop/disable/mask.
            # A stale 'failed' from startup is not an acknowledgement: a late persistent
            # mask would overwrite a restored non-default policy. Keep the journal on timeout.
            settled = reported == "disabled"
        if settled and active in ("inactive", "failed"):
            break
        time.sleep(1)
    else:
        raise RuntimeError(f"{service} did not settle after disable; keeping recovery record")

    # Remove the currently effective policy at *its* level, then apply the
    # saved policy at the original level. Unmasking /etc may uncover a /run mask.
    for _ in range(8):
        current = unit_policy(service)
        if current == original:
            return
        if current not in UNIT_POLICIES or original not in UNIT_POLICIES:
            break
        if current != "disabled":
            flags = ["--runtime"] if current.endswith("-runtime") else []
            action = "unmask" if current.startswith("masked") else "disable"
        else:
            flags = ["--runtime"] if original.endswith("-runtime") else []
            action = "mask" if original.startswith("masked") else "enable"
        command("systemctl", *flags, action, unit)
    raise RuntimeError(f"{unit} UnitFileState is {unit_policy(service)!r}, expected {original!r}; keeping journal")


def stop_owned(container, token, label=OWNER_LABEL):
    container.reload()
    if container.labels.get(label) != token:
        raise RuntimeError("Refusing to stop a container without this run's owner label")
    stop_by_id(container)


def stop_by_id(container):
    """The caller must have verified the immutable ID or this run's owner label."""
    container.reload()
    if container.attrs["State"].get("Paused"):
        container.unpause()
    if container.attrs["State"]["Running"]:
        container.stop(timeout=10)  # By immutable ID, even if the systemd unit is already inactive.
    container.reload()
    if container.status not in ("created", "exited"):
        raise RuntimeError(f"Test container {container.id} has not stopped: {container.status}")


def stop_service(container):
    command("systemctl", "stop", "hft.service")
    if container is not None:
        container.reload()
        if container.attrs["State"]["Running"]:
            raise RuntimeError("hft is still running after systemctl stop")


def stop_owned_unit(service):
    unit = service + ".service"
    try:
        command("systemctl", "stop", unit)
    except subprocess.CalledProcessError:
        if command("systemctl", "show", unit, "-p", "ActiveState", "--value") not in ("inactive", "failed"):
            raise


def wait_for_feature(client):
    for _ in range(60):
        container = lookup(client, SERVICE)
        if container and container.status == "running":
            return container
        if command("systemctl", "show", "hft.service", "-p", "Result", "--value") == "start-limit-hit":
            start_service()
        time.sleep(1)
    raise RuntimeError("Timed out waiting for SONiC to enable hft")


def create_with_args(client, source, name, args):
    """Equivalent to docker create <the platform's run options> <image> <args>."""
    config = source.attrs["Config"].copy()
    host = source.attrs["HostConfig"]
    # The standalone, local HFT service uses host networking and bind mounts.
    # Do not silently detach a custom installation from its network or volumes.
    if host["NetworkMode"] != "host" or any(mount["Type"] == "volume" for mount in source.attrs["Mounts"]):
        raise RuntimeError("Cannot temporarily replace this non-standard hft container")
    config.update(Image=source.attrs["Image"], HostConfig=host, Cmd=args,
                  Labels={**(config.get("Labels") or {}), OWNER_LABEL: name})
    # inspect reports an inherited hostname; Docker rejects setting one with --uts=host.
    if host["UTSMode"] == "host":
        config.pop("Hostname", None)
    cid = client.api.create_container_from_config(config, name=name)["Id"]
    return client.containers.get(cid)


def with_otel_args(original, overrides):
    """Replace only OTEL's flag (-o) and endpoint, preserving all other Docker CMD tokens."""
    keep = []
    tokens = iter(original or ())
    for token in tokens:
        if token in ("--enable-otel", "-o") or token.startswith(("--enable-otel=", "--otel-endpoint=")):
            continue
        if token == "--otel-endpoint":
            value = next(tokens, None)
            if not value or value.startswith("-"):
                raise RuntimeError("Cannot merge an incomplete --otel-endpoint in the original hft command")
            continue
        if token == "--" or (token.startswith("-") and not token.startswith("--") and len(token) > 2):
            raise RuntimeError("Cannot safely merge positional or clustered short options in the original hft command")
        keep.append(token)
    return keep + list(overrides)


def create_from_launcher(client, work, service, label, args):
    cid = command("bash", str(work / "create_container.sh"), service, label + "=" + work.name,
                  f"/usr/bin/{service}.sh", *args)
    candidate = client.containers.get(cid)
    if candidate.name != service or candidate.labels.get(label) != work.name:
        raise RuntimeError(f"Platform launcher did not create the requested {service} test container")
    check_hwsku(candidate)
    return candidate


def save(path, data):
    """Publish the complete recovery record before the operation it describes."""
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as tmp:
        json.dump(data, tmp)
        tmp.flush()
        os.fsync(tmp.fileno())
    os.replace(tmp.name, path)
    sync_directory(path.parent)


def sync_directory(directory):
    fd = os.open(directory, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def install(client, work, state, args):
    original = lookup(client, SERVICE)
    owner = command("sonic-db-cli", "CONFIG_DB", "HGET", "FEATURE|hft", "set_owner")
    if owner not in ("", "local") or state != feature_state():
        raise RuntimeError("HFT ownership or feature state changed before setup")
    if (original is not None and original.status == "running") != (state != "disabled"):
        raise RuntimeError("HFT container and feature state disagree before setup")
    if original:
        check_source(original)
        if state != "disabled":
            require_restartable(SERVICE)
        args = with_otel_args(original.attrs["Config"].get("Cmd"), args)

    # Write recovery information before the first change. Keep the *actual* original
    # container (including its writable layer) until its name and state are restored.
    record = work / "before.json"
    if record.exists():
        raise RuntimeError("HFT install already attempted; recover this run first")
    policy = disabled_policy(SERVICE) if state == "disabled" else None
    before = {"state": state, "original": original.id if original else None, "unit_policy": policy,
              "enable_armed": False}
    save(record, before)
    if original is None:
        # Label at Docker create, before SONiC is allowed to start the feature. An
        # interrupted/failed bootstrap never requires adopting an unlabelled hft.
        candidate = create_from_launcher(client, work, SERVICE, OWNER_LABEL, args)
    else:
        candidate = create_with_args(client, original, work.name, args)
    before["candidate"] = candidate.id
    save(record, before)
    if original is not None:
        stop_service(original)
        original.rename(work.name + "-original")
        candidate.rename(SERVICE)
    if state == "disabled":
        before["enable_armed"] = True
        save(record, before)
        try:
            change_feature_state(SERVICE, "disabled", "enabled")
        except FeatureConflict:
            before["enable_armed"] = False  # Redis confirmed that no write took place.
            save(record, before)
            raise
        wait_for_feature(client)
    else:
        start_service()
    running = client.containers.get(SERVICE)
    if running.id != candidate.id or running.attrs["Config"]["Cmd"] != args:
        raise RuntimeError("SONiC did not start the hft container with the requested Docker CMD")


def restart_countersyncd(client, work):
    candidate_id = json.loads((work / "before.json").read_text()).get("candidate")
    current = lookup(client, SERVICE)
    if (not current or current.id != candidate_id or current.labels.get(OWNER_LABEL) != work.name or
            current.status != "running" or feature_state() not in ("enabled", "always_enabled") or
            command("sonic-db-cli", "CONFIG_DB", "HGET", "FEATURE|hft", "set_owner") not in ("", "local")):
        raise RuntimeError("Refusing to restart countersyncd outside this run's HFT container")

    def pid():
        value = command("docker", "exec", candidate_id, "supervisorctl", "pid", "countersyncd")
        return int(value) if value.isdecimal() else 0

    old = pid()
    if not old:
        raise RuntimeError("countersyncd was not running before restart")
    command("docker", "exec", candidate_id, "supervisorctl", "restart", "countersyncd")
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        new = pid()
        if new and new != old:
            return old, new
        time.sleep(1)
    raise RuntimeError(f"countersyncd did not restart from PID {old}")


def restore(client, work):
    record = work / "before.json"
    if not record.exists():  # Setup rejected the initial state without changing the DUT.
        return None
    before = json.loads(record.read_text())
    if command("sonic-db-cli", "CONFIG_DB", "HGET", "FEATURE|hft", "set_owner") not in ("", "local"):
        raise RuntimeError("HFT is no longer locally managed; keeping recovery record")
    state = feature_state()
    if state != before["state"] and not (before["enable_armed"] and state == "enabled"):
        raise RuntimeError("HFT feature state changed outside the transaction; keeping recovery record")
    source_id = before["original"]
    current = lookup(client, SERVICE)
    test_owns_current = current is not None and current.labels.get(OWNER_LABEL) == work.name
    if current and current.id != source_id and not test_owns_current:
        raise RuntimeError("Unexpected hft container; refusing to stop or remove it")
    source = lookup(client, source_id) if source_id else None
    if source_id and (not source or source.name not in (SERVICE, work.name + "-original")):
        raise RuntimeError("Original hft is missing or has an unexpected name; keeping recovery record")
    if test_owns_current:
        # Under warm restart the unit's ExecStop uses 'container kill', which
        # requires the feature still to be enabled. Stop and verify before disabling.
        stop_owned_unit(SERVICE)
    candidates = client.containers.list(all=True, filters={"label": OWNER_LABEL + "=" + work.name})
    for candidate in candidates:
        stop_owned(candidate, work.name)
    if before["enable_armed"] and state == "enabled":
        change_feature_state(SERVICE, "enabled", "disabled")

    for candidate in candidates:
        candidate.remove()  # Never force-remove a running container.
    if source and source.name != SERVICE:
        source.rename(SERVICE)
    if before["state"] == "disabled":
        restore_disabled_policy(SERVICE, before["unit_policy"], enabled_by_test=before["enable_armed"])
    else:
        check_hwsku(source)
        start_service()
        if client.containers.get(SERVICE).id != before["original"]:
            raise RuntimeError("Failed to restore the original hft container")
    return before["state"]


def points_to(link, work):
    return link.is_symlink() and os.readlink(link) == str(work)


def check_otel(client, work, snapshot):
    if command("sonic-db-cli", "CONFIG_DB", "HGET", "FEATURE|otel", "set_owner") not in ("", "local"):
        raise RuntimeError("OTEL is not locally managed; keeping recovery record")
    current = lookup(client, "otel")
    original = snapshot["container_id"]
    if original:
        if (not current or current.id != original or OTEL_LABEL in current.labels or
                current.attrs["HostConfig"]["AutoRemove"]):
            raise RuntimeError("Original otel container changed; refusing recovery")
        check_hwsku(current)
    elif current and current.labels.get(OTEL_LABEL) != work.name:
        raise RuntimeError("Unexpected otel container; refusing to stop or remove it")
    return current


def otel_fields():
    return json.loads(command("redis-cli", "-n", "4", "--json", "HGETALL", "FEATURE|otel"))


def check_otel_fields(snapshot, current, armed):
    """Only state is test-written on an existing row; all other fields belong to the DUT."""
    original = snapshot["original_feature"]
    if current.get("set_owner", "local") not in ("", "local"):
        raise FeatureConflict("OTEL is no longer locally managed")
    if original:
        allowed = {original.get("state")}
        if armed and snapshot["original_state"] == "disabled":
            allowed.update(("enabled", "disabled"))
        if current and current.get("state") in allowed:
            return
    elif not current or (armed and current.get("state") in ("enabled", "disabled") and
                         current == {**CREATED_OTEL_FIELDS, "state": current["state"]}):
        return
    raise RuntimeError("FEATURE|otel changed outside the HFT transaction; preserving it")


def enable_otel(client, work, snapshot):
    current = otel_fields()
    check_otel_fields(snapshot, current, False)
    save(work / "otel-enable.json", True)  # before changing the feature
    try:
        if snapshot["original_feature"]:
            change_feature_state("otel", snapshot["original_feature"].get("state"), "enabled")
        else:
            fields = [v for field in CREATED_OTEL_FIELDS.items() for v in field]
            result = command("redis-cli", "-n", "4", "--raw", "EVAL",
                             "if redis.call('EXISTS',KEYS[1]) ~= 0 then return 0 end; "
                             "redis.call('HSET',KEYS[1],unpack(ARGV)); return 1", "1", "FEATURE|otel", *fields)
            if result == "0":
                raise FeatureConflict("FEATURE|otel appeared during setup; refusing to replace it")
            if result != "1":
                raise RuntimeError(f"Unexpected Redis result enabling OTEL: {result!r}")
    except FeatureConflict:
        (work / "otel-enable.json").unlink()
        sync_directory(work)
        raise
    wait_otel(client, work, snapshot, lambda c: c is not None and c.status == "running", "start")


def wait_otel(client, work, snapshot, predicate, description):
    deadline = time.monotonic() + 60
    while True:
        current = check_otel(client, work, snapshot)
        if predicate(current):
            return current
        if time.monotonic() >= deadline:
            raise RuntimeError(f"Timed out waiting for OTEL to {description}")
        time.sleep(1)


def collector_running(container):
    rc, output = container.exec_run(["supervisorctl", "status", "otel"])
    return rc == 0 and output.split()[:2] == [b"otel", b"RUNNING"]


def stop_collector(container):
    rc, output = container.exec_run(["supervisorctl", "stop", "otel"])
    if rc and b"not running" not in output.lower():
        raise RuntimeError(f"Could not stop the original OTEL collector: {output!r}")


class FeatureConflict(RuntimeError):
    """The owner, state or test-created row no longer matches the intended write."""


def change_feature_state(service, expected_state, restore_state, *, created=False):
    # For a temporary hash, compare *all* fields before either writing or deleting.
    # For an existing hash, compare state and local ownership in the same Redis
    # operation and leave every other field (including later operator edits) alone.
    expected = {"state": expected_state} if expected_state is not None else {}
    if created:
        expected = {**CREATED_OTEL_FIELDS, **expected}
    fields = [v for item in expected.items() for v in item]
    script = """
        local row = ARGV[1] == 'row'
        local owner = redis.call('HGET', KEYS[1], 'set_owner')
        if owner and owner ~= '' and owner ~= 'local' then return 0 end
        if ARGV[1] == 'missing-state' and
           (redis.call('EXISTS',KEYS[1]) == 0 or redis.call('HEXISTS',KEYS[1],'state') ~= 0) then return 0 end
        if row and redis.call('HLEN', KEYS[1]) ~= (#ARGV - 2) / 2 then return 0 end
        for i = 3, #ARGV, 2 do
            if redis.call('HGET', KEYS[1], ARGV[i]) ~= ARGV[i+1] then return 0 end
        end
        if ARGV[2] ~= '' then redis.call('HSET', KEYS[1], 'state', ARGV[2])
        elseif row then redis.call('DEL', KEYS[1])
        else redis.call('HDEL', KEYS[1], 'state') end
        return 1
    """
    mode = "row" if created else "missing-state" if expected_state is None else "state"
    result = command("redis-cli", "-n", "4", "--raw", "EVAL", script, "1", "FEATURE|" + service,
                     mode, restore_state or "", *fields)
    if result == "0":
        raise FeatureConflict(f"{service} owner or feature state changed; keeping recovery record")
    if result != "1":
        raise RuntimeError(f"Unexpected Redis result changing {service}: {result!r}")


def restore_otel(client, work, snapshot):
    current = check_otel(client, work, snapshot)
    armed = (work / "otel-enable.json").exists()
    fields = otel_fields()
    check_otel_fields(snapshot, fields, armed)
    if (work / "collector-target.json").exists():
        try:
            install_collector_config(work, None)
        except CollectorConfigChanged:
            # A later operator file is authoritative. Preserve it and recover
            # service liveness independently of whether we can restore the file.
            pass
    if snapshot["original_state"] == "disabled":
        if current:
            # Also covers a pre-existing, originally stopped container left running
            # with an inactive unit. check_otel verified its exact ID (or run label).
            stop_owned_unit("otel")
            stop_by_id(current)
        if armed and fields.get("state") == "enabled":
            change_feature_state("otel", "enabled", "disabled", created=not snapshot["original_feature"])
        current = wait_otel(client, work, snapshot, lambda c: c is None or c.status in ("created", "exited"), "stop")
        # Let featured act on 'disabled' before removing a temporary row; once
        # the row is gone it can no longer reconcile the unit's boot policy.
        restore_disabled_policy("otel", snapshot["unit_policy"],
                                allow_missing="state" not in snapshot["original_feature"], enabled_by_test=armed)
        fields = otel_fields()
        check_otel_fields(snapshot, fields, armed)
        if armed and fields and not snapshot["original_feature"]:
            change_feature_state("otel", "disabled", None, created=True)
        elif armed and "state" not in snapshot["original_feature"] and fields.get("state") == "disabled":
            change_feature_state("otel", "disabled", None)
        if current and snapshot["container_id"] is None:
            current.remove()  # The tagged test container has positively stopped.
    elif snapshot["original_collector_running"]:
        if (not (work / "collector-activity.json").exists() and
                current.status == "running" and collector_running(current)):
            return  # We did not stop or restart this original process.
        require_restartable("otel")
        command("systemctl", "reset-failed", "otel.service")
        command("systemctl", "restart", "otel.service")
        # The operator's valid original collector may have no gRPC :4317 receiver.
        wait_otel(client, work, snapshot, lambda c: c.status == "running" and collector_running(c), "restore collector")
    else:
        if current.status != "running":
            command("systemctl", "start", "otel.service")
            current = wait_otel(client, work, snapshot, lambda c: c.status == "running", "start")
        stop_collector(current)


def config_digest(data):
    return hashlib.sha256(data).hexdigest()


class CollectorConfigChanged(RuntimeError):
    """The installed OTEL file is no longer the file we are allowed to replace."""


def file_identity(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_nlink, st.st_ctime_ns, st.st_mtime_ns)


def collector_file():
    try:
        st = OTEL_CONFIG.lstat()
    except FileNotFoundError:
        return None, None
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        raise CollectorConfigChanged(f"Refusing to replace managed {OTEL_CONFIG}")

    def open_file(name, flags):
        return os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK)

    with open(OTEL_CONFIG, "rb", opener=open_file) as stream:
        if file_identity(os.fstat(stream.fileno())) != file_identity(st):
            raise CollectorConfigChanged("OTEL config identity changed while opening it")
        data = stream.read()
        if file_identity(os.fstat(stream.fileno())) != file_identity(st):
            raise CollectorConfigChanged("OTEL config changed while reading it")
    return st, data


def check_service_config(work):
    """A rejected installation must never stop/restart the original collector."""
    _, data = collector_file()
    target = work / "collector-target.json"
    if not target.exists() or data is None or config_digest(data) != json.loads(target.read_text()):
        raise CollectorConfigChanged("OTEL config is not this case's installed test configuration")


def install_collector_config(work, owner, before_replace=None):
    """Publish the allowed content digest and atomically install it under the owner fence."""
    st, current = collector_file()
    original, original_mode = json.loads((work / "otel.json").read_text())["otel_config"]
    if st and stat.S_IMODE(st.st_mode) != (int(original_mode, 8) if original_mode else 0o644):
        raise CollectorConfigChanged("OTEL config permissions changed outside the HFT transaction")
    if current != (original.encode() if original is not None else None):
        if current is None or not (work / ("config-" + config_digest(current))).exists():
            raise CollectorConfigChanged("OTEL config was changed outside this transaction")

    def revalidate_file():
        latest, contents = collector_file()
        if (contents != current or (latest is None) != (st is None) or
                (latest and file_identity(latest) != file_identity(st))):
            raise CollectorConfigChanged("OTEL config changed before publication")

    stage = OTEL_CONFIG.parent / ("." + work.name + ".otel.tmp")
    if owner is None:
        stage.unlink(missing_ok=True)
        if original is None:
            revalidate_file()
            OTEL_CONFIG.unlink(missing_ok=True)
            return
        data, mode = original.encode(), int(original_mode, 8)
        if current == data and st and stat.S_IMODE(st.st_mode) == mode:
            return
    else:
        pending = work / ("config." + owner)
        data = pending.read_bytes()
        mode = stat.S_IMODE(st.st_mode) if st else 0o644
        save(work / ("config-" + config_digest(data)), True)
        save(work / "collector-target.json", config_digest(data))  # write ahead of rename
    fd = os.open(stage, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as tmp:
            tmp.write(data)
            if st:
                os.fchown(tmp.fileno(), st.st_uid, st.st_gid)
            os.fchmod(tmp.fileno(), mode)
            tmp.flush()
            os.fsync(tmp.fileno())
        if before_replace is not None:
            before_replace()
        revalidate_file()
        os.replace(stage, OTEL_CONFIG)
        sync_directory(OTEL_CONFIG.parent)
    finally:
        stage.unlink(missing_ok=True)
    if owner is not None:
        pending.unlink()


def transaction(action, work, owner, args):
    """Fence delayed DUT commands from a dead controller and serialize recovery handoffs."""
    if work.parent != ACTIVE.parent or not work.name.startswith("sonic-mgmt-hft-"):
        raise ValueError(f"Not an HFT transaction directory: {work}")
    fd = os.open(work, os.O_DIRECTORY | os.O_NOFOLLOW)
    fence = FENCE_FDS.set((fd,))
    try:
        deadline = time.monotonic() + 120
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise RuntimeError(f"HFT helper is still busy in {work}; retain the journal and retry")
                time.sleep(0.25)
        path = work / "owner.json"
        if action == "claim":
            if path.exists():
                if (json.loads(path.read_text())["id"] == owner and points_to(ACTIVE, work)
                        and points_to(LEGACY_LOCK, work)):
                    return
                raise RuntimeError("HFT claim already attempted; refusing to overwrite its owner")
            save(path, {"version": 6, "id": owner, "controller": args[0]})
            try:
                ACTIVE.symlink_to(work)
                sync_directory(ACTIVE.parent)
                try:
                    LEGACY_LOCK.symlink_to(work)  # Also exclude pre-journal versions of the fixture.
                except BaseException:
                    ACTIVE.unlink()
                    raise
            except FileExistsError:
                if not points_to(ACTIVE, work) and not points_to(LEGACY_LOCK, work):
                    shutil.rmtree(work)  # Only this contender's unpublished private directory.
                raise
            return
        ownership = json.loads(path.read_text())
        if not points_to(ACTIVE, work) or ownership["id"] != owner:
            raise RuntimeError("HFT transaction or owner changed; refusing stale operation")
        if ownership.get("closing") and action not in (
                "take", "close", "clean-profiles", "restore", "restore-otel", "done", "finish"):
            raise RuntimeError("HFT transaction is closing; refusing late setup")
        if action in ("restore", "restore-otel") and (work / "profile.json").exists():
            raise RuntimeError("Test profile is still armed; cannot restore the production export path")
        if action in ("take", "close", "restore", "restore-otel"):
            if not os.path.lexists(LEGACY_LOCK):  # /run was cleared by a DUT reboot.
                LEGACY_LOCK.symlink_to(work)
            if not points_to(LEGACY_LOCK, work):
                raise RuntimeError("Another HFT run holds the legacy lock")
            if (work / "before.json").exists() or (work / "otel.json").exists():
                wait_for_service_jobs()
        if action == "take":
            save(path, {**ownership, "id": args[0], "controller": args[1], "closing": True})
        elif action == "close":
            if not ownership.get("closing"):
                save(path, {**ownership, "closing": True})
            print(" ".join(ownership.get("done", [])))
        elif action == "done":
            name, = args
            if not ownership.get("closing") or name not in ("hft", "otel", "sink", "profiles"):
                raise RuntimeError("Invalid HFT recovery checkpoint")
            save(path, {**ownership, "done": sorted(set(ownership.get("done", [])) | {name})})
        elif action == "finish":
            required = {"hft"} if (work / "before.json").exists() else set()
            if (work / "sink.json").exists():
                required.update(("sink", "profiles"))
            if (work / "otel.json").exists():
                required.add("otel")
            if ((work / "profile.json").exists() or not ownership.get("closing") or
                    not required.issubset(ownership.get("done", []))):
                raise RuntimeError("HFT transaction has not completed recovery")
            if points_to(LEGACY_LOCK, work):
                LEGACY_LOCK.unlink()
            elif os.path.lexists(LEGACY_LOCK):
                raise RuntimeError("Unexpected HFT lock; keeping recovery record")
            ACTIVE.unlink()
            sync_directory(ACTIVE.parent)
            shutil.rmtree(work)
        elif action == "record":
            name, = args
            if name not in ("sink.json", "otel.json") or (work / name).exists():
                raise RuntimeError("Invalid or already armed HFT recovery record")
            pending = work / (name + "." + owner)
            if name == "otel.json":
                # Reject an unsupported or changed baseline *before* arming rollback.
                import docker
                snapshot = json.loads(pending.read_text())
                client = docker.from_env()
                try:
                    current = check_otel(client, work, snapshot)
                    if (current.id if current else None) != snapshot["container_id"]:
                        raise RuntimeError("OTEL identity changed before setup")
                    check_otel_fields(snapshot, otel_fields(), False)
                    if snapshot["original_state"] == "disabled":
                        snapshot["unit_policy"] = disabled_policy("otel")
                    else:
                        require_restartable("otel")
                finally:
                    client.close()
                save(work / name, snapshot)
                pending.unlink()
                return
            # Do not put collector configuration in a command line or Ansible log.
            with pending.open() as stream:
                os.fsync(stream.fileno())
            os.replace(pending, work / name)
            os.fsync(fd)
        elif action in ("profile-create", "profile-state", "profile-remove", "clean-profiles"):
            from hft_profiles import OwnedProfile  # sibling staged on the DUT
            profile = OwnedProfile(work, command, save, fd)
            if action == "profile-create":
                print(profile.create(args[0], **json.load(sys.stdin)))
            elif action == "profile-state":
                profile.set_state(*args)
            else:
                profile.remove(*args)
        elif action in ("install", "restore", "restart-countersyncd", "prepare-otel", "configure", "restart-otel",
                        "stop-collector", "restore-otel"):
            if not points_to(LEGACY_LOCK, work):
                raise RuntimeError("HFT runtime lock is missing or has changed")
            if action == "restore":
                if not ownership.get("closing"):
                    save(path, {**ownership, "closing": True})
                if not (work / "before.json").exists():
                    return
            import docker
            client = docker.from_env()
            try:
                if action == "install":
                    install(client, work, args[0], args[1:])
                elif action == "restart-countersyncd":
                    print(json.dumps(restart_countersyncd(client, work)))
                elif action == "restore":
                    print(restore(client, work) or "")
                elif action == "restore-otel":
                    restore_otel(client, work, json.loads((work / "otel.json").read_text()))
                else:
                    snapshot = json.loads((work / "otel.json").read_text())
                    current = check_otel(client, work, snapshot)
                    if action == "prepare-otel":
                        check_otel_fields(snapshot, otel_fields(), False)
                        if not current:
                            create_from_launcher(client, work, "otel", OTEL_LABEL, [])
                        if snapshot["original_state"] == "disabled":
                            enable_otel(client, work, snapshot)
                    elif not current:
                        raise RuntimeError("Expected OTEL container is missing; not starting an unlabelled replacement")
                    elif action == "configure":
                        def check_destination():
                            active = check_otel(client, work, snapshot)
                            fields = otel_fields()
                            check_otel_fields(snapshot, fields, (work / "otel-enable.json").exists())
                            if not active or active.status != "running" or fields.get("state") not in (
                                    "enabled", "always_enabled"):
                                raise RuntimeError("OTEL is not enabled and running; refusing config replacement")

                        install_collector_config(work, owner, before_replace=check_destination)
                    else:
                        fields = otel_fields()
                        check_otel_fields(snapshot, fields, (work / "otel-enable.json").exists())
                        if fields.get("state") not in ("enabled", "always_enabled"):
                            raise RuntimeError("OTEL is no longer enabled; refusing to interrupt the collector")
                        require_restartable("otel")
                        check_service_config(work)
                        save(work / "collector-activity.json", True)  # before the first process change
                        if action == "restart-otel":
                            command("systemctl", "reset-failed", "otel.service")
                            command("systemctl", "restart", "otel.service")
                        else:
                            stop_collector(current)
            finally:
                client.close()
        else:
            raise ValueError(f"Unknown action: {action}")
    finally:
        FENCE_FDS.reset(fence)
        os.close(fd)


if __name__ == "__main__":
    action, directory, owner, *arguments = sys.argv[1:]
    transaction(action, Path(directory), owner, arguments)
