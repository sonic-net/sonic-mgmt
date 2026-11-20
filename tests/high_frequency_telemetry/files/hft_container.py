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


def command(*args):
    return subprocess.check_output(args, text=True).strip()


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


def disabled_policy(service):
    policy = unit_policy(service)
    if policy not in UNIT_POLICIES:
        raise RuntimeError(f"Cannot restore non-standard {service} UnitFileState {policy!r}")
    return policy


def restore_disabled_policy(service, original, *, allow_missing=False):
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
        if (missing or reported in ("", "disabled", "failed")) and active in ("inactive", "failed"):
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


def enable_feature(client):
    command("config", "feature", "state", SERVICE, "enabled")
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


def create_from_launcher(client, work, service, label, args):
    cid = command("bash", str(work / "create_container.sh"), service, label + "=" + work.name, *args)
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

    # Write recovery information before the first change. Keep the *actual* original
    # container (including its writable layer) until its name and state are restored.
    record = work / "before.json"
    if record.exists():
        raise RuntimeError("HFT install already attempted; recover this run first")
    policy = disabled_policy(SERVICE) if state == "disabled" else None
    save(record, {"state": state, "original": original.id if original else None, "unit_policy": policy})
    if original is None:
        # Label at Docker create, before SONiC is allowed to start the feature. An
        # interrupted/failed bootstrap never requires adopting an unlabelled hft.
        candidate = create_from_launcher(client, work, SERVICE, OWNER_LABEL, args)
    else:
        candidate = create_with_args(client, original, work.name, args)
        stop_service(original)
        original.rename(work.name + "-original")
        candidate.rename(SERVICE)
    if feature_state() == "disabled":
        enable_feature(client)
    else:
        start_service()
    running = client.containers.get(SERVICE)
    if running.id != candidate.id or running.attrs["Config"]["Cmd"] != args:
        raise RuntimeError("SONiC did not start the hft container with the requested Docker CMD")


def restore(client, work):
    record = work / "before.json"
    if not record.exists():  # Setup rejected the initial state without changing the DUT.
        return
    before = json.loads(record.read_text())
    if command("sonic-db-cli", "CONFIG_DB", "HGET", "FEATURE|hft", "set_owner") not in ("", "local"):
        raise RuntimeError("HFT is no longer locally managed; keeping recovery record")
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
    if before["state"] == "disabled" and feature_state() != "disabled":
        command("config", "feature", "state", SERVICE, "disabled")

    for candidate in candidates:
        candidate.remove()  # Never force-remove a running container.
    if source and source.name != SERVICE:
        source.rename(SERVICE)
    if before["state"] == "disabled":
        restore_disabled_policy(SERVICE, before["unit_policy"])
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
    if not snapshot["original_feature"]:
        fields = [v for field in CREATED_OTEL_FIELDS.items() for v in field]
        result = command("redis-cli", "-n", "4", "--raw", "EVAL",
                         "if redis.call('EXISTS',KEYS[1]) ~= 0 then return 0 end; "
                         "redis.call('HSET',KEYS[1],unpack(ARGV)); return 1", "1", "FEATURE|otel", *fields)
        if result != "1":
            (work / "otel-enable.json").unlink()
            raise RuntimeError("FEATURE|otel appeared during setup; refusing to replace it")
    command("config", "feature", "state", "otel", "enabled")
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


def undo_otel_state(expected_state, restore_state, *, created):
    # For a temporary hash, compare *all* fields before either writing or deleting.
    # For an existing hash, compare state and local ownership in the same Redis
    # operation and leave every other field (including later operator edits) alone.
    expected = {**CREATED_OTEL_FIELDS, "state": expected_state} if created else {"state": expected_state}
    fields = [v for item in expected.items() for v in item]
    script = """
        local row = ARGV[1] == 'row'
        local owner = redis.call('HGET', KEYS[1], 'set_owner')
        if owner and owner ~= '' and owner ~= 'local' then return 0 end
        if row and redis.call('HLEN', KEYS[1]) ~= (#ARGV - 2) / 2 then return 0 end
        for i = 3, #ARGV, 2 do
            if redis.call('HGET', KEYS[1], ARGV[i]) ~= ARGV[i+1] then return 0 end
        end
        if ARGV[2] ~= '' then redis.call('HSET', KEYS[1], 'state', ARGV[2])
        elseif row then redis.call('DEL', KEYS[1])
        else redis.call('HDEL', KEYS[1], 'state') end
        return 1
    """
    result = command("redis-cli", "-n", "4", "--raw", "EVAL", script, "1", "FEATURE|otel",
                     "row" if created else "state", restore_state or "", *fields)
    if result != "1":
        raise RuntimeError("OTEL feature state changed during recovery; keeping recovery record")


def restore_otel(client, work, snapshot):
    current = check_otel(client, work, snapshot)
    armed = (work / "otel-enable.json").exists()
    fields = otel_fields()
    check_otel_fields(snapshot, fields, armed)
    install_collector_config(work, None)  # Restore only the original or test-written file.
    if snapshot["original_state"] == "disabled":
        if current:
            # Also covers a pre-existing, originally stopped container left running
            # with an inactive unit. check_otel verified its exact ID (or run label).
            stop_owned_unit("otel")
            stop_by_id(current)
        if armed and fields.get("state") == "enabled":
            undo_otel_state("enabled", "disabled", created=not snapshot["original_feature"])
        current = wait_otel(client, work, snapshot, lambda c: c is None or c.status in ("created", "exited"), "stop")
        # Let featured act on 'disabled' before removing a temporary row; once
        # the row is gone it can no longer reconcile the unit's boot policy.
        restore_disabled_policy("otel", snapshot["unit_policy"],
                                allow_missing="state" not in snapshot["original_feature"])
        fields = otel_fields()
        check_otel_fields(snapshot, fields, armed)
        if armed and fields and not snapshot["original_feature"]:
            undo_otel_state("disabled", None, created=True)
        elif armed and "state" not in snapshot["original_feature"] and fields.get("state") == "disabled":
            undo_otel_state("disabled", None, created=False)
        if current and snapshot["container_id"] is None:
            current.remove()  # The tagged test container has positively stopped.
    elif snapshot["original_collector_running"]:
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


def install_collector_config(work, owner):
    """Publish the allowed content digest and atomically install it under the owner fence."""
    if os.path.lexists(OTEL_CONFIG):
        st = OTEL_CONFIG.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise RuntimeError(f"Refusing to overwrite managed {OTEL_CONFIG}")
    else:
        st = None
    original, original_mode = json.loads((work / "otel.json").read_text())["otel_config"]
    current = OTEL_CONFIG.read_bytes() if st else None
    if st and stat.S_IMODE(st.st_mode) != (int(original_mode, 8) if original_mode else 0o644):
        raise RuntimeError("OTEL config permissions changed outside the HFT transaction")
    if current != (original.encode() if original is not None else None):
        if current is None or not (work / ("config-" + config_digest(current))).exists():
            raise RuntimeError("OTEL config was changed outside this transaction")
    stage = OTEL_CONFIG.parent / ("." + work.name + ".otel.tmp")
    if owner is None:
        stage.unlink(missing_ok=True)
        if original is None:
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
    fd = os.open(stage, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as tmp:
            tmp.write(data)
            if st:
                os.fchown(tmp.fileno(), st.st_uid, st.st_gid)
            os.fchmod(tmp.fileno(), mode)
            tmp.flush()
            os.fsync(tmp.fileno())
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
            save(path, {"version": 3, "id": owner, "controller": args[0]})
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
        if ownership.get("closing") and action not in ("take", "close", "restore", "restore-otel", "done", "finish"):
            raise RuntimeError("HFT transaction is closing; refusing late setup")
        if action in ("take", "close", "restore"):
            if not os.path.lexists(LEGACY_LOCK):  # /run was cleared by a DUT reboot.
                LEGACY_LOCK.symlink_to(work)
            if not points_to(LEGACY_LOCK, work):
                raise RuntimeError("Another HFT run holds the legacy lock")
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
            if not ownership.get("closing") or not required.issubset(ownership.get("done", [])):
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
        elif action == "configure":
            install_collector_config(work, owner)
        elif action in ("install", "restore", "prepare-otel", "restart-otel", "stop-collector", "restore-otel"):
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
                    elif action == "restart-otel":
                        command("systemctl", "reset-failed", "otel.service")
                        command("systemctl", "restart", "otel.service")
                    else:
                        stop_collector(current)
            finally:
                client.close()
        else:
            raise ValueError(f"Unknown action: {action}")
    finally:
        os.close(fd)


if __name__ == "__main__":
    action, directory, owner, *arguments = sys.argv[1:]
    transaction(action, Path(directory), owner, arguments)
