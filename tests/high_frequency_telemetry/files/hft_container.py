"""Run on the DUT. Give the systemd-managed hft container a temporary Docker CMD."""

import json
import subprocess
import sys
import time
from pathlib import Path

SERVICE = "hft"
OWNER_LABEL = "sonic-mgmt.hft-test"
DEVICE_DIR = Path("/usr/share/sonic/device")


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
        raise RuntimeError("Refusing to restart hft: its HwSKU mount does not match the DUT")


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


def stop_service(container):
    command("systemctl", "stop", "hft.service")
    if container is not None:
        container.reload()
        if container.attrs["State"]["Running"]:
            raise RuntimeError("hft is still running after systemctl stop")


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
    before = {"state": state, "original": original.id if original else None}
    with (work / "before.json").open("x") as record:
        json.dump(before, record)
    if original is None:
        # Ask SONiC for the correct platform-specific mounts, privileges and environment.
        source = enable_feature(client)
        check_source(source)
        (work / "source").write_text(source.id)
    else:
        source = original
    candidate = create_with_args(client, source, work.name, args)
    stop_service(source)
    source.rename(work.name + "-original")
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
    source_file = work / "source"
    source_id = source_file.read_text() if source_file.exists() else before["original"]
    current = lookup(client, SERVICE)
    test_owns_current = current is not None and current.labels.get(OWNER_LABEL) == work.name
    if current and current.id != source_id and not test_owns_current:
        raise RuntimeError("Unexpected hft container; refusing to stop or remove it")
    if before["state"] == "disabled" or test_owns_current:
        # Under warm restart the unit's ExecStop uses 'container kill', which
        # requires the feature still to be enabled. Stop and verify before disabling.
        stop_service(current)
    if before["state"] == "disabled" and feature_state() != "disabled":
        command("config", "feature", "state", SERVICE, "disabled")

    for candidate in client.containers.list(all=True, filters={"label": OWNER_LABEL + "=" + work.name}):
        candidate.remove()  # Never force-remove a running container.
    source = lookup(client, source_id) if source_id else None
    if before["original"] and not source:
        raise RuntimeError("The original hft container is missing")
    if source:
        if source.name not in (SERVICE, work.name + "-original"):
            raise RuntimeError("Unexpected name for the original hft container")
        if before["original"] is None:
            source.remove()
        elif source.name != SERVICE:
            source.rename(SERVICE)
    if before["state"] != "disabled":
        check_hwsku(source)
        start_service()
        if client.containers.get(SERVICE).id != before["original"]:
            raise RuntimeError("Failed to restore the original hft container")
    # The caller removes the record only after the restored daemon is healthy.


if __name__ == "__main__":
    import docker

    action, directory, *arguments = sys.argv[1:]
    client = docker.from_env()
    try:
        if action == "install":
            install(client, Path(directory), arguments[0], arguments[1:])
        elif action == "restore":
            restore(client, Path(directory))
        else:
            raise ValueError(f"Unknown action: {action}")
    finally:
        client.close()
