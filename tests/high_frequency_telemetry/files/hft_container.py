"""Run on the DUT: temporarily give the systemd-managed hft container a Docker CMD."""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import docker
from docker.errors import NotFound


WORK = Path(__file__).resolve().parent
RECORD = WORK / "before.json"
LABEL = "sonic-mgmt.hft-test"


def command(*args):
    return subprocess.check_output(args, text=True, close_fds=False).strip()  # inherit the outer flock


def container(client, name):
    try:
        return client.containers.get(name)
    except NotFound:
        return None


def feature(field="state"):
    return command("sonic-db-cli", "CONFIG_DB", "HGET", "FEATURE|hft", field)


def change_state(expected, new):
    # Only change the locally owned state this fixture saw. Leave the other FEATURE fields alone.
    script = """local owner = redis.call('HGET', KEYS[1], 'set_owner');
        if owner and owner ~= '' and owner ~= 'local' or redis.call('HGET', KEYS[1], 'state') ~= ARGV[1]
        then return 0 end; redis.call('HSET', KEYS[1], 'state', ARGV[2]); return 1"""
    result = command("redis-cli", "-n", "4", "--raw", "EVAL", script, "1", "FEATURE|hft", expected, new)
    if result == "0" and new == "enabled":
        (WORK / "enabled").unlink()  # The comparison refused: this run made no change.
    if result != "1":
        raise RuntimeError("HFT ownership or state changed")


def check_hwsku(source):
    platform = command("sonic-cfggen", "-H", "-v", "DEVICE_METADATA.localhost.platform")
    sku = command("sonic-cfggen", "-d", "-v", 'DEVICE_METADATA["localhost"]["hwsku"]')
    mounts = [Path(m["Source"]) for m in source.attrs["Mounts"] if m["Destination"] == "/usr/share/sonic/hwsku"]
    if not platform or not sku or mounts != [Path("/usr/share/sonic/device") / platform / sku]:
        raise RuntimeError("hft.sh would replace this container because its HwSKU mount does not match")


def with_otel(cmd, flags):
    """Keep unrelated CMD tokens; refuse ambiguous short options before stopping hft."""
    result = []
    args = iter(cmd or [])
    for arg in args:
        if arg in ("--enable-otel", "-o") or arg.startswith(("--enable-otel=", "--otel-endpoint=")):
            continue
        if arg == "--otel-endpoint":
            endpoint = next(args, None)
            if not endpoint or endpoint.startswith("-"):
                raise RuntimeError("Incomplete --otel-endpoint in the original hft command")
            continue
        if arg == "--" or (arg.startswith("-") and not arg.startswith("--") and len(arg) > 2):
            raise RuntimeError(f"Cannot safely override OTEL in the original hft command: {arg}")
        result.append(arg)
    return result + flags


def clone(client, source_id, flags):
    """Clone the managed container in a waited child that also holds the outer flock."""
    source = client.containers.get(source_id)
    check_hwsku(source)
    config = source.attrs["Config"].copy()
    host = source.attrs["HostConfig"]
    if (host["NetworkMode"] != "host" or host["AutoRemove"] or
            any(m["Type"] == "volume" for m in source.attrs["Mounts"])):
        raise RuntimeError("Unsupported hft container configuration")
    config.update(Image=source.attrs["Image"], HostConfig=host, Cmd=with_otel(config.get("Cmd"), flags),
                  Labels={**(config.get("Labels") or {}), LABEL: WORK.name})
    if host["UTSMode"] == "host":
        config.pop("Hostname", None)
    return client.api.create_container_from_config(config, name=WORK.name)["Id"]


def start_service():
    try:
        command("systemctl", "start", "hft.service")
    except subprocess.CalledProcessError:
        if command("systemctl", "show", "hft.service", "-p", "Result", "--value") != "start-limit-hit":
            raise
        command("systemctl", "reset-failed", "hft.service")
        command("systemctl", "start", "hft.service")


def wait_for_feature(*states):
    for _ in range(60):
        if command("sonic-db-cli", "STATE_DB", "HGET", "FEATURE|hft", "state") in states:
            return
        time.sleep(1)
    raise RuntimeError(f"HFT did not reach {states}; retaining recovery record")


def install(client, flags):
    source = container(client, "hft")
    state = feature()
    if feature("set_owner") not in ("", "local") or state not in ("disabled", "enabled", "always_enabled"):
        raise RuntimeError("HFT is not locally configurable")
    if bool(source and source.status == "running") != (state != "disabled"):
        raise RuntimeError("HFT container does not match its feature state")
    if source and (LABEL in source.labels or source.status not in ("created", "exited", "running")):
        raise RuntimeError("Unexpected hft container; refusing to replace it")
    policy = command("systemctl", "show", "hft.service", "-p", "UnitFileState", "--value")
    if policy not in ("masked", "disabled", "enabled") or (state != "disabled" and policy == "masked"):
        raise RuntimeError(f"Cannot safely restart hft with unit policy {policy!r}")
    if state == "disabled":
        wait_for_feature("", "disabled")
    # Keep the original container and its ID, including its writable layer, until teardown.
    with RECORD.open("x") as record:
        json.dump({"state": state, "original": source.id if source else None, "policy": policy}, record)
        record.flush()
        os.fsync(record.fileno())
    if source:
        trial = command(sys.executable, "-B", __file__, "clone", source.id, *flags)
        current = container(client, "hft")
        if not current or current.id != source.id or feature() != state or feature("set_owner") not in ("", "local"):
            command("docker", "rm", trial)  # Never interrupt an original that changed while creating the candidate.
            raise RuntimeError("HFT baseline changed during container creation")
        if source.status == "running":
            command("systemctl", "stop", "hft.service")
        source.reload()
        if source.status not in ("created", "exited"):
            raise RuntimeError("Original hft did not stop")
        command("docker", "rename", source.id, WORK.name + "-original")
        command("docker", "rename", trial, "hft")
    else:
        # Use the stock launcher's mounts and environment and label the container at create time.
        trial = command("bash", str(WORK / "create_hft.sh"), LABEL + "=" + WORK.name, *flags)
    if state == "disabled":
        (WORK / "enabled").touch()  # Before the write, so a lost reply still leaves a recovery record.
        change_state("disabled", "enabled")
    else:
        start_service()
    return trial


def restore_disabled_policy(policy):
    wait_for_feature("disabled")  # featured acknowledges disable after stopping and masking the unit.
    if feature() != "disabled" or feature("set_owner") not in ("", "local"):
        raise RuntimeError("HFT feature changed during restoration")
    if command("systemctl", "show", "hft.service", "-p", "UnitFileState", "--value") != policy:
        command("systemctl", "unmask", "hft.service")
        command("systemctl", {"masked": "mask", "enabled": "enable", "disabled": "disable"}[policy], "hft.service")


def restore(client):
    if not RECORD.exists():
        return  # No HFT change was attempted.
    before = json.loads(RECORD.read_text())
    if command("redis-cli", "-n", "4", "--raw", "KEYS", "HIGH_FREQUENCY_TELEMETRY_*"):
        raise RuntimeError("HFT profiles remain; quiesce them before restoring the original container")
    source_id = before["original"]
    current = container(client, "hft")
    enabled = (WORK / "enabled").exists()
    allowed = {before["state"], "enabled"} if enabled else {before["state"]}
    if feature("set_owner") not in ("", "local") or feature() not in allowed:
        raise RuntimeError("HFT owner or state changed; retaining recovery record")
    if current and current.labels.get(LABEL) != WORK.name and current.id != source_id:
        raise RuntimeError("Unrecognized hft container; retaining recovery record")
    if enabled and feature() == "enabled":
        wait_for_feature("enabled", "failed")  # Don't undo an enable that featured hasn't processed yet.
    if current and current.labels.get(LABEL) == WORK.name:
        command("systemctl", "stop", "hft.service")
        current.reload()
        if current.attrs["State"]["Running"]:
            command("docker", "stop", current.id)  # Its service may already have been inactive.
    if enabled and feature() == "enabled":
        change_state("enabled", "disabled")
    if enabled:
        restore_disabled_policy(before["policy"])
    for trial in client.containers.list(all=True, filters={"label": LABEL + "=" + WORK.name}):
        command("docker", "rm", trial.id)  # Never force-remove a running or unidentified container.
    if source_id:
        source = client.containers.get(source_id)
        if source.name == WORK.name + "-original":
            command("docker", "rename", source_id, "hft")
        elif source.name != "hft":
            raise RuntimeError("Original hft container was renamed outside this test")
        if before["state"] != "disabled" and source.status != "running":
            check_hwsku(source)
            start_service()
            restored = client.containers.get("hft")
            if restored.id != source_id or restored.status != "running":
                raise RuntimeError("Original hft container was not restored")
    RECORD.unlink()


if __name__ == "__main__":
    action, *args = sys.argv[1:]
    client = docker.from_env()
    try:
        if action == "install":
            print(install(client, args))
        elif action == "clone":
            print(clone(client, args[0], args[1:]))
        elif action == "restore":
            restore(client)
        else:
            raise ValueError(action)
    finally:
        client.close()
