#!/usr/bin/env python3
"""Operator-invoked generic deployment actions; never call from the planner."""

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from generic_config import (digest, generic_identity, installed_asset, numbers, read_buffer_daemon, read_running,
                            validate_references, write_private)


def expand_pgs(rows):
    expanded = {}
    for key, row in rows.items():
        ports, indices = key.split("|")
        for port in ports.split(","):
            for index in numbers(indices):
                child = port + "|" + str(index)
                if child in expanded:
                    raise ValueError("Overlapping BUFFER_PG bindings: {}".format(child))
                expanded[child] = row
    return expanded


def verify_config(config, running, report):
    """Accept only declared daemon outputs in addition to the rendered configuration."""
    expected = report.get("lossless_buffers")
    managed = {"BUFFER_PROFILE", "BUFFER_PG"} if expected else set()
    differences = sorted(table for table in set(config) | set(running)
                         if table not in managed and config.get(table, {}) != running.get(table, {}))
    if differences:
        raise ValueError("CONFIG_DB read-back differs in tables: {}".format(", ".join(differences)))
    if not expected:
        return True
    pending = False
    for table, required in (
            ("BUFFER_PROFILE", expected["profiles"]),
            ("BUFFER_PG", {key: {"profile": name} for key, name in expected["pgs"].items()})):
        planned, actual = config.get(table, {}), running.get(table, {})
        if table == "BUFFER_PG":
            planned, actual = expand_pgs(planned), expand_pgs(actual)
        if ({key: row for key, row in planned.items() if key not in required}
                != {key: row for key, row in actual.items() if key not in required}):
            raise ValueError("CONFIG_DB read-back differs in protected or template-owned {}".format(table))
        for key, row in required.items():
            if key not in actual:
                pending = True
            elif actual[key] != row:
                raise ValueError("Daemon-generated {} {} differs from the expected lookup/binding".format(table, key))
    return not pending


def check_daemon_asset(report):
    if "buffer_daemon" in report:
        current = read_buffer_daemon()
        if any(current[key] != value for key, value in report["buffer_daemon"].items()):
            raise ValueError("Active buffer daemon lookup changed since rendering")


def read_appl_buffers():
    query = """
import json
from swsscommon import swsscommon

db = swsscommon.DBConnector('APPL_DB', 0)
result = {}
for name in ('BUFFER_PROFILE', 'BUFFER_PG'):
    table = swsscommon.Table(db, name + '_TABLE')
    rows = {}
    for key in table.getKeys():
        present, values = table.get(key)
        if present:
            rows[key.replace(':', '|')] = dict(values)
    result[name] = rows
print(json.dumps(result))
"""
    return json.loads(subprocess.check_output(["docker", "exec", "swss", "python3", "-c", query], text=True))


def verify_appl_buffers(expected):
    actual = read_appl_buffers()
    pgs = expand_pgs(actual.get("BUFFER_PG", {}))
    pending = False
    for table, rows in (
            (actual.get("BUFFER_PROFILE", {}), expected["profiles"]),
            (pgs, {key: {"profile": name} for key, name in expected["pgs"].items()})):
        for key, row in rows.items():
            if key not in table:
                pending = True
            elif table[key] != row:
                raise ValueError("APPL_DB lossless buffer {} differs from expected programming".format(key))
    return not pending


def check_hwsku_alias(config, report, require_present=False):
    spec = report.get("hwsku_alias")
    if spec is None:
        return None
    platform = report["platform"]
    if not platform or Path(platform).name != platform or platform in (".", ".."):
        raise ValueError("Invalid alias platform")
    expected = generic_identity(Path("/usr/share/sonic/device") / platform, spec["original_hwsku"])
    if spec != expected or config["DEVICE_METADATA"]["localhost"]["hwsku"] != expected["hwsku"]:
        raise ValueError("HwSKU alias report does not match the rendered DUT identity")
    if require_present and not Path(spec["alias"]).is_symlink():
        raise ValueError("Applied generic HwSKU alias is missing")
    return spec


def create_hwsku_alias(config, report, directory):
    spec = check_hwsku_alias(config, report)
    if spec is None:
        return
    alias = Path(spec["alias"])
    if alias.is_symlink():
        return
    os.symlink(Path(spec["target"]).name, alias)
    metadata = alias.lstat()
    ownership = {"alias": str(alias), "target": os.readlink(alias),
                 "inode": metadata.st_ino, "device": metadata.st_dev}
    try:
        write_private(directory / "hwsku-alias-created.json", ownership)
    except BaseException:
        if alias.is_symlink() and alias.lstat().st_ino == ownership["inode"]:
            alias.unlink()
        raise


def remove_created_alias(directory):
    journal = directory / "hwsku-alias-created.json"
    if not journal.is_file():
        return
    ownership = json.loads(journal.read_text())
    alias = Path(ownership["alias"])
    if not alias.exists() and not alias.is_symlink():
        return
    metadata = alias.lstat()
    if (not alias.is_symlink() or os.readlink(alias) != ownership["target"]
            or metadata.st_ino != ownership["inode"] or metadata.st_dev != ownership["device"]):
        raise ValueError("Owned HwSKU alias changed; refusing to remove another owner's path")
    alias.unlink()


def check_render_assets(report):
    for path, expected in report["assets"].items():
        if hashlib.sha256(Path(path).read_bytes()).hexdigest() != expected:
            raise ValueError("Installed rendering asset changed: {}".format(path))
    if "lookup_path" in report:
        platform = Path("/usr/share/sonic/device") / report["platform"]
        sku = Path(report["hwsku_alias"]["target"]) if "hwsku_alias" in report else platform / report["hwsku"]
        current = installed_asset(platform, sku, "pg_profile_lookup.ini", platform_first=True)
        if str(current.resolve(strict=True)) != report["lookup_path"]:
            raise ValueError("Installed lookup selection changed since rendering")


def reload_config(path):
    """Retry only SONiC's pre-mutation readiness rejection, never a failed reload."""
    deadline = time.monotonic() + 300
    readiness_messages = {
        "System is not up. Retry later or use -f to avoid system checks",
        "SwSS container is not ready. Retry later or use -f to avoid system checks",
    }
    while True:
        try:
            completed = subprocess.run(["config", "reload", "-y", str(path)],
                                       check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as error:
            output = error.stdout or ""
            if (error.returncode != 1 or not readiness_messages.intersection(output.splitlines())
                    or time.monotonic() >= deadline):
                sys.stdout.write(output)
                sys.stderr.write(error.stderr or "")
                raise
            time.sleep(5)
        else:
            sys.stdout.write(completed.stdout)
            sys.stderr.write(completed.stderr)
            return


def run(action, directory):
    request = json.loads((directory / "request.json").read_text())
    config, report = request["config"], request["report"]
    if digest(config) != report["config_sha256"]:
        raise ValueError("Rendered configuration digest does not match its report")
    running = None if action == "rollback" else read_running()
    if action == "stage":
        if digest(running) != report["baseline_sha256"]:
            raise ValueError("Running CONFIG_DB changed since rendering; render a fresh scenario")
        check_render_assets(report)
        check_daemon_asset(report)
        check_hwsku_alias(config, report)
        validate_references(config, report["retired_ports"])
        write_private(directory / "running-backup.json", running)
        startup = Path("/etc/sonic/config_db.json")
        metadata = startup.stat()
        original = startup.read_bytes()
        descriptor = os.open(str(directory / "startup-backup.json"), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(original)
        write_private(directory / "startup-stat.json", {
            "mode": metadata.st_mode & 0o777, "uid": metadata.st_uid, "gid": metadata.st_gid})
        write_private(directory / "new-config.json", config)
    elif action == "apply":
        if not (directory / "running-backup.json").is_file():
            raise ValueError("No staged running configuration backup")
        if digest(running) != report["baseline_sha256"]:
            raise ValueError("Running configuration changed after staging; refusing to overwrite it")
        check_render_assets(report)
        check_daemon_asset(report)
        create_hwsku_alias(config, report, directory)
        write_private(directory / "reload-attempted.json", {"config_sha256": report["config_sha256"]})
        reload_config(directory / "new-config.json")
    elif action == "verify":
        check_daemon_asset(report)
        check_hwsku_alias(config, report, require_present=True)
        deadline = time.monotonic() + 120
        while True:
            ready = verify_config(config, running, report)
            if ready and ("lossless_buffers" not in report or verify_appl_buffers(report["lossless_buffers"])):
                break
            if time.monotonic() >= deadline:
                raise ValueError("Timed out waiting for daemon-generated lossless profiles and PG bindings")
            time.sleep(1)
            running = read_running()
    elif action == "save":
        check_daemon_asset(report)
        check_hwsku_alias(config, report, require_present=True)
        if "lossless_buffers" in report:
            if (not verify_config(config, running, report)
                    or not verify_appl_buffers(report["lossless_buffers"])):
                raise ValueError("Daemon-generated buffers are incomplete before save")
        else:
            verify_config(config, running, report)
        subprocess.run(["config", "save", "-y"], check=True)
        if digest(json.loads(Path("/etc/sonic/config_db.json").read_text())) != digest(running):
            raise ValueError("Saved startup configuration differs from the verified artifact")
    elif action == "rollback":
        if not (directory / "reload-attempted.json").exists():
            remove_created_alias(directory)
            print("No reload attempted on this device; leaving its configuration untouched")
            return
        backup = directory / "running-backup.json"
        if not backup.is_file() or not (directory / "startup-backup.json").is_file():
            raise ValueError("Complete recovery snapshots are absent; refusing an incomplete recovery")
        reload_config(backup)
        metadata = json.loads((directory / "startup-stat.json").read_text())
        descriptor, name = tempfile.mkstemp(prefix=".generic-restore-", dir="/etc/sonic")
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write((directory / "startup-backup.json").read_bytes())
            os.chmod(temporary, metadata["mode"])
            os.chown(temporary, metadata["uid"], metadata["gid"])
            os.replace(str(temporary), "/etc/sonic/config_db.json")
        finally:
            if temporary.exists():
                temporary.unlink()
        if digest(read_running()) != digest(json.loads(backup.read_text())):
            raise ValueError("Rollback CONFIG_DB read-back failed; retain backups for manual recovery")
        remove_created_alias(directory)
    else:
        raise ValueError("Unknown deployment action")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--action", choices=("stage", "apply", "verify", "save", "rollback"), required=True)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    try:
        with open("/var/lib/sonic-generic/.action.lock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            run(args.action, args.directory)
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        parser.exit(1, "Generic device action failed: {}\n".format(error))


if __name__ == "__main__":
    main()
