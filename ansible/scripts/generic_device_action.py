#!/usr/bin/env python3
"""Operator-invoked generic deployment actions; never call from the planner."""

import argparse
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from generic_config import digest, generic_identity, read_running, write_private


def check_hwsku_alias(config, report):
    spec = report.get("hwsku_alias")
    if spec is None:
        return None
    platform = report["platform"]
    if not platform or Path(platform).name != platform or platform in (".", ".."):
        raise ValueError("Invalid alias platform")
    expected = generic_identity(Path("/usr/share/sonic/device") / platform, spec["original_hwsku"])
    if spec != expected or config["DEVICE_METADATA"]["localhost"]["hwsku"] != expected["hwsku"]:
        raise ValueError("HwSKU alias report does not match the rendered DUT identity")
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
    if action in ("stage", "apply") and digest(config) != report["config_sha256"]:
        raise ValueError("Rendered configuration digest does not match its report")
    running = None if action in ("rollback", "save") else read_running()
    if action == "stage":
        if digest(running) != report["baseline_sha256"]:
            raise ValueError("Running CONFIG_DB changed since rendering; render a fresh scenario")
        check_hwsku_alias(config, report)
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
        if digest(json.loads((directory / "new-config.json").read_text())) != report["config_sha256"]:
            raise ValueError("Staged configuration changed after validation; render a fresh scenario")
        create_hwsku_alias(config, report, directory)
        write_private(directory / "reload-attempted.json", {"config_sha256": report["config_sha256"]})
        reload_config(directory / "new-config.json")
    elif action == "save":
        for _ in range(3):
            before = digest(read_running())
            subprocess.run(["config", "save", "-y"], check=True)
            saved = digest(json.loads(Path("/etc/sonic/config_db.json").read_text()))
            after = digest(read_running())
            if before == saved == after:
                break
        else:
            raise ValueError("Saved startup configuration differs from stable running CONFIG_DB after 3 save attempts")
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
    parser.add_argument("--action", choices=("stage", "apply", "save", "rollback"), required=True)
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
