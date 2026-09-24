#!/usr/bin/env python3
"""Preview or persist management addressing and 9600-baud boot settings on one SONiC DUT."""

import argparse
import copy
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile


CONFIG_PATH = Path("/etc/sonic/config_db.json")
GRUB_PATH = Path("/host/grub/grub.cfg")
TABLE = "MGMT_INTERFACE"


def run_command(arguments):
    """Run a SONiC CLI command without a shell and surface command failures."""
    return subprocess.run(
        arguments, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True,
    ).stdout


def read_running():
    """Read the host CONFIG_DB, not the kernel's temporary interface configuration."""
    return parse_config(run_command(["sonic-cfggen", "-d", "--print-data"]))


def parse_config(content):
    """Reject invalid configuration shapes before constructing a repair plan."""
    config = json.loads(content)
    if not isinstance(config, dict) or not isinstance(config.get(TABLE, {}), dict):
        raise ValueError("Configuration and MGMT_INTERFACE must be JSON objects")
    metadata = config.get("DEVICE_METADATA", {})
    if not isinstance(metadata, dict) or not isinstance(metadata.get("localhost", {}), dict):
        raise ValueError("DEVICE_METADATA.localhost must be a JSON object")
    return config


def address_pair(prefix, gateway, version):
    """Validate an explicit management prefix and its directly connected gateway."""
    if "/" not in prefix:
        raise ValueError("Management addresses require an explicit prefix length")
    interface = ipaddress.ip_interface(prefix)
    router = ipaddress.ip_address(gateway)
    if interface.version != version or router.version != version:
        raise ValueError("Prefix and gateway must both be IPv{}".format(version))
    gateway_on_link = router in interface.network or (version == 6 and router.is_link_local)
    if router == interface.ip or not gateway_on_link:
        raise ValueError("Gateway must be a different address in the management subnet")
    if interface.ip.is_unspecified or interface.ip.is_multicast:
        raise ValueError("Management address must be unicast")
    if router.is_unspecified or router.is_multicast:
        raise ValueError("Management gateway must be unicast")
    if version == 4 and interface.network.prefixlen < 31:
        reserved = (interface.network.network_address, interface.network.broadcast_address)
        if interface.ip in reserved or router in reserved:
            raise ValueError("Network and broadcast addresses cannot be used as host or gateway")
    return str(interface), str(router)


def management_config(running, addresses):
    """Replace only the requested eth0 address families, preserving all other tables."""
    desired = copy.deepcopy(running)
    table = desired.setdefault(TABLE, {})
    if not isinstance(table, dict):
        raise ValueError("MGMT_INTERFACE must be an object")
    for prefix, gateway in addresses:
        version = ipaddress.ip_interface(prefix).version
        for key in list(table):
            if not key.startswith("eth0|"):
                continue
            if ipaddress.ip_interface(key.split("|", 1)[1]).version != version:
                continue
            if not isinstance(table[key], dict) or set(table[key]) - {"gwaddr", "NULL"}:
                raise ValueError(
                    "{} has additional management attributes; reconcile them manually".format(key)
                )
            del table[key]
        table["eth0|" + prefix] = {"gwaddr": gateway}
    return desired


def console_9600(text):
    """Patch both boot stages, without touching ONIE or unrelated baud-rate text."""
    serial_count = 0
    kernel_count = 0
    result = []
    for line in text.splitlines(keepends=True):
        if re.match(r"^\s*serial\s+", line):
            pattern = r"(?<!\S)--speed=(\d+)(?!\S)"
            stage = "GRUB serial"
            serial_count += 1
        elif re.match(r"^\s*linux(?:efi)?\s+/\S*image-\S*/boot/vmlinuz\S*\s", line):
            pattern = r"(?<!\S)console=ttyS0,(\d+)(?:n8)?(?!\S)"
            stage = "SONiC kernel"
            kernel_count += 1
        else:
            result.append(line)
            continue
        matches = list(re.finditer(pattern, line))
        if len(matches) != 1 or matches[0].group(1) not in ("9600", "115200"):
            raise ValueError(
                "{} must have exactly one recognized 9600/115200 setting".format(stage)
            )
        match = matches[0]
        line = line[:match.start(1)] + "9600" + line[match.end(1):]
        result.append(line)
    if serial_count != 1 or kernel_count == 0:
        raise ValueError("Expected one GRUB serial command and at least one SONiC kernel entry")
    return "".join(result)


def backup(path, content):
    """Create a private, unique backup before changing either configuration file."""
    fd, name = tempfile.mkstemp(prefix=path.name + ".mgfx-backup-", dir=str(path.parent))
    with os.fdopen(fd, "wb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    return name


def atomic_write(path, content):
    """Keep the boot file's ownership and mode when replacing it."""
    previous = path.stat()
    fd, name = tempfile.mkstemp(prefix=path.name + ".mgfx-", dir=str(path.parent))
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if hasattr(os, "chown"):
            os.chown(name, previous.st_uid, previous.st_gid)
        os.chmod(name, previous.st_mode & 0o7777)
        os.replace(name, str(path))
    finally:
        if temporary.exists():
            temporary.unlink()


def repair(hostname, addresses, set_console_9600=False, apply=False, console_access=False):
    """Preflight, preview, apply through supported CLI, and read back the resulting artifacts."""
    config_path = CONFIG_PATH.resolve(strict=True)
    config_bytes = config_path.read_bytes()
    saved = parse_config(config_bytes)
    running = read_running()
    actual = running.get("DEVICE_METADATA", {}).get("localhost", {}).get("hostname", "")
    if not isinstance(actual, str) or not actual:
        raise ValueError("CONFIG_DB must contain a nonempty device hostname")
    if actual.lower() != hostname.lower() or socket.gethostname().lower() != hostname.lower():
        raise ValueError("Expected hostname does not match both the kernel and CONFIG_DB hostname")
    desired = management_config(running, addresses)
    desired_saved = management_config(saved, addresses)
    grub_path = GRUB_PATH.resolve(strict=True) if set_console_9600 else None
    grub_bytes = grub_path.read_bytes() if grub_path else None
    wanted_grub = console_9600(grub_bytes.decode("utf-8")).encode("utf-8") if grub_path else None
    save_needed = bool(addresses) and (
        running.get(TABLE, {}) != desired.get(TABLE, {}) or saved.get(TABLE, {}) != desired.get(TABLE, {})
    )
    grub_needed = grub_path is not None and grub_bytes != wanted_grub
    unsaved_tables = sorted(
        key for key in set(running) | set(saved)
        if key != TABLE and running.get(key) != saved.get(key)
    )
    plan = {
        "hostname": actual,
        "mode": "apply" if apply else "preview",
        "running_management": running.get(TABLE, {}),
        "saved_management": saved.get(TABLE, {}),
        "desired_management": desired.get(TABLE, {}),
        "save_required": save_needed,
        "grub_update_required": grub_needed,
        "other_unsaved_tables": unsaved_tables,
        "unrequested_management_drift": desired_saved.get(TABLE, {}) != desired.get(TABLE, {}),
    }
    print(json.dumps(plan, indent=2), flush=True)
    if not apply:
        return plan
    if not console_access:
        raise ValueError("--apply requires --confirm-console-access; management addressing can disconnect SSH")
    if save_needed and unsaved_tables:
        raise ValueError(
            "config save would persist unrelated changes in {}; reconcile these first".format(unsaved_tables)
        )
    if save_needed and plan["unrequested_management_drift"]:
        raise ValueError(
            "Unrequested management settings differ between running and saved config; reconcile them first"
        )
    if not save_needed and not grub_needed:
        return plan
    backups = {}
    if save_needed:
        backups["config"] = backup(config_path, config_bytes)
    if grub_needed:
        backups["grub"] = backup(grub_path, grub_bytes)
    print(json.dumps({"backups": backups}), flush=True)
    if config_path.read_bytes() != config_bytes or read_running() != running:
        raise ValueError("Configuration changed during preflight; no repair commands executed")
    if grub_path and grub_path.read_bytes() != grub_bytes:
        raise ValueError("GRUB changed during preflight; no repair commands executed")
    if save_needed:
        for prefix, gateway in addresses:
            if management_config(running, [(prefix, gateway)]) != running:
                run_command(["config", "interface", "ip", "add", "eth0", prefix, gateway])
        if read_running() != desired:
            raise ValueError("Running CONFIG_DB does not match the plan; stop and use the console to investigate")
        run_command(["config", "save", "-y"])
        if parse_config(config_path.read_bytes()) != desired:
            raise ValueError("config save readback does not match CONFIG_DB; backups are listed above")
    if grub_needed:
        if grub_path.read_bytes() != grub_bytes:
            raise ValueError("GRUB changed while management settings were saved; refusing to overwrite it")
        atomic_write(grub_path, wanted_grub)
        if grub_path.read_bytes() != wanted_grub:
            raise ValueError("GRUB readback failed; backup is listed above")
    print("Persisted settings verified. No reload or reboot performed.", flush=True)
    return plan


def main():
    """Run locally on the named SONiC device; default to a read-only preview."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hostname", required=True, help="Expected DUT hostname; refuses a different device")
    parser.add_argument("--ipv4-prefix")
    parser.add_argument("--ipv4-gateway")
    parser.add_argument("--ipv6-prefix")
    parser.add_argument("--ipv6-gateway")
    parser.add_argument("--set-console-9600", action="store_true", help="Only for a confirmed 9600-baud console link")
    parser.add_argument("--apply", action="store_true", help="Write settings; default is preview only")
    parser.add_argument(
        "--confirm-console-access", action="store_true",
        help="Confirm this runs through working console access",
    )
    args = parser.parse_args()
    try:
        addresses = []
        for version in (4, 6):
            prefix = getattr(args, "ipv{}_prefix".format(version))
            gateway = getattr(args, "ipv{}_gateway".format(version))
            if bool(prefix) != bool(gateway):
                raise ValueError("IPv{} requires both prefix and gateway".format(version))
            if prefix:
                addresses.append(address_pair(prefix, gateway, version))
        if not addresses and not args.set_console_9600:
            raise ValueError("Specify a management prefix/gateway pair or --set-console-9600")
        if args.apply and (not hasattr(os, "geteuid") or os.geteuid() != 0):
            raise ValueError("Apply must run as root on the selected SONiC device")
        from sonic_py_common import multi_asic
        if multi_asic.is_multi_asic():
            raise ValueError("Multi-ASIC devices require a namespace-aware procedure; this helper refuses them")
        repair(args.hostname, addresses, args.set_console_9600, args.apply, args.confirm_console_access)
        return 0
    except (OSError, ValueError, ImportError, subprocess.CalledProcessError) as error:
        print("ERROR: {}. If writes began, use the listed backups and console; do not reboot.".format(error),
              file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError) and error.stderr:
            print(error.stderr.strip(), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
