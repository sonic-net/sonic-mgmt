#!/usr/bin/env python3
"""
Push config_db.json to Gamut DUTs (spine0, leaf0, leaf1).

Usage:
    python3 to_dut.py                    # push from gamut_2x2_base_configs/
    python3 to_dut.py <directory>         # push from specified directory

Copies config to /tmp on each DUT, then prompts whether to activate
(cp to /etc/sonic/ + config reload -y).

Expects files named spine0, leaf0, leaf1 in the source directory.
"""
import sys
import os
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import paramiko

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG_DIR = os.path.join(SCRIPT_DIR, "gamut_2x2_base_configs")

DUTS = [
    {"name": "spine0", "ip": "172.25.168.173", "user": "cisco", "pass": "cisco123"},
    {"name": "leaf0",  "ip": "172.25.168.174", "user": "cisco", "pass": "cisco123"},
    {"name": "leaf1",  "ip": "172.25.168.175", "user": "cisco", "pass": "cisco123"},
]


def resolve_dir(arg):
    """Resolve the config directory from user input or default."""
    if arg is None:
        return DEFAULT_CONFIG_DIR
    if os.path.isabs(arg):
        return arg
    return os.path.join(os.getcwd(), arg)


def ssh_connect(dut):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        dut["ip"], username=dut["user"], password=dut["pass"],
        look_for_keys=False, allow_agent=False
    )
    return ssh


def run_cmd(ssh, cmd):
    _, stdout, stderr = ssh.exec_command(cmd, get_pty=True)
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    rc = stdout.channel.recv_exit_status()
    return rc, out, err


def push_to_tmp(dut, src_path):
    """Copy config to /tmp on a single DUT. Returns (name, success, message)."""
    ssh = ssh_connect(dut)
    sftp = ssh.open_sftp()
    sftp.put(src_path, "/tmp/config_db.json")
    sftp.close()
    ssh.close()
    return dut["name"], True, "OK"


def activate_config(dut):
    """Activate config on a single DUT. Returns (name, success, message)."""
    ssh = ssh_connect(dut)

    rc, _, err = run_cmd(ssh, "sudo cp /tmp/config_db.json /etc/sonic/config_db.json")
    if rc != 0:
        ssh.close()
        return dut["name"], False, f"cp failed: {err}"

    rc, _, err = run_cmd(ssh, "sudo config reload -y")
    if rc != 0:
        ssh.close()
        return dut["name"], False, f"config reload failed: {err}"

    ssh.close()
    return dut["name"], True, "OK"


def run_parallel(func, duts, **kwargs):
    """Run func for each DUT in parallel and print results."""
    futures = {}
    with ThreadPoolExecutor(max_workers=len(duts)) as pool:
        for dut in duts:
            futures[pool.submit(func, dut, **kwargs)] = dut["name"]

        for future in as_completed(futures):
            try:
                name, ok, msg = future.result()
                status = msg if ok else f"FAILED: {msg}"
                print(f"  {name}: {status}")
            except Exception as e:
                print(f"  {futures[future]}: FAILED: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Push config_db.json to Gamut DUTs"
    )
    parser.add_argument(
        "directory", nargs="?", default=None,
        help="Source directory (default: gamut_2x2_base_configs/ next to this script)"
    )
    args = parser.parse_args()

    srcdir = resolve_dir(args.directory)

    # Verify source directory and files
    if not os.path.isdir(srcdir):
        print(f"ERROR: directory not found: {srcdir}")
        sys.exit(1)

    for dut in DUTS:
        src = os.path.join(srcdir, dut["name"])
        if not os.path.isfile(src):
            print(f"ERROR: {src} not found")
            sys.exit(1)

    # Show what will be pushed
    print(f"=== Pushing configs from {srcdir} ===\n")
    for dut in DUTS:
        src_path = os.path.join(srcdir, dut["name"])
        size = os.path.getsize(src_path)
        print(f"  {dut['name']} ({dut['ip']}) [{size:,} bytes]")

    # Step 1: Copy to /tmp on all DUTs in parallel
    print(f"\nCopying to /tmp on all DUTs...")
    futures = {}
    with ThreadPoolExecutor(max_workers=len(DUTS)) as pool:
        for dut in DUTS:
            src_path = os.path.join(srcdir, dut["name"])
            futures[pool.submit(push_to_tmp, dut, src_path)] = dut["name"]

        for future in as_completed(futures):
            try:
                name, ok, msg = future.result()
                status = msg if ok else f"FAILED: {msg}"
                print(f"  {name}: {status}")
            except Exception as e:
                print(f"  {futures[future]}: FAILED: {e}")

    # Step 2: Prompt to activate
    print(f"\nActivate config on all DUTs?")
    print(f"  This will copy /tmp/config_db.json -> /etc/sonic/config_db.json")
    print(f"  and run 'config reload -y' on each DUT.")
    resp = input("\nProceed? (y/N): ").strip().lower()
    if resp != "y":
        print("Configs left in /tmp/config_db.json on each DUT.")
        print("To activate manually, SSH to each DUT and run:")
        print("  sudo cp /tmp/config_db.json /etc/sonic/config_db.json")
        print("  sudo config reload -y   # or reboot")
        sys.exit(0)

    # Step 3: Activate on all DUTs in parallel
    print(f"\nActivating configs...")
    run_parallel(activate_config, DUTS)
    print("\nDone.")


if __name__ == "__main__":
    main()
