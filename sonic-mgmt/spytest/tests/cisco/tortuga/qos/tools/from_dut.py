#!/usr/bin/env python3
"""
Pull config_db.json from Gamut DUTs (spine0, leaf0, leaf1) to a local directory.

Usage:
    python3 from_dut.py <directory>    # save to specified directory

Saves files as: <directory>/spine0, <directory>/leaf0, <directory>/leaf1
"""
import sys
import os
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import paramiko

DUTS = [
    {"name": "spine0", "ip": "172.25.168.173", "user": "cisco", "pass": "cisco123"},
    {"name": "leaf0",  "ip": "172.25.168.174", "user": "cisco", "pass": "cisco123"},
    {"name": "leaf1",  "ip": "172.25.168.175", "user": "cisco", "pass": "cisco123"},
]


def resolve_dir(arg):
    """Resolve directory path from user input."""
    if os.path.isabs(arg):
        return arg
    return os.path.join(os.getcwd(), arg)


def scp_from(dut, dest_path):
    """Pull config_db.json from a single DUT. Returns (name, success, message)."""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        dut["ip"], username=dut["user"], password=dut["pass"],
        look_for_keys=False, allow_agent=False
    )
    sftp = ssh.open_sftp()
    sftp.get("/etc/sonic/config_db.json", dest_path)
    sftp.close()
    ssh.close()
    size = os.path.getsize(dest_path)
    return dut["name"], True, f"OK ({size:,} bytes)"


def main():
    parser = argparse.ArgumentParser(
        description="Pull config_db.json from Gamut DUTs"
    )
    parser.add_argument(
        "directory",
        help="Destination directory for config files"
    )
    args = parser.parse_args()

    destdir = resolve_dir(args.directory.rstrip("/"))

    # Warn if directory already has files
    if os.path.isdir(destdir) and os.listdir(destdir):
        print(f"WARNING: {destdir} already has files: {os.listdir(destdir)}")
        resp = input("Overwrite? (y/N): ").strip().lower()
        if resp != "y":
            print("Aborted.")
            sys.exit(0)

    os.makedirs(destdir, exist_ok=True)

    print(f"=== Pulling config_db.json from DUTs to {destdir} ===\n")

    futures = {}
    with ThreadPoolExecutor(max_workers=len(DUTS)) as pool:
        for dut in DUTS:
            dest_path = os.path.join(destdir, dut["name"])
            print(f"  {dut['name']} ({dut['ip']}) - started")
            futures[pool.submit(scp_from, dut, dest_path)] = dut["name"]

        print()
        for future in as_completed(futures):
            try:
                name, ok, msg = future.result()
                print(f"  {name}: {msg}")
            except Exception as e:
                print(f"  {futures[future]}: FAILED: {e}")

    print(f"\nDone. Files in {destdir}/")


if __name__ == "__main__":
    main()
