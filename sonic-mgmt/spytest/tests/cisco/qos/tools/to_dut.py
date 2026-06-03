#!/usr/bin/env python3
"""
Push config_db.json to SONiC DUTs defined in a testbed YAML.

Usage:
    python3 to_dut.py --yaml <testbed.yaml> --config-dir <directory>

Copies config to /tmp on each DUT, then prompts whether to activate
(cp to /etc/sonic/ + config reload -y).

Expects config files named after each DUT (e.g., spine0, leaf0) in the config directory.
"""
import sys
import os
import re
import argparse
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

SSH_OPTS = ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password",
            "-o", "ConnectTimeout=10", "-o", "LogLevel=ERROR"]


def parse_testbed_yaml(yaml_path):
    """Parse testbed YAML and extract DUT information using regex."""
    with open(yaml_path, 'r') as f:
        content = f.read()

    duts = []
    
    # Pattern matches device blocks with device_type: DevSonic
    # Note: use \bpassword to avoid matching 'altpassword'
    device_pattern = re.compile(
        r'^    (\w+):.*\n'                                                      # device name
        r'        device_type:\s*DevSonic\s*\n'                                 # device_type
        r'        access:\s*\{[^}]*ip:\s*([^,\}\s]+)[^}]*\}\s*\n'               # access
        r'        credentials:\s*\{[^}]*username:\s*([^,\}\s]+)[^}]*\bpassword:\s*([^,\}\s]+)',
        re.MULTILINE
    )
    
    for match in device_pattern.finditer(content):
        duts.append({
            'name': match.group(1).strip(),
            'ip': match.group(2).strip(),
            'user': match.group(3).strip(),
            'pass': match.group(4).strip(),
        })

    return duts


def resolve_path(path):
    """Resolve a path to absolute."""
    if os.path.isabs(path):
        return path
    return os.path.join(os.getcwd(), path)


def run_cmd(dut, cmd):
    """Run a command on a DUT via sshpass + ssh."""
    full_cmd = ["sshpass", "-p", dut["pass"], "ssh"] + SSH_OPTS + [
        f"{dut['user']}@{dut['ip']}", cmd
    ]
    r = subprocess.run(full_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       universal_newlines=True, timeout=60)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def push_to_tmp(dut, src_path):
    """Copy config to /tmp on a single DUT. Returns (name, success, message)."""
    full_cmd = ["sshpass", "-p", dut["pass"], "scp"] + SSH_OPTS + [
        src_path, f"{dut['user']}@{dut['ip']}:/tmp/config_db.json"
    ]
    r = subprocess.run(full_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       universal_newlines=True, timeout=60)
    if r.returncode != 0:
        return dut["name"], False, f"scp failed: {r.stderr.strip()}"
    return dut["name"], True, "OK"


def activate_config(dut):
    """Activate config on a single DUT. Returns (name, success, message)."""
    rc, _, err = run_cmd(dut, "sudo cp /tmp/config_db.json /etc/sonic/config_db.json")
    if rc != 0:
        return dut["name"], False, f"cp failed: {err}"

    try:
        rc, _, err = run_cmd(dut, "sudo config reload -y")
    except subprocess.TimeoutExpired:
        # config reload restarts services and often kills the SSH session;
        # a timeout or disconnect here is expected, not a failure.
        return dut["name"], True, "OK (SSH disconnected during reload — expected)"

    # Non-zero rc with empty stderr almost always means the SSH session was
    # dropped by the reload (services restarting).  Treat it as success.
    if rc != 0 and not err:
        return dut["name"], True, "OK (SSH disconnected during reload — expected)"
    if rc != 0:
        return dut["name"], False, f"config reload failed: {err}"

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
        description="Push config_db.json to SONiC DUTs from testbed YAML"
    )
    parser.add_argument(
        "--yaml", required=True,
        help="Path to testbed YAML file"
    )
    parser.add_argument(
        "--config-dir", required=True,
        help="Directory containing config files (named after each DUT)"
    )
    parser.add_argument(
        "--yes", "-y", action="store_true",
        help="Auto-confirm activation (non-interactive mode)"
    )
    args = parser.parse_args()

    yaml_path = resolve_path(args.yaml)
    srcdir = resolve_path(args.config_dir)

    # Verify YAML file exists
    if not os.path.isfile(yaml_path):
        print(f"ERROR: testbed YAML not found: {yaml_path}")
        sys.exit(1)

    # Parse testbed YAML to get DUTs
    DUTS = parse_testbed_yaml(yaml_path)
    if not DUTS:
        print(f"ERROR: No DevSonic devices found in {yaml_path}")
        sys.exit(1)

    # Verify source directory exists
    if not os.path.isdir(srcdir):
        print(f"ERROR: config directory not found: {srcdir}")
        sys.exit(1)

    # Filter DUTs to only those with config files present
    duts_with_configs = []
    for dut in DUTS:
        src = os.path.join(srcdir, dut["name"])
        if os.path.isfile(src):
            duts_with_configs.append(dut)
        else:
            print(f"WARNING: No config file for {dut['name']} (expected: {src})")

    if not duts_with_configs:
        print(f"ERROR: No config files found in {srcdir}")
        sys.exit(1)

    DUTS = duts_with_configs

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

    # Step 2: Prompt to activate (or auto-confirm with --yes)
    if args.yes:
        resp = "y"
        print(f"\nActivating config on all DUTs (--yes specified)...")
    else:
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
