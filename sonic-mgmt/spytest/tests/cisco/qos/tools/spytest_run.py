#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SPYtest Job Runner

Upgrades DUTs, pushes base configs, runs tests via run_test.sh, transfers logs
to server, and publishes results to dashboard.

Usage:
    ./spytest_run.py --testbed 10002 --url <image_url>
    ./spytest_run.py --testbed 10001 --test scheduler/test_v4_dwrr_1node.py
    ./spytest_run.py --testbed 10002 --url <url> --schedule 2

All testbed-specific config (NPU, profile, docker image, base configs, etc.)
is looked up from testbed_config.py using the YAML filename.
Repo root is auto-discovered by walking up from the YAML path.
"""

import argparse
import glob
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

# Python 3.6 compat: capture_output and text were added in 3.7
_subprocess_run = subprocess.run
def _run(*args, **kwargs):
    if kwargs.pop('capture_output', False):
        kwargs.setdefault('stdout', subprocess.PIPE)
        kwargs.setdefault('stderr', subprocess.PIPE)
    if 'text' in kwargs:
        kwargs['universal_newlines'] = kwargs.pop('text')
    return _subprocess_run(*args, **kwargs)
subprocess.run = _run

import yaml
from testbed_config import get_config as get_tb_config, discover_repo, find_testbed_yaml, TESTBED_IDS
from testbed import check_lock

# ── Constants ────────────────────────────────────────────────────────────

SCRIPT_DIR = Path(__file__).resolve().parent
UPGRADE_SCRIPT = SCRIPT_DIR / "upgrade_on_dut.sh"
RUNNER_SCRIPT = SCRIPT_DIR / "run_test.sh"
TO_DUT_SCRIPT = SCRIPT_DIR / "to_dut.py"
PUBLISH_SCRIPT = SCRIPT_DIR / "spytest_publish.py"
BASE_CONFIGS_DIR = SCRIPT_DIR.parent / "dut_configs"
DEFAULT_LOG_DIR = Path.home() / "spytest" / "logs"

# ── Log server and dashboard (hardcoded for simplicity) ──
import base64 as _b64
LOG_SERVER = {
    "host": "sonic-ucs-m6-51",
    "user": "sonic",
    "password": _b64.b64decode("cm9aZXNAMTIz").decode(),
    "base_path": "/home/sonic/test_logs_central/spytest_logs",
}
DASHBOARD_URL = "http://sonic-ucs-m6-51:5005"

os.environ["TZ"] = "America/New_York"
time.tzset()

# ── Logging setup ────────────────────────────────────────────────────────

class ColorFormatter(logging.Formatter):
    """Color log output when on a TTY, plain when piped/cron."""
    COLORS = {
        logging.DEBUG:    "\033[0;36m",   # cyan
        logging.INFO:     "\033[0;32m",   # green
        logging.WARNING:  "\033[1;33m",   # yellow
        logging.ERROR:    "\033[0;31m",   # red
        logging.CRITICAL: "\033[1;31m",   # bold red
    }
    RESET = "\033[0m"

    def __init__(self, use_color=True):
        super().__init__("%(asctime)s %(message)s", datefmt="%H:%M:%S")
        self.use_color = use_color

    def format(self, record):
        msg = super().format(record)
        if self.use_color:
            color = self.COLORS.get(record.levelno, "")
            return f"{color}{msg}{self.RESET}"
        return msg


def setup_logging(log_file: Path):
    """Configure logging to stdout + file."""
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    # Console handler (colors if TTY)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(ColorFormatter(use_color=sys.stdout.isatty()))
    logger.addHandler(ch)

    # File handler (no colors)
    log_file.parent.mkdir(parents=True, exist_ok=True)
    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(ColorFormatter(use_color=False))
    logger.addHandler(fh)

    return logger

log = logging.getLogger(__name__)

# ── SSH / SCP helpers ────────────────────────────────────────────────────

SSH_OPTS = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "PreferredAuthentications=password",
    "-o", "PubkeyAuthentication=no",
    "-o", "ConnectTimeout=10",
]


def remote_ssh(host, user, password, cmd, timeout=60):
    """Run a command on a remote host via sshpass + ssh."""
    full_cmd = ["sshpass", "-p", password, "ssh"] + SSH_OPTS + [f"{user}@{host}", cmd]
    return subprocess.run(full_cmd, capture_output=True, text=True, timeout=timeout)


def remote_scp(host, user, password, src, dst, recursive=False, timeout=300):
    """Copy files to a remote host via sshpass + scp."""
    flags = ["-r"] if recursive else []
    full_cmd = (
        ["sshpass", "-p", password, "scp"]
        + flags + SSH_OPTS
        + ["-o", "ConnectTimeout=30"]
        + [str(src), f"{user}@{host}:{dst}"]
    )
    return subprocess.run(full_cmd, capture_output=True, text=True, timeout=timeout)


def is_host_reachable(host, user, password, retries=3, delay=10):
    """Quick SSH check with retries."""
    for attempt in range(retries):
        try:
            r = remote_ssh(host, user, password, "echo ok", timeout=30)
            if r.returncode == 0:
                return True
            # Log failure details for debugging
            if attempt < retries - 1:
                log.debug("  SSH to %s failed (attempt %d/%d): %s", host, attempt + 1, retries, r.stderr.strip())
                time.sleep(delay)
        except subprocess.TimeoutExpired:
            if attempt < retries - 1:
                log.debug("  SSH to %s timed out (attempt %d/%d)", host, attempt + 1, retries)
                time.sleep(delay)
        except Exception as e:
            if attempt < retries - 1:
                log.debug("  SSH to %s error (attempt %d/%d): %s", host, attempt + 1, retries, e)
                time.sleep(delay)
    return False

# ── Build ID from DUT ────────────────────────────────────────────────────

def get_version_info_from_dut(dut):
    """SSH to a DUT and extract branch + build ID from 'show version'.

    Parses output like:
      SONiC Software Version: SONiC.202405c.2.2.7-369I-40506-20260430.210246
    Returns (branch, build_id) e.g. ('202405c', '40506'), or (None, None).
    """
    try:
        r = remote_ssh(dut["ip"], dut["user"], dut["password"],
                       "show version | grep 'SONiC Software Version'", timeout=15)
        if r.returncode == 0 and r.stdout.strip():
            # Extract branch: SONiC.<branch>.
            branch_m = re.search(r'SONiC\.(\w+)\.', r.stdout)
            # Extract build ID: 4-6 digit number before 8-digit date
            build_m = re.search(r'-(\d{4,6})-\d{8}', r.stdout)
            branch = branch_m.group(1) if branch_m else None
            build_id = build_m.group(1) if build_m else None
            return branch, build_id
    except Exception:
        pass
    return None, None


def _write_version_info(log_dir, branch, build_id):
    """Write branch/build to version_info.txt so publish can read it standalone."""
    try:
        path = os.path.join(log_dir, "version_info.txt")
        with open(path, "w") as f:
            f.write(f"branch={branch}\nbuild={build_id}\n")
    except Exception:
        pass

# ── URL parsing ──────────────────────────────────────────────────────────

def parse_image_url(url):
    """Extract branch and build_id from image URL filename.

    Example filename:
      sonic-buildimage-cisco.202405c.2.tortuga...periodic-39253-fd5207b58...tar.gz
    Returns:
      ("202405c", "39253")
    """
    fname = os.path.basename(url)

    # Branch: first field after 'cisco.'
    m = re.search(r"cisco\.([^.]+)\.", fname)
    branch = m.group(1) if m else "unknown"

    # Build ID: 4-6 digit number before a 20+ char hex commit hash
    m = re.search(r"-(\d{4,6})-[0-9a-f]{20,}\.tar", fname)
    build_id = m.group(1) if m else "unknown"

    return branch, build_id

# ── YAML testbed parsing ─────────────────────────────────────────────────

def _include_constructor(loader, node):
    return None

yaml.add_constructor("!include", _include_constructor, Loader=yaml.SafeLoader)


def parse_duts_from_yaml(yaml_path):
    """Return list of dicts: {name, ip, user, password} for DevSonic devices."""
    with open(yaml_path) as f:
        data = yaml.safe_load(f)

    duts = []
    for name, dev in data.get("devices", {}).items():
        if dev.get("device_type") == "DevSonic":
            duts.append({
                "name": name,
                "ip": dev["access"]["ip"],
                "user": dev["credentials"]["username"],
                "password": dev["credentials"]["password"],
            })
    return duts

# ── Git ──────────────────────────────────────────────────────────────────

_pulled_repos = set()


def git_pull_repo(repo_dir, branch=None):
    """Reset repo to clean state and pull latest.
    Assumes repo already exists at repo_dir."""
    repo_str = str(repo_dir)
    if repo_str in _pulled_repos:
        log.info("  Repo already updated: %s (skipping)", repo_dir)
        return True

    # Fetch latest from origin
    log.info("  git fetch origin ...")
    r = subprocess.run(
        ["git", "fetch", "origin"],
        cwd=repo_dir, capture_output=True, text=True, timeout=120,
    )
    if r.returncode != 0:
        log.warning("  git fetch failed: %s", r.stderr.strip())

    # Checkout branch if specified
    if branch:
        log.info("  git checkout %s ...", branch)
        r = subprocess.run(
            ["git", "checkout", branch],
            cwd=repo_dir, capture_output=True, text=True, timeout=60,
        )
        if r.returncode != 0:
            log.warning("  git checkout %s failed: %s", branch, r.stderr.strip())

    # Get current branch name
    r = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        cwd=repo_dir, capture_output=True, text=True, timeout=10,
    )
    current_branch = r.stdout.strip() if r.returncode == 0 else "master"

    # Pull latest (preserves local commits)
    log.info("  git pull --ff-only origin/%s ...", current_branch)
    r = subprocess.run(
        ["git", "pull", "--ff-only", "origin", current_branch],
        cwd=repo_dir, capture_output=True, text=True, timeout=60,
    )
    if r.returncode == 0:
        log.info("  ✓ Repo updated (origin/%s)", current_branch)
    else:
        # ff-only failed (local commits ahead) — that's fine, keep as-is
        log.info("  Local commits ahead of origin — keeping as-is")
    _pulled_repos.add(repo_str)

    return repo_str in _pulled_repos

# ── DUT upgrade ──────────────────────────────────────────────────────────

def upgrade_dut(dut, url):
    """SCP upgrade script to DUT and run it (triggers reboot)."""
    log.info("Upgrading %s (%s) with %s", dut["name"], dut["ip"], os.path.basename(url))

    # Copy upgrade script
    log.info("  Copying upgrade script to %s...", dut["name"])
    r = remote_scp(dut["ip"], dut["user"], dut["password"], UPGRADE_SCRIPT, "/tmp/upgrade_on_dut.sh")
    if r.returncode != 0:
        log.error("  SCP failed: %s", r.stderr.strip())
        return False

    # Run upgrade (SSH will disconnect during reboot — that's expected)
    log.info("  Running upgrade on %s (triggers reboot)...", dut["name"])
    try:
        remote_ssh(
            dut["ip"], dut["user"], dut["password"],
            f"chmod +x /tmp/upgrade_on_dut.sh && sudo /tmp/upgrade_on_dut.sh --url '{url}'",
            timeout=600,
        )
    except subprocess.TimeoutExpired:
        log.info("  SSH timed out (expected during reboot)")
    return True


def wait_for_dut(dut, max_wait=600, interval=30):
    """Wait for DUT to become SSH-reachable after reboot."""
    log.info("Waiting for %s (%s) to come back online...", dut["name"], dut["ip"])
    elapsed = 0
    polls = 0
    while elapsed < max_wait:
        # Single attempt per poll — no inner retries during reboot wait
        if is_host_reachable(dut["ip"], dut["user"], dut["password"], retries=1):
            log.info("  ✓ %s is back after %ds", dut["name"], elapsed)
            return True
        polls += 1
        if polls % 4 == 0:
            log.info("  %s still rebooting (%ds elapsed)...", dut["name"], elapsed)
        time.sleep(interval)
        elapsed += interval
    log.error("  ✗ %s did not come back within %ds", dut["name"], max_wait)
    return False


def wait_for_containers(dut, max_wait=180, interval=10):
    """Wait for critical SONiC containers to be running."""
    critical_containers = ["swss", "bgp", "syncd"]
    log.info("  Waiting for containers on %s...", dut["name"])
    elapsed = 0
    while elapsed < max_wait:
        try:
            r = remote_ssh(dut["ip"], dut["user"], dut["password"],
                          "docker ps --format '{{.Names}}' 2>/dev/null | grep -E 'swss|bgp|syncd' | wc -l",
                          timeout=15)
            if r.returncode == 0:
                count = int(r.stdout.strip() or "0")
                if count >= len(critical_containers):
                    log.info("    ✓ %s: containers ready (%ds)", dut["name"], elapsed)
                    return True
        except Exception:
            pass
        time.sleep(interval)
        elapsed += interval
    log.warning("    ⚠ %s: containers not all up after %ds (continuing)", dut["name"], max_wait)
    return False

# ── Log transfer ─────────────────────────────────────────────────────────

def transfer_and_cleanup_logs(tb, local_log_dir, branch, build_id, log_server, tb_config):
    """SCP run logs to central server.

    If the build directory already contains logs from a previous run,
    a numbered subdirectory (run2, run3, ...) is created automatically.
    Returns the final remote path used (or None on failure).
    """
    if not os.path.isdir(local_log_dir):
        log.warning("No local log dir: %s", local_log_dir)
        return None

    srv = log_server

    # Path: <base>/<profile>/<platform>/<build_id>/
    # e.g. /home/sonic/test_logs_central/spytest_logs/202405c-Tortuga/g200/40506/
    profile_suffix = tb_config.get("profile_suffix", "Unknown")
    profile = f"{branch}-{profile_suffix}" if branch != "unknown" else profile_suffix
    base_remote_path = f"{srv['base_path']}/{profile}/{tb}/{build_id}"

    # Check if the directory already has content from a previous run
    r = remote_ssh(srv["host"], srv["user"], srv["password"],
                   f"ls '{base_remote_path}/' 2>/dev/null | head -1", timeout=15)
    if r.returncode == 0 and r.stdout.strip():
        # Directory exists and has content — find the highest existing runN directory
        r2 = remote_ssh(srv["host"], srv["user"], srv["password"],
                        f"ls -d '{base_remote_path}'/run[0-9]* 2>/dev/null | grep -oP 'run\\K[0-9]+' | sort -n | tail -1",
                        timeout=15)
        if r2.returncode == 0 and r2.stdout.strip().isdigit():
            # runN directories exist — use next number
            next_run = int(r2.stdout.strip()) + 1
        else:
            # No runN dirs yet — existing content is implicitly run1, new goes to run2
            next_run = 2

        remote_path = f"{base_remote_path}/run{next_run}"
        log.info("Build %s already has logs — using %s", build_id, remote_path)
    else:
        remote_path = base_remote_path

    log.info("Transferring logs → %s:%s", srv["host"], remote_path)

    # Create remote directory
    r = remote_ssh(srv["host"], srv["user"], srv["password"], f"mkdir -p '{remote_path}'", timeout=30)
    if r.returncode != 0:
        log.error("Failed to create remote dir: %s", r.stderr.strip())
        return None

    # Remove .gz files before transfer to save time/space
    for gz in glob.glob(os.path.join(local_log_dir, "**", "*.gz"), recursive=True):
        try:
            os.remove(gz)
        except OSError:
            pass

    # SCP contents of log dir directly into remote_path (no extra subdirectory)
    scp_cmd = (
        f"sshpass -p '{srv['password']}' scp -r -o StrictHostKeyChecking=no "
        f"-o UserKnownHostsFile=/dev/null -o ConnectTimeout=30 "
        f"{local_log_dir}/* {srv['user']}@{srv['host']}:{remote_path}/"
    )
    r = subprocess.run(scp_cmd, shell=True, capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        log.error("SCP failed: %s", r.stderr.strip())
        return None

    log.info("  ✓ Logs transferred")
    return remote_path


def cleanup_local_logs(local_log_dir):
    """Remove local log directory after publish is done."""
    if not os.path.isdir(local_log_dir):
        return
    # chmod first so rm doesn't need sudo (docker creates root-owned files)
    subprocess.run(["chmod", "-R", "777", str(local_log_dir)], capture_output=True, text=True)
    rm = subprocess.run(["rm", "-rf", str(local_log_dir)], capture_output=True, text=True)
    if rm.returncode != 0:
        log.warning("  Could not remove local logs (root-owned): %s", local_log_dir)
    else:
        log.info("  ✓ Local logs removed: %s", local_log_dir)

# ── Run one testbed ──────────────────────────────────────────────────────

def run_one_testbed(yaml_file, cfg, tb_config):
    """Run full pipeline for one testbed. Returns (success: bool, duration_min: int).

    Args:
        yaml_file: Path to testbed YAML.
        cfg: Dict with keys: image_url, spine_image_url, test,
             skip_config, branch.
        tb_config: Dict from testbed_config.get_config() with runner_platform,
                   profile_suffix, npu, base_config_dir, etc.
    """
    start = time.time()
    yaml_file = Path(yaml_file).resolve()
    tb = yaml_file.stem  # for log messages

    # Auto-discover repo and spytest dir from YAML path
    try:
        repo_dir, spytest_dir = discover_repo(yaml_file)
    except ValueError as e:
        log.error("%s", e)
        return False, 0

    if not yaml_file.is_file():
        log.error("Testbed YAML not found: %s", yaml_file)
        return False, 0

    image_url = cfg.get("image_url", "")
    spine_url = cfg.get("spine_image_url", "")
    test = cfg.get("test", "full")
    skip_upgrade = not image_url

    tb_branch, tb_build_id = parse_image_url(image_url) if image_url else ("unknown", "unknown")

    log.info("=" * 64)
    log.info("  YAML:    %s", yaml_file)
    log.info("  Repo:    %s", repo_dir)
    log.info("  Test:    %s", test)
    if not skip_upgrade:
        log.info("  Image:   %s", os.path.basename(image_url))
        if spine_url:
            log.info("  Spine:   %s", os.path.basename(spine_url))
    log.info("=" * 64)

    # ── Testbed reservation check ──
    if not check_lock(yaml_file.name):
        log.error("No valid reservation. Aborting.")
        return False, 0

    # ── Phase 0: Update repo ──
    log.info("═══ Phase 0: Updating repo ═══")
    branch = cfg.get("branch", "")
    git_pull_repo(repo_dir, branch=branch if branch else None)

    # Apply pre-patch if configured
    pre_patch = cfg.get("pre_patch", "")
    if pre_patch:
        log.info("  Applying pre-patch: %s", pre_patch)
        r = subprocess.run(
            ["git", "apply", pre_patch],
            cwd=repo_dir, capture_output=True, text=True, timeout=30,
        )
        if r.returncode == 0:
            log.info("  ✓ Patch applied")
        else:
            log.warning("  Patch apply failed (continuing): %s", r.stderr.strip())

    # Parse DUTs
    duts = parse_duts_from_yaml(yaml_file)
    if not duts:
        log.error("No DUTs found in %s", yaml_file)
        return False, 0
    for d in duts:
        log.info("  DUT: %s (%s)", d["name"], d["ip"])

    # HACK: On gamut testbed, skip upgrading spine1 (Superbolt) — only upgrade spine0, leaf0, leaf1
    if tb_config.get("runner_platform") == "gamut":
        upgrade_duts = [d for d in duts if d["name"] != "spine1"]
        log.info("  [HACK] Gamut: skipping spine1 upgrade. Upgrading: %s",
                 [d["name"] for d in upgrade_duts])
    else:
        upgrade_duts = duts

    # ── Phase 1: Upgrade ──
    if not skip_upgrade:
        log.info("═══ Phase 1: Upgrading %d DUTs (parallel) ═══", len(upgrade_duts))

        # Check reachability (parallel)
        def check_reachable(d):
            ok = is_host_reachable(d["ip"], d["user"], d["password"])
            return d, ok

        with ThreadPoolExecutor(max_workers=len(upgrade_duts)) as pool:
            futures = [pool.submit(check_reachable, d) for d in upgrade_duts]
            for f in as_completed(futures):
                d, ok = f.result()
                if not ok:
                    log.error("%s (%s) is unreachable. Skipping %s.", d["name"], d["ip"], tb)
                    return False, int((time.time() - start) / 60)
                log.info("  ✓ %s reachable", d["name"])

        # Upgrade all DUTs in parallel
        def do_upgrade(d):
            url = image_url
            if spine_url and d["name"].startswith("spine"):
                url = spine_url
            upgrade_dut(d, url)
            return d

        with ThreadPoolExecutor(max_workers=len(upgrade_duts)) as pool:
            futures = [pool.submit(do_upgrade, d) for d in upgrade_duts]
            for f in as_completed(futures):
                d = f.result()
                log.info("  ✓ Upgrade initiated on %s", d["name"])

        # Wait for all DUTs in parallel
        log.info("Waiting for DUTs to reboot (parallel)...")

        def do_wait(d):
            ok = wait_for_dut(d)
            return d, ok

        failed = 0
        with ThreadPoolExecutor(max_workers=len(upgrade_duts)) as pool:
            futures = [pool.submit(do_wait, d) for d in upgrade_duts]
            for f in as_completed(futures):
                d, ok = f.result()
                if not ok:
                    failed += 1

        if failed:
            log.error("%d DUT(s) failed to come back. Skipping tests for %s.", failed, tb)
            return False, int((time.time() - start) / 60)

        # Print versions
        log.info("Post-upgrade versions:")
        for d in upgrade_duts:
            r = remote_ssh(d["ip"], d["user"], d["password"],
                           "show version | grep 'SONiC Software Version'", timeout=15)
            ver = r.stdout.strip() if r.returncode == 0 else "unknown"
            log.info("  %s: %s", d["name"], ver)

        # Wait for containers to come up after upgrade
        log.info("Waiting for containers to start (parallel)...")
        with ThreadPoolExecutor(max_workers=len(upgrade_duts)) as pool:
            futures = [pool.submit(wait_for_containers, d) for d in upgrade_duts]
            for f in as_completed(futures):
                f.result()  # Just wait, don't fail on warning
    else:
        log.info("═══ Phase 1: Upgrade SKIPPED ═══")

    # ── Phase 1.5: Push base configs ──
    skip_config = cfg.get("skip_config", False)
    base_config_dir_name = tb_config.get("base_config_dir", "")
    if not skip_config and base_config_dir_name:
        config_dir = BASE_CONFIGS_DIR / base_config_dir_name
        if config_dir.is_dir():
            log.info("═══ Phase 1.5: Pushing base configs ═══")
            log.info("  Config dir: %s", config_dir)
            # Call to_dut.py with --yes flag to auto-confirm
            push_cmd = [
                sys.executable, str(TO_DUT_SCRIPT),
                "--yaml", str(yaml_file),
                "--config-dir", str(config_dir),
                "--yes",
            ]
            log.info("  Running: %s", " ".join(push_cmd))
            push_proc = subprocess.run(push_cmd, capture_output=True, text=True)
            if push_proc.returncode == 0:
                log.info("  ✓ Base configs pushed successfully")
                if push_proc.stdout:
                    for line in push_proc.stdout.strip().split("\n"):
                        log.info("    %s", line)
                # Wait for containers to restart after config reload
                log.info("  Waiting for containers to restart...")
                time.sleep(30)  # Initial delay for config reload to trigger
                with ThreadPoolExecutor(max_workers=len(duts)) as pool:
                    futures = [pool.submit(wait_for_containers, d) for d in duts]
                    for f in as_completed(futures):
                        f.result()
            else:
                log.warning("  ✗ Failed to push configs (continuing anyway)")
                if push_proc.stderr:
                    log.warning("    %s", push_proc.stderr.strip())
        else:
            log.warning("  Config dir not found: %s (skipping)", config_dir)
    elif skip_config:
        log.info("═══ Phase 1.5: Base configs SKIPPED ═══")

    # ── Get real build ID and branch from DUT ──
    dut_branch, dut_build_id = get_version_info_from_dut(duts[0])
    if dut_build_id:
        log.info("Version from DUT: branch=%s build=%s", dut_branch, dut_build_id)
        tb_build_id = dut_build_id
        if dut_branch:
            tb_branch = dut_branch
    else:
        log.warning("Could not get version from DUT, using: branch=%s build=%s", tb_branch, tb_build_id)

    # ── Phase 2: Run tests ──
    log.info("═══ Phase 2: Running tests (%s) on %s ═══", test, tb)

    profile_suffix = tb_config.get("profile_suffix", "unknown")
    # Split test string into separate arguments for multiple tests
    test_args = test.split() if test else ["full"]
    cmd = [str(RUNNER_SCRIPT), "--yaml", str(yaml_file)] + test_args
    log.info("Running: %s", " ".join(cmd))

    test_proc = subprocess.run(cmd, cwd=spytest_dir, stdin=subprocess.DEVNULL)
    test_rc = test_proc.returncode

    # ── Phase 3: Transfer logs ──
    log.info("═══ Phase 3: Transferring logs ═══")
    # run_test.sh names the log dir using profile_suffix (lowercase)
    run_log_dirs = sorted(glob.glob(str(spytest_dir / f"run_logs_{profile_suffix.lower()}_*")), reverse=True)
    latest_log_dir = None
    remote_logs_path = None
    if run_log_dirs:
        latest_log_dir = run_log_dirs[0]
        # Write version info so standalone spytest_publish.py can find it
        _write_version_info(latest_log_dir, tb_branch, tb_build_id)
        if LOG_SERVER:
            remote_logs_path = transfer_and_cleanup_logs(
                tb, latest_log_dir, tb_branch, tb_build_id, LOG_SERVER, tb_config)
        else:
            log.warning("No log_server configured; logs remain at %s", latest_log_dir)
    else:
        log.warning("No run_logs directory found for %s (suffix=%s) under %s",
                    tb, profile_suffix.lower(), spytest_dir)

    # ── Phase 4: Publish to dashboard (before local cleanup) ──
    if cfg.get("publish") and latest_log_dir and os.path.isdir(latest_log_dir):
        log.info("═══ Phase 4: Publishing to dashboard ═══")

        publish_cmd = [
            sys.executable, str(PUBLISH_SCRIPT),
            "--yaml", yaml_file.name,
            "--branch", tb_branch,
            "--topo", "2x2",
            "--build", tb_build_id,
            "--skip-upload",  # Phase 3 already transferred logs; just generate XML + import
            "--no-cleanup",
        ]
        # Pass actual remote path so publish records the correct log location
        if remote_logs_path:
            publish_cmd += ["--logs-path", remote_logs_path]
        publish_cmd.append(latest_log_dir)
        log.info("  Running: %s", " ".join(publish_cmd))
        try:
            publish_proc = subprocess.run(publish_cmd, capture_output=True, text=True, timeout=300)
            if publish_proc.returncode == 0:
                log.info("  ✓ Published to dashboard")
                # Extract result IDs from output
                for line in publish_proc.stdout.split("\n"):
                    if "Result ID:" in line:
                        log.info("    %s", line.strip())
            else:
                log.warning("  ✗ Failed to publish to dashboard")
                if publish_proc.stderr:
                    log.warning("    %s", publish_proc.stderr.strip()[:200])
        except subprocess.TimeoutExpired:
            log.warning("  ✗ Publish timed out")
        except Exception as e:
            log.warning("  ✗ Publish failed: %s", e)
    else:
        log.info("═══ Phase 4: Publish SKIPPED (--publish not specified or no logs) ═══")

    # ── Cleanup local logs (after publish) ──
    if latest_log_dir and os.path.isdir(latest_log_dir):
        cleanup_local_logs(latest_log_dir)

    duration = int((time.time() - start) / 60)
    if test_rc == 0:
        log.info("✓ Testbed %s COMPLETE (%dm)", tb, duration)
    else:
        log.error("✗ Testbed %s FAILED (exit=%d, %dm)", tb, test_rc, duration)

    return test_rc == 0, duration


def schedule_run(args):
    """Create a crontab entry to run the script N hours from now."""
    from datetime import timedelta

    hours = args.schedule
    run_time = datetime.now() + timedelta(hours=hours)

    script_path = Path(__file__).resolve()
    cmd_parts = [sys.executable, str(script_path)]

    cmd_parts.extend(["--testbed", str(args.testbed)])
    if args.branch:
        cmd_parts.extend(["--branch", args.branch])
    if args.url:
        cmd_parts.extend(["--url", args.url])
    if args.spine_url:
        cmd_parts.extend(["--spine-url", args.spine_url])
    if args.skip_config:
        cmd_parts.append("--skip-config")
    if args.publish:
        cmd_parts.append("--publish")
    if args.test:
        cmd_parts.extend(["--test", args.test])
    
    cmd = " ".join(cmd_parts)
    
    # Crontab entry: minute hour day month weekday command
    cron_minute = run_time.minute
    cron_hour = run_time.hour
    cron_day = run_time.day
    cron_month = run_time.month
    
    # Log file for the scheduled run
    log_file = DEFAULT_LOG_DIR / f"scheduled_{run_time.strftime('%Y%m%d_%H%M')}.log"
    DEFAULT_LOG_DIR.mkdir(parents=True, exist_ok=True)
    
    cron_entry = f"{cron_minute} {cron_hour} {cron_day} {cron_month} * {cmd} >> {log_file} 2>&1"
    
    # Add to crontab
    try:
        # Get existing crontab
        result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        existing = result.stdout if result.returncode == 0 else ""
        
        # Add new entry
        new_crontab = existing.rstrip() + "\n" + cron_entry + "\n"
        
        # Install new crontab
        proc = subprocess.run(["crontab", "-"], input=new_crontab, text=True, capture_output=True)
        if proc.returncode != 0:
            print(f"ERROR: Failed to install crontab: {proc.stderr}", file=sys.stderr)
            sys.exit(1)
        
        print(f"Scheduled run for {run_time.strftime('%Y-%m-%d %H:%M %Z')} ({hours}h from now)")
        print(f"")
        print(f"Crontab entry added:")
        print(f"  {cron_entry}")
        print(f"")
        print(f"Log file: {log_file}")
        print(f"")
        print(f"To view scheduled jobs: crontab -l")
        print(f"To remove: crontab -e  (delete the line)")
        
    except Exception as e:
        print(f"ERROR: Failed to create crontab: {e}", file=sys.stderr)
        sys.exit(1)


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="SPYtest Job Runner — run QoS tests on a single testbed",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Testbed IDs:
""" + "\n".join(f"  {tid} = {desc} ({yname})" for tid, (yname, desc) in sorted(TESTBED_IDS.items())) + """

Testbed config (NPU, docker image, profile, etc.) is looked up from
testbed_config.py using the YAML filename. Repo root is auto-discovered
from the YAML path.

Examples:
  %(prog)s --testbed 10002 --url <image_url>
  %(prog)s --testbed 10001 --test scheduler/test_v4_dwrr_1node.py
  %(prog)s --testbed 10003 --url <url> --test full
  %(prog)s --testbed 10002 --url <url> --schedule 2
""",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--testbed", type=int, metavar="ID", help="Testbed ID (see list below)")
    group.add_argument("--yaml", help=argparse.SUPPRESS)  # internal/undocumented
    parser.add_argument("--branch", help="Git branch to checkout before running")
    parser.add_argument("--url", help="Image URL for DUT upgrade")
    parser.add_argument("--spine-url", help="Separate image URL for spines")
    parser.add_argument("--skip-config", action="store_true", help="Skip pushing base configs")
    parser.add_argument("--publish", action="store_true", help="Publish results to dashboard (default: no publish)")
    parser.add_argument("--test", default="full", help="Test file(s) or 'full' (default: full)")

    parser.add_argument("--schedule", type=float, metavar="HOURS",
                        help="Schedule run N hours from now (creates crontab entry and exits)")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    # Resolve --testbed <int> to YAML path
    if args.testbed is not None:
        entry = TESTBED_IDS.get(args.testbed)
        if not entry:
            parser.error(
                f"Unknown testbed ID: {args.testbed}\nValid IDs:\n" +
                "\n".join(f"  {tid} = {desc} ({yname})" for tid, (yname, desc) in sorted(TESTBED_IDS.items()))
            )
        yaml_name = entry[0]
        try:
            yaml_path = find_testbed_yaml(yaml_name)
        except ValueError as e:
            parser.error(str(e))
    else:
        yaml_path = Path(args.yaml).resolve()

    # Validate YAML exists
    if not yaml_path.is_file():
        parser.error(f"YAML file not found: {yaml_path}")

    # Look up testbed config
    tb_config = get_tb_config(yaml_path)
    if not tb_config:
        parser.error(
            f"Unknown testbed YAML: {yaml_path.name}\n"
            f"Add an entry to testbed_config.py for this file."
        )

    # Handle --schedule
    if args.schedule is not None:
        schedule_run(args)
        return

    # Build config dict from CLI args
    cfg = {
        "image_url": args.url or "",
        "spine_image_url": args.spine_url or "",
        "test": args.test,
        "skip_upgrade": not args.url,
        "skip_config": args.skip_config,
        "branch": args.branch or "",
        "publish": args.publish,
    }

    # Setup logging
    log_dir = Path(str(DEFAULT_LOG_DIR))
    log_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    master_log = log_dir / f"master_{ts}.log"
    setup_logging(master_log)

    # Banner
    log.info("=" * 64)
    log.info("  SPYtest Job Runner")
    log.info("  %s", datetime.now().strftime("%Y-%m-%d %H:%M:%S %Z"))
    log.info("")
    log.info("  YAML:     %s", yaml_path)
    log.info("  Profile:  %s", tb_config["profile_suffix"])
    log.info("  NPU:      %s", tb_config["npu"])
    log.info("  Test:     %s", cfg["test"])
    if cfg["image_url"]:
        b, bid = parse_image_url(cfg["image_url"])
        log.info("  Image:    %s (branch=%s build=%s)", os.path.basename(cfg["image_url"]), b, bid)
        if cfg["spine_image_url"]:
            log.info("  Spine:    %s", os.path.basename(cfg["spine_image_url"]))
    else:
        log.info("  Image:    (no --url, skipping upgrade)")
    log.info("  Log:      %s", master_log)
    log.info("=" * 64)

    try:
        success, duration = run_one_testbed(yaml_path, cfg, tb_config)
    except KeyboardInterrupt:
        log.warning("Interrupted (Ctrl-C).")
        success, duration = False, 0

    log.info("")
    log.info("=" * 64)
    log.info("  %s  %s  (%dm)", "✓ PASS" if success else "✗ FAIL", yaml_path.stem, duration)
    log.info("  Log: %s", master_log)
    log.info("=" * 64)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
