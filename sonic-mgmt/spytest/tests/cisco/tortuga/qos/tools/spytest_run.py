#!/usr/bin/env python3
"""
SPYtest Job Runner

Upgrades DUTs, pushes base configs, runs tests via run_test.sh, transfers logs to server.
Supports a sequential testbed queue (e.g. g200 → q200).

Usage:
    ./spytest_run.py                                       # Use default config
    ./spytest_run.py --config spytest_job.yaml             # Custom config
    ./spytest_run.py --testbed g200 q200 --url <url>       # CLI overrides
    ./spytest_run.py --skip-upgrade --testbed g200         # Test only
    ./spytest_run.py --schedule 2 --testbed g200           # Run 2 hours from now
"""

import argparse
import fcntl
import glob
import logging
import os
import re
import shutil
import subprocess
import sys
import time
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

import yaml

# ── Constants ────────────────────────────────────────────────────────────

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_CONF = Path.home() / "spytest" / "spytest_jobs.yaml"
UPGRADE_SCRIPT = SCRIPT_DIR / "upgrade_on_dut.sh"
RUNNER_SCRIPT = SCRIPT_DIR / "run_test.sh"
TO_DUT_SCRIPT = SCRIPT_DIR / "to_dut.py"
PUBLISH_SCRIPT = SCRIPT_DIR / "spytest_publish.py"
BASE_CONFIGS_DIR = SCRIPT_DIR.parent / "base_configs"
# Derive repo_base from script location: tools/ -> qos/ -> tortuga/ -> cisco/ -> tests/ -> spytest/ -> sonic-mgmt/ -> sonic-test/ -> REPO_BASE
DEFAULT_REPO_BASE = SCRIPT_DIR.parents[7]
DEFAULT_LOG_DIR = DEFAULT_REPO_BASE / "logs"
LOCK_FILE = Path("/tmp/spytest_run.lock")

# ── Log server and dashboard (hardcoded for simplicity) ──
import base64 as _b64
LOG_SERVER = {
    "host": "sonic-ucs-m6-51",
    "user": "sonic",
    "password": _b64.b64decode("cm9aZXNAMTIz").decode(),
    "base_path": "/home/sonic/test_logs_central/spytest_logs",
}
DASHBOARD_URL = "http://sonic-ucs-m6-51:5005"

# Testbed to base config directory mapping
BASE_CONFIG_MAP = {
    "g200": "laguna_2x2_configs",
    "laguna": "laguna_2x2_configs",
    "q200": "carib_siren_2x2_configs",
    "carib": "carib_siren_2x2_configs",
    "siren": "carib_siren_2x2_configs",
    "gamut": "gamut_2x2_configs",
}

os.environ["TZ"] = "America/New_York"
time.tzset()


def build_testbed_registry(repo_base):
    """Build testbed registry from a base directory containing repo clones."""
    base = Path(repo_base)
    sonic_test = base / "sonic-test"
    oci_repo = base / "oci-sonic-mgmt"

    return {
        "q200": {
            "spytest": sonic_test / "sonic-mgmt" / "spytest",
            "tb_dir":  sonic_test / "spytest_tb_files",
            "yaml":    "tortuga_2x2_Q200_testbed.yaml",
            "repo":    sonic_test,
            "runner_platform": "tortuga",
        },
        "g200": {
            "spytest": sonic_test / "sonic-mgmt" / "spytest",
            "tb_dir":  sonic_test / "spytest_tb_files",
            "yaml":    "tortuga_2x2_G200_testbed.yaml",
            "repo":    sonic_test,
            "runner_platform": "tortuga",
        },
        "gamut": {
            "spytest": sonic_test / "sonic-mgmt" / "spytest",
            "tb_dir":  sonic_test / "spytest_tb_files",
            "yaml":    "gamut_2x2_qos.yaml",
            "repo":    sonic_test,
            "runner_platform": "gamut",
        },
        "oci": {
            "spytest": oci_repo / "spytest",
            "tb_dir":  oci_repo / "spytest" / "testbeds",
            "yaml":    "rocev2_testbed.yaml",
            "repo":    oci_repo,
            "runner_platform": "oci",
        },
    }

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

    # Hard reset to origin (discard any local changes)
    log.info("  git reset --hard origin/%s ...", current_branch)
    r = subprocess.run(
        ["git", "reset", "--hard", f"origin/{current_branch}"],
        cwd=repo_dir, capture_output=True, text=True, timeout=60,
    )
    if r.returncode == 0:
        log.info("  ✓ Repo reset to origin/%s", current_branch)
        _pulled_repos.add(repo_str)
    else:
        log.warning("  git reset failed: %s", r.stderr.strip())

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


def wait_for_dut(dut, max_wait=600, interval=15):
    """Wait for DUT to become SSH-reachable after reboot."""
    log.info("Waiting for %s (%s) to come back online...", dut["name"], dut["ip"])
    elapsed = 0
    while elapsed < max_wait:
        if is_host_reachable(dut["ip"], dut["user"], dut["password"]):
            log.info("  ✓ %s is back after %ds", dut["name"], elapsed)
            return True
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

def transfer_and_cleanup_logs(tb, local_log_dir, branch, build_id, log_server, testbed_registry):
    """SCP run logs to central server."""
    if not os.path.isdir(local_log_dir):
        log.warning("No local log dir: %s", local_log_dir)
        return

    srv = log_server

    # Path: <base>/<profile>/<platform>/<build_id>/
    # e.g. /home/sonic/test_logs_central/spytest_logs/202405c-Tortuga/g200/40506/
    profile = f"{branch}-Tortuga" if branch != "unknown" else "Tortuga"
    remote_path = f"{srv['base_path']}/{profile}/{tb}/{build_id}"
    log.info("Transferring logs → %s:%s", srv["host"], remote_path)

    # Create remote directory
    r = remote_ssh(srv["host"], srv["user"], srv["password"], f"mkdir -p '{remote_path}'", timeout=30)
    if r.returncode != 0:
        log.error("Failed to create remote dir: %s", r.stderr.strip())
        return

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
        return

    log.info("  ✓ Logs transferred")


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

def run_one_testbed(tb, cfg, branch, build_id, testbed_registry):
    """Run full pipeline for one testbed. Returns (success: bool, duration_min: int)."""
    start = time.time()

    reg = testbed_registry.get(tb)
    if not reg:
        log.error("Unknown testbed: %s", tb)
        return False, 0

    spytest_dir = reg["spytest"]
    yaml_file = reg["tb_dir"] / reg["yaml"]

    # Pre-flight checks
    if not spytest_dir.is_dir():
        log.error("Spytest dir not found: %s", spytest_dir)
        return False, 0
    if not yaml_file.is_file():
        log.error("Testbed YAML not found: %s", yaml_file)
        return False, 0

    image_url = cfg.get("image_url", "")
    spine_url = cfg.get("spine_image_url", "")
    test = cfg.get("test", "full")
    skip_upgrade = cfg.get("skip_upgrade", False)
    log_server = LOG_SERVER

    # Per-testbed overrides (testbeds can be a dict with per-tb config)
    tb_cfg = cfg.get("_tb_config", {})
    if tb_cfg:
        image_url = tb_cfg.get("image_url", image_url)
        spine_url = tb_cfg.get("spine_image_url", spine_url)
        test = tb_cfg.get("test", test)
        skip_upgrade = tb_cfg.get("skip_upgrade", skip_upgrade)

    # Empty image_url handling:
    # - If skip_upgrade=false and no image_url → skip this testbed (no-op)
    # - If skip_upgrade=true and no image_url → run tests with existing image
    if not image_url and not skip_upgrade:
        log.info("Skipping testbed %s (no image_url configured)", tb)
        return True, 0  # Success, 0 duration - just skip

    # Parse branch/build_id from this testbed's image URL
    tb_branch, tb_build_id = parse_image_url(image_url) if image_url else (branch, build_id)

    log.info("=" * 64)
    log.info("  Testbed: %s", tb)
    log.info("  YAML:    %s", yaml_file.name)
    log.info("  Test:    %s", test)
    if not skip_upgrade:
        log.info("  Image:   %s", os.path.basename(image_url))
        if spine_url:
            log.info("  Spine:   %s", os.path.basename(spine_url))
    log.info("=" * 64)

    # ── Phase 0: Update repo ──
    log.info("═══ Phase 0: Updating repo ═══")
    branch = cfg.get("branch", "")
    git_pull_repo(reg["repo"], branch=branch if branch else None)

    # Apply pre-patch if configured
    pre_patch = cfg.get("pre_patch", "")
    if pre_patch:
        log.info("  Applying pre-patch: %s", pre_patch)
        r = subprocess.run(
            ["git", "apply", pre_patch],
            cwd=reg["repo"], capture_output=True, text=True, timeout=30,
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

    # ── Phase 1: Upgrade ──
    if not skip_upgrade:
        log.info("═══ Phase 1: Upgrading %d DUTs (parallel) ═══", len(duts))

        # Check reachability (parallel)
        def check_reachable(d):
            ok = is_host_reachable(d["ip"], d["user"], d["password"])
            return d, ok

        with ThreadPoolExecutor(max_workers=len(duts)) as pool:
            futures = [pool.submit(check_reachable, d) for d in duts]
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

        with ThreadPoolExecutor(max_workers=len(duts)) as pool:
            futures = [pool.submit(do_upgrade, d) for d in duts]
            for f in as_completed(futures):
                d = f.result()
                log.info("  ✓ Upgrade initiated on %s", d["name"])

        # Wait for all DUTs in parallel
        log.info("Waiting for DUTs to reboot (parallel)...")

        def do_wait(d):
            ok = wait_for_dut(d)
            return d, ok

        failed = 0
        with ThreadPoolExecutor(max_workers=len(duts)) as pool:
            futures = [pool.submit(do_wait, d) for d in duts]
            for f in as_completed(futures):
                d, ok = f.result()
                if not ok:
                    failed += 1

        if failed:
            log.error("%d DUT(s) failed to come back. Skipping tests for %s.", failed, tb)
            return False, int((time.time() - start) / 60)

        # Print versions
        log.info("Post-upgrade versions:")
        for d in duts:
            r = remote_ssh(d["ip"], d["user"], d["password"],
                           "show version | grep 'SONiC Software Version'", timeout=15)
            ver = r.stdout.strip() if r.returncode == 0 else "unknown"
            log.info("  %s: %s", d["name"], ver)

        # Wait for containers to come up after upgrade
        log.info("Waiting for containers to start (parallel)...")
        with ThreadPoolExecutor(max_workers=len(duts)) as pool:
            futures = [pool.submit(wait_for_containers, d) for d in duts]
            for f in as_completed(futures):
                f.result()  # Just wait, don't fail on warning
    else:
        log.info("═══ Phase 1: Upgrade SKIPPED ═══")

    # ── Phase 1.5: Push base configs ──
    skip_config = cfg.get("skip_config", False)
    if not skip_config and tb in BASE_CONFIG_MAP:
        config_dir = BASE_CONFIGS_DIR / BASE_CONFIG_MAP[tb]
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

    runner_plat = reg["runner_platform"]
    # Split test string into separate arguments for multiple tests
    test_args = test.split() if test else ["full"]
    cmd = [str(RUNNER_SCRIPT), "--platform", runner_plat, "--yaml", str(yaml_file)] + test_args
    log.info("Running: %s", " ".join(cmd))

    test_proc = subprocess.run(cmd, cwd=spytest_dir)
    test_rc = test_proc.returncode

    # ── Phase 3: Transfer logs ──
    log.info("═══ Phase 3: Transferring logs ═══")
    # run_test.sh names the log dir using the runner_platform (e.g. "tortuga"), not the testbed name
    # Logs are created in the spytest_dir (which is mounted as /data inside the container)
    run_log_dirs = sorted(glob.glob(str(spytest_dir / f"run_logs_{runner_plat}_*")), reverse=True)
    latest_log_dir = None
    if run_log_dirs:
        latest_log_dir = run_log_dirs[0]
        if log_server:
            transfer_and_cleanup_logs(tb, latest_log_dir, tb_branch, tb_build_id, log_server, testbed_registry)
        else:
            log.warning("No log_server configured; logs remain at %s", latest_log_dir)
    else:
        log.warning("No run_logs directory found for %s (platform=%s) under /data/", tb, runner_plat)

    # ── Phase 4: Publish to dashboard (before local cleanup) ──
    if latest_log_dir and os.path.isdir(latest_log_dir):
        log.info("═══ Phase 4: Publishing to dashboard ═══")
        # Build profile from branch (e.g., "202405c" -> "202405c-Tortuga")
        profile = f"{tb_branch}-Tortuga" if tb_branch != "unknown" else "Tortuga"
        publish_cmd = [
            sys.executable, str(PUBLISH_SCRIPT),
            "--profile", profile,
            "--platform", tb,
            "--topo", "2x2",
            "--build", tb_build_id,
            "--skip-upload",  # Phase 3 already transferred logs; just generate XML + import
            "--no-cleanup",
            latest_log_dir,
        ]
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
        log.info("═══ Phase 4: Publish SKIPPED (no logs) ═══")

    # ── Cleanup local logs (after publish) ──
    if latest_log_dir and os.path.isdir(latest_log_dir):
        cleanup_local_logs(latest_log_dir)

    duration = int((time.time() - start) / 60)
    if test_rc == 0:
        log.info("✓ Testbed %s COMPLETE (%dm)", tb, duration)
    else:
        log.error("✗ Testbed %s FAILED (exit=%d, %dm)", tb, test_rc, duration)

    return test_rc == 0, duration

# ── Email notification ────────────────────────────────────────────────

def send_summary_email(email_to, testbed_names, results, master_log):
    """Send a summary email via curl + SMTP relay."""
    all_pass = all(r["pass"] for r in results.values())
    status = "ALL PASSED" if all_pass else "SOME FAILED"
    subject = f"SPYtest Run — {status} — {datetime.now().strftime('%Y-%m-%d')}"
    sender = f"{os.environ.get('USER', 'spytest')}@cisco.com"

    lines = [f"SPYtest Job Runner — {datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z')}\n"]
    for tb in testbed_names:
        r = results[tb]
        mark = "PASS" if r["pass"] else "FAIL"
        lines.append(f"  {mark}  {tb}  ({r['duration']}m)")
    lines.append(f"\nOverall: {status}")
    lines.append(f"Log: {master_log}")
    body = "\n".join(lines)

    # Build RFC 5322 message
    msg = f"From: {sender}\r\nTo: {email_to}\r\nSubject: {subject}\r\n\r\n{body}\r\n"

    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".eml", delete=False) as f:
            f.write(msg)
            msg_file = f.name

        r = subprocess.run(
            ["curl", "--url", "smtp://outbound.cisco.com:25",
             "--mail-from", sender, "--mail-rcpt", email_to,
             "-T", msg_file, "--silent", "--show-error"],
            capture_output=True, text=True, timeout=30,
        )
        os.unlink(msg_file)

        if r.returncode == 0:
            log.info("Summary email sent to %s", email_to)
        else:
            log.warning("Failed to send email: %s", r.stderr.strip())
    except Exception as e:
        log.warning("Failed to send email: %s", e)


def schedule_run(args):
    """Create a crontab entry to run the script N hours from now."""
    from datetime import timedelta
    
    hours = args.schedule
    run_time = datetime.now() + timedelta(hours=hours)
    
    # Build the command to schedule (exclude --schedule itself)
    script_path = Path(__file__).resolve()
    cmd_parts = [sys.executable, str(script_path)]
    
    if args.config != str(DEFAULT_CONF):
        cmd_parts.extend(["--config", args.config])
    if args.testbed:
        cmd_parts.extend(["--testbed"] + args.testbed)
    if args.branch:
        cmd_parts.extend(["--branch", args.branch])
    if args.url:
        cmd_parts.extend(["--url", args.url])
    if args.spine_url:
        cmd_parts.extend(["--spine-url", args.spine_url])
    if args.skip_upgrade:
        cmd_parts.append("--skip-upgrade")
    if args.skip_config:
        cmd_parts.append("--skip-config")
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

def load_config(config_path):
    """Load YAML config file."""
    with open(config_path) as f:
        return yaml.safe_load(f)


def main():
    parser = argparse.ArgumentParser(
        description="SPYtest Job Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Testbeds run sequentially in listed order. If one fails, the next still runs.

Examples:
  %(prog)s                                          # Use default config
  %(prog)s --testbed g200 q200 --url <url>          # CLI queue
  %(prog)s --skip-upgrade --testbed g200 --test test_dwrr.py
  %(prog)s --schedule 2 --testbed g200 --url <url>  # Run 2 hours from now
  %(prog)s --schedule 0.5 --testbed q200            # Run 30 minutes from now
""",
    )
    parser.add_argument("--config", default=str(DEFAULT_CONF), help="Config YAML file")
    parser.add_argument("--testbed", nargs="+", help="Testbed queue (space-separated)")
    parser.add_argument("--branch", help="Git branch to checkout before running")
    parser.add_argument("--url", help="Image URL (overrides config)")
    parser.add_argument("--spine-url", help="Separate image URL for spines")
    parser.add_argument("--skip-upgrade", action="store_true", help="Skip DUT upgrade")
    parser.add_argument("--skip-config", action="store_true", help="Skip pushing base configs")
    parser.add_argument("--test", help="Test file or 'full'")
    parser.add_argument("--schedule", type=float, metavar="HOURS",
                        help="Schedule run N hours from now (creates crontab entry and exits)")
    args = parser.parse_args()

    # Handle --schedule: create crontab entry and exit
    if args.schedule is not None:
        schedule_run(args)
        return

    # Load config
    cfg = {}
    if os.path.isfile(args.config):
        cfg = load_config(args.config)
    else:
        print(f"Warning: Config not found: {args.config}", file=sys.stderr)

    # CLI overrides
    if args.testbed:
        cfg["_cli_testbeds"] = args.testbed
    if args.branch:
        cfg["branch"] = args.branch
    if args.url:
        cfg["_cli_url"] = args.url
    if args.spine_url:
        cfg["_cli_spine_url"] = args.spine_url
    if args.skip_upgrade:
        cfg["skip_upgrade"] = True
    if args.skip_config:
        cfg["skip_config"] = True
    if args.test:
        cfg["_cli_test"] = args.test

    # Resolve testbed list and per-testbed configs
    # Config testbeds can be a dict (per-testbed config) or list (simple names)
    raw_testbeds = cfg.get("testbeds", {})
    if isinstance(raw_testbeds, dict):
        # Dict style: {g200: {image_url: ...}, q200: {image_url: ...}}
        all_tb_names = list(raw_testbeds.keys())
        per_tb_config = raw_testbeds
    else:
        # List style: [g200, q200] — legacy, uses global image_url
        all_tb_names = list(raw_testbeds)
        per_tb_config = {}

    # --testbed CLI selects which testbeds to run (subset of config)
    testbed_names = cfg.get("_cli_testbeds", all_tb_names)
    if not testbed_names:
        parser.error("No testbeds specified. Use --testbed or set in config.")

    # Note: empty image_url is allowed - testbed will be skipped unless skip_upgrade=true

    # Acquire per-testbed locks (allows different testbeds to run in parallel)
    lock_fds = []
    for tb in sorted(testbed_names):
        lock_file = Path(f"/tmp/spytest_run_{tb}.lock")
        lock_file.parent.mkdir(parents=True, exist_ok=True)
        fd = open(lock_file, "w")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            lock_fds.append(fd)
        except IOError:
            print(f"[{datetime.now()}] Testbed '{tb}' is already running. Exiting.", file=sys.stderr)
            # Release any locks we acquired
            for lfd in lock_fds:
                lfd.close()
            sys.exit(1)

    # Setup logging
    log_dir = Path(str(DEFAULT_LOG_DIR))
    log_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    master_log = log_dir / f"master_{ts}.log"
    setup_logging(master_log)

    # Build testbed registry - always use script's own location as repo_base
    # This prevents running tests in wrong workspace when yaml has stale repo_base
    repo_base = str(DEFAULT_REPO_BASE)
    yaml_repo_base = cfg.get("repo_base")
    if yaml_repo_base and str(Path(yaml_repo_base).resolve()) != str(Path(repo_base).resolve()):
        log.warning("Ignoring repo_base from config (%s) — using script location: %s",
                    yaml_repo_base, repo_base)
    testbed_registry = build_testbed_registry(repo_base)
    log.info("Repo base: %s", repo_base)

    # Banner
    log.info("=" * 64)
    log.info("  SPYtest Job Runner")
    log.info("  %s", datetime.now().strftime("%Y-%m-%d %H:%M:%S %Z"))
    log.info("")
    log.info("  Queue:        %s", " → ".join(testbed_names))
    cli_skip_upgrade = cfg.get("skip_upgrade", False)
    for tb in testbed_names:
        tb_c = per_tb_config.get(tb, {})
        url = cfg.get("_cli_url") or tb_c.get("image_url") or cfg.get("image_url", "")
        surl = cfg.get("_cli_spine_url") or tb_c.get("spine_image_url", "")
        tst = cfg.get("_cli_test") or tb_c.get("test") or cfg.get("test", "full")
        tb_skip = cli_skip_upgrade or tb_c.get("skip_upgrade", False)
        if url:
            b, bid = parse_image_url(url)
            log.info("  [%s] image=%s (branch=%s build=%s) test=%s", tb, os.path.basename(url), b, bid, tst)
            if surl:
                log.info("  [%s] spine=%s", tb, os.path.basename(surl))
        elif tb_skip:
            log.info("  [%s] test=%s (existing image, skip_upgrade=true)", tb, tst)
        else:
            log.info("  [%s] SKIP (no image_url)", tb)
    log.info("  Log: %s", master_log)
    log.info("=" * 64)

    # Run testbed queue
    results = {}
    for i, tb in enumerate(testbed_names, 1):
        log.info("━━━ Queue [%d/%d]: %s ━━━", i, len(testbed_names), tb)

        # Build effective config for this testbed: per-tb overrides → CLI overrides → global
        run_cfg = dict(cfg)  # shallow copy of global
        tb_c = per_tb_config.get(tb, {})
        run_cfg["image_url"] = cfg.get("_cli_url") or tb_c.get("image_url") or cfg.get("image_url", "")
        run_cfg["spine_image_url"] = cfg.get("_cli_spine_url") or tb_c.get("spine_image_url") or cfg.get("spine_image_url", "")
        run_cfg["test"] = cfg.get("_cli_test") or tb_c.get("test") or cfg.get("test", "full")
        run_cfg["skip_upgrade"] = cfg.get("skip_upgrade") or tb_c.get("skip_upgrade", False)
        run_cfg["pre_patch"] = tb_c.get("pre_patch", "")
        run_cfg["_tb_config"] = {}  # already merged, clear to avoid double-read

        branch, build_id = parse_image_url(run_cfg["image_url"]) if run_cfg["image_url"] else ("unknown", "unknown")
        success, duration = run_one_testbed(tb, run_cfg, branch, build_id, testbed_registry)
        results[tb] = {"pass": success, "duration": duration}

    # Summary
    log.info("")
    log.info("=" * 64)
    log.info("  RUN SUMMARY — %s", datetime.now().strftime("%Y-%m-%d %H:%M:%S %Z"))
    log.info("")
    all_pass = True
    for tb in testbed_names:
        r = results[tb]
        if r["pass"] and r["duration"] == 0:
            status = "○ SKIP"
        elif r["pass"]:
            status = "✓ PASS"
        else:
            status = "✗ FAIL"
            all_pass = False
        log.info("    %s  %s  (%dm)", status, tb, r["duration"])
    log.info("")
    log.info("  Overall: %s", "ALL PASSED" if all_pass else "SOME FAILED")
    log.info("  Log: %s", master_log)
    log.info("=" * 64)

    # Send email notification
    email_to = cfg.get("email_to", "")
    if email_to:
        send_summary_email(email_to, testbed_names, results, master_log)

    sys.exit(0 if all_pass else 1)


if __name__ == "__main__":
    main()
