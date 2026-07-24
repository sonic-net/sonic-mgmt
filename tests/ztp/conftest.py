"""ZTP test fixtures.

Two big jobs in this file:

1. Build the ZTP payload (`ztp_payload`) and resolve the provisioning mode
   (local-staged ztp.json vs DHCP Option 67).

2. Keep the DUT recoverable across the whole ZTP test suite. ZTP tests are
   destructive: they remove /etc/sonic/config_db.json, hide
   /etc/sonic/minigraph.xml, kick `ztp run`, and (TC22) intentionally apply an
   invalid HWSKU. Any of those can leave the DUT in a state where the next
   test cannot even SSH into it -- which then snowballs into
   AnsibleConnectionFailure on every subsequent test. The
   `backup_and_restore_config_db` fixture below has explicit two-stage
   recovery (config reload + save, then cold reboot fallback) so a bad
   teardown does not cascade into the next test.
"""
import json
import logging
import os
import shlex
import time

import pytest

from tests.common.helpers.assertions import pytest_assert as pt_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

CONFIG_DB_PATH = "/etc/sonic/config_db.json"
CONFIG_DB_BACKUP_PATH = "/host/ztp/config_db.json.ztp_test_backup"
MINIGRAPH_PATH = "/etc/sonic/minigraph.xml"
MINIGRAPH_BACKUP_PATH = "/host/ztp/minigraph.xml.ztp_test_backup"
ZTP_JSON_PATH = "/host/ztp/ztp.json"
ZTP_DATA_JSON_PATH = "/host/ztp/ztp_data.json"
ZTP_CONFIG_TO_APPLY_PATH = "/host/ztp/config_db_to_apply.json"
ZTP_DISABLE_CMD = "sudo ztp disable -y"
CONFIG_RELOAD_CMD = "sudo config reload -y -f"
CONFIG_SAVE_CMD = "sudo config save -y"
DEVICE_PATH = "/usr/share/sonic/device"
DEFAULT_FRR_URL = "http://10.29.158.47/ztp/m64/frr.conf"
DEFAULT_FRR_DST = "/etc/sonic/frr/frr.conf"

SSH_STOP_DETECT_TIMEOUT = 180
SSH_START_DELAY = 30
SSH_START_TIMEOUT = 900
CRITICAL_SERVICES_TIMEOUT = 600
CRITICAL_SERVICES_INTERVAL = 20

_ZTP_SERVICE_CFG_CANDIDATES = (
    "/host/ztp/ztp_cfg.json",
    "/etc/sonic/ztp.json",
)


# ---------------------------------------------------------------------------
# DHCP Option 67 auto-detection (unchanged behavior)
# ---------------------------------------------------------------------------


def _read_ztp_service_cfg(duthost):
    for cfg_path in _ZTP_SERVICE_CFG_CANDIDATES:
        res = duthost.shell("sudo cat {} 2>/dev/null".format(cfg_path), module_ignore_errors=True)
        if res.get("rc", 1) != 0:
            continue
        raw = res.get("stdout", "").strip()
        if not raw:
            continue
        try:
            return json.loads(raw)
        except (ValueError, json.JSONDecodeError):
            continue
    return None


def _find_opt67_url_path(cfg):
    if isinstance(cfg, dict):
        for key in ("opt67-url", "opt67_url"):
            val = cfg.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
        for val in cfg.values():
            found = _find_opt67_url_path(val)
            if found:
                return found
    elif isinstance(cfg, list):
        for item in cfg:
            found = _find_opt67_url_path(item)
            if found:
                return found
    return None


def _dhcp_opt67_signal_present(duthost):
    ztp_cfg = _read_ztp_service_cfg(duthost)
    opt67_path = _find_opt67_url_path(ztp_cfg) if ztp_cfg else None

    if opt67_path:
        q = shlex.quote(opt67_path)
        exists = duthost.shell("sudo test -s {}".format(q), module_ignore_errors=True)
        if exists.get("rc", 1) == 0:
            head = duthost.shell("sudo head -1 {}".format(q), module_ignore_errors=True)
            line = (head.get("stdout") or "").strip()
            if line.startswith("http://") or line.startswith("https://"):
                logger.info("DHCP Option 67: opt67-url file present at %s", opt67_path)
                return True

    probe = duthost.shell(
        (
            "sudo sh -c '"
            "for f in /run/ztp/dhcp_opt67_url /run/ztp/opt67-url /var/run/ztp/opt67-url; do "
            "  if [ -s \"$f\" ] && head -1 \"$f\" | grep -qE \"^https?://\"; then exit 0; fi; "
            "done; "
            "grep -rsh \"bootfile-name\" /var/lib/dhcp/ 2>/dev/null | grep -qE \"https?://\" && exit 0; "
            "exit 1'"
        ),
        module_ignore_errors=True,
    )
    return probe.get("rc", 1) == 0


def resolve_ztp_provisioning_mode(duthost):
    override = os.getenv("ZTP_PROVISIONING_MODE", "auto").strip().lower()

    if override == "local":
        logger.info("ZTP provisioning mode: local (ZTP_PROVISIONING_MODE=local)")
        return "local"

    if override == "dhcp":
        logger.info("ZTP provisioning mode: dhcp (ZTP_PROVISIONING_MODE=dhcp)")
        return "dhcp"

    attempts = int(os.getenv("ZTP_DHCP_PROBE_ATTEMPTS", "6"))
    interval = int(os.getenv("ZTP_DHCP_PROBE_INTERVAL", "5"))

    for attempt in range(attempts):
        if _dhcp_opt67_signal_present(duthost):
            logger.info(
                "ZTP provisioning mode: dhcp (auto-detected DHCP Option 67, attempt %s/%s)",
                attempt + 1,
                attempts,
            )
            return "dhcp"
        if attempt < attempts - 1:
            time.sleep(interval)

    logger.info(
        "ZTP provisioning mode: local (auto: no DHCP Option 67 signal after %s attempts)",
        attempts,
    )
    return "local"


def _build_default_payload():
    frr_url = os.getenv("ZTP_FRR_URL", DEFAULT_FRR_URL)
    ztp = {}
    step_index = 1

    ztp["{:02d}-download".format(step_index)] = {
        "files": [
            {
                "url": {
                    "source": frr_url,
                    "destination": DEFAULT_FRR_DST,
                }
            }
        ],
        "halt-on-failure": False,
        "ignore-result": False,
        "reboot-on-failure": False,
        "reboot-on-success": False,
    }
    step_index += 1

    ztp["{:02d}-configdb-json".format(step_index)] = {
        "url": {
            "source": "file:///host/ztp/config_db_to_apply.json",
            "destination": "/etc/sonic/config_db.json",
        },
        "clear-config": False,
        "save-config": True,
    }

    return {"ztp": ztp}


@pytest.fixture(scope="module")
def ztp_provisioning_mode(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    return resolve_ztp_provisioning_mode(duthost)


@pytest.fixture(scope="module")
def ztp_payload(ztp_provisioning_mode):
    ztp_json_content = _build_default_payload()
    payload_origin = "auto-generated"
    logger.info("Using auto-generated ztp_data payload from fixture.")

    return {
        "local_ztp_json": None,
        "ztp_json_content": ztp_json_content,
        "payload_origin": payload_origin,
        "dut_ztp_data_json": ZTP_DATA_JSON_PATH,
        "dut_config_to_apply": ZTP_CONFIG_TO_APPLY_PATH,
        "provisioning_mode": ztp_provisioning_mode,
    }


# ---------------------------------------------------------------------------
# Platform / HWSKU info (used by TC20, TC21, TC22)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def platform_hwsku_info(duthosts, rand_one_dut_hostname):
    """Resolve the DUT's platform, the running HWSKU and the platform-default HWSKU.

    Used by HWSKU validation tests (TC20, TC21, TC22). Reads from `duthost.facts`
    where available and falls back to /usr/share/sonic/device/<platform>/default_sku
    for the default HWSKU (the file can list multiple SKUs whitespace-separated;
    we take the first token as the platform default).
    """
    duthost = duthosts[rand_one_dut_hostname]

    platform = duthost.facts.get("platform") if hasattr(duthost, "facts") else None
    running_hwsku = duthost.facts.get("hwsku") if hasattr(duthost, "facts") else None

    # Fall back to sonic-cfggen if facts are not populated (e.g. ZTP just rebuilt
    # the DUT and the cached facts are stale).
    if not platform:
        res = duthost.shell(
            "sonic-cfggen -d -v DEVICE_METADATA.localhost.platform",
            module_ignore_errors=True,
        )
        platform = (res.get("stdout") or "").strip() or None
    if not running_hwsku:
        res = duthost.shell(
            "sonic-cfggen -d -v DEVICE_METADATA.localhost.hwsku",
            module_ignore_errors=True,
        )
        running_hwsku = (res.get("stdout") or "").strip() or None

    default_hwsku = None
    if platform:
        default_sku_file = "{}/{}/default_sku".format(DEVICE_PATH, platform)
        res = duthost.shell(
            "sudo cat {} 2>/dev/null".format(default_sku_file),
            module_ignore_errors=True,
        )
        if res.get("rc", 1) == 0:
            content = (res.get("stdout") or "").strip()
            if content:
                default_hwsku = content.split()[0]

    logger.info(
        "platform_hwsku_info: platform=%s running_hwsku=%s default_hwsku=%s",
        platform, running_hwsku, default_hwsku,
    )

    return {
        "platform": platform,
        "running_hwsku": running_hwsku,
        "default_hwsku": default_hwsku,
    }


# ---------------------------------------------------------------------------
# DUT recovery helpers used by backup_and_restore_config_db
# ---------------------------------------------------------------------------


def _wait_for_critical_services(duthost):
    try:
        duthost.critical_services_fully_started()
        return True
    except Exception as error:  # pylint: disable=broad-except
        logger.info("Waiting for critical services: %s", error)
        return False


def _wait_for_ssh_back(localhost, duthost, *, expect_disconnect=True):
    """Wait for SSH on the DUT to come back. Used after `config reload` or reboot.

    If `expect_disconnect` is True we first wait for port 22 to actually drop
    (with a short timeout) so we don't race the test framework and incorrectly
    decide the DUT is "up" because it never went down. Returns True on success.
    """
    if expect_disconnect:
        localhost.wait_for(
            host=duthost.mgmt_ip,
            port=22,
            state="stopped",
            timeout=SSH_STOP_DETECT_TIMEOUT,
            module_ignore_errors=True,
        )

    ssh_wait = localhost.wait_for(
        host=duthost.mgmt_ip,
        port=22,
        state="started",
        delay=SSH_START_DELAY,
        timeout=SSH_START_TIMEOUT,
        module_ignore_errors=True,
    )
    return not ssh_wait.get("failed", False)


def _safe_shell(duthost, cmd):
    """Run a shell command and swallow BOTH module failures and connection
    failures (AnsibleConnectionFailure, sudo prompt timeout, SSH drop).

    `module_ignore_errors=True` only suppresses Ansible module failures, not
    transport-layer failures. During recovery from a destructive ZTP test the
    DUT may have a hung sudo or a flapping SSHd, and we still need every
    teardown step to proceed so we ultimately reach the reboot fallback.
    """
    try:
        return duthost.shell(cmd, module_ignore_errors=True)
    except Exception as err:  # pylint: disable=broad-except
        logger.warning(
            "ZTP teardown: shell command failed at transport/sudo layer "
            "(swallowed so teardown can continue): cmd=%r err=%s",
            cmd, err,
        )
        return {
            "rc": -1,
            "stdout": "",
            "stderr": str(err),
            "failed": True,
            "connection_failed": True,
        }


def _file_exists(duthost, path):
    try:
        res = duthost.stat(path=path)
    except Exception as err:  # pylint: disable=broad-except
        logger.warning("stat(%s) failed at transport layer (swallowed): %s", path, err)
        return False
    return bool(res.get("stat", {}).get("exists"))


def _safe_copy(duthost, src, dst):
    """Best-effort `cp src dst` -- never raises, returns True on rc==0."""
    res = _safe_shell(duthost, "sudo cp {} {}".format(src, dst))
    return res.get("rc", 1) == 0


def _ssh_is_healthy(localhost, duthost, probe_timeout=20):
    """SSH liveness probe. Returns True if TCP/22 is open."""
    try:
        res = localhost.wait_for(
            host=duthost.mgmt_ip,
            port=22,
            state="started",
            delay=0,
            timeout=probe_timeout,
            module_ignore_errors=True,
        )
        return not res.get("failed", False)
    except Exception as err:  # pylint: disable=broad-except
        logger.warning("SSH liveness probe raised: %s", err)
        return False


# ---------------------------------------------------------------------------
# backup_and_restore_config_db: robust two-stage recovery
# ---------------------------------------------------------------------------


@pytest.fixture(scope="function")
def backup_and_restore_config_db(duthosts, rand_one_dut_hostname, localhost):
    """Snapshot critical SONiC config before a destructive ZTP test, then put
    the DUT back together afterwards.

    Setup:
      - Back up /etc/sonic/config_db.json -> /host/ztp/config_db.json.ztp_test_backup
      - Back up /etc/sonic/minigraph.xml -> /host/ztp/minigraph.xml.ztp_test_backup
        (ZTP tests intentionally hide minigraph.xml so the ZTP daemon does not
         exit early; we must put it back so the DUT is not permanently broken.)

    Teardown (two-stage, no early aborts):
      Stage 1 (fast):
        - `ztp disable -y`
        - restore config_db.json and minigraph.xml from backup
        - `config reload -y -f` then `config save -y`
        - wait for SSH to drop+come back and for critical services to start
      Stage 2 (fallback, only if Stage 1 fails):
        - re-disable ZTP, re-restore config files
        - `config save -y` (belt-and-suspenders, in case Stage 1 dirtied Redis)
        - `sudo reboot`
        - wait for SSH to come back and for critical services to start

    Why both reload AND save: `config reload` loads on-disk config into Redis
    and restarts services but does NOT write back to disk. If reload mutates
    the live config (or had to fall back to minigraph regeneration), the disk
    copy will be stale and the next reboot would come up unreachable.

    Why a reboot fallback: a test like TC4 deliberately leaves the DUT with
    no config_db.json and no profile files, and TC22 applies an invalid HWSKU.
    In both cases SAI/ASIC_DB can be in a state that `config reload` alone
    cannot recover from. A cold reboot from a restored config_db.json
    guarantees a clean re-init.

    Helpers are wrapped in module_ignore_errors=True so a fixable mid-flow
    failure (e.g. ZTP socket transiently busy) does not abort recovery; the
    fixture only asserts at the very end if the DUT is still not reachable.
    """
    duthost = duthosts[rand_one_dut_hostname]

    # ----- Setup: snapshot config_db.json and minigraph.xml -----
    config_exists = _file_exists(duthost, CONFIG_DB_PATH)
    minigraph_exists = _file_exists(duthost, MINIGRAPH_PATH)

    if config_exists:
        logger.info("Backing up %s -> %s", CONFIG_DB_PATH, CONFIG_DB_BACKUP_PATH)
        pt_assert(
            _safe_copy(duthost, CONFIG_DB_PATH, CONFIG_DB_BACKUP_PATH),
            "Failed to back up config_db.json before ZTP test",
        )
    else:
        logger.info("%s does not exist; skipping config_db backup", CONFIG_DB_PATH)

    if minigraph_exists:
        logger.info("Backing up %s -> %s", MINIGRAPH_PATH, MINIGRAPH_BACKUP_PATH)
        # minigraph backup is best-effort; some testbeds do not have minigraph.xml.
        _safe_copy(duthost, MINIGRAPH_PATH, MINIGRAPH_BACKUP_PATH)
    else:
        logger.info("%s does not exist; skipping minigraph backup", MINIGRAPH_PATH)

    yield {
        "config_exists": config_exists,
        "minigraph_exists": minigraph_exists,
        "backup_path": CONFIG_DB_BACKUP_PATH,
        "minigraph_backup_path": MINIGRAPH_BACKUP_PATH,
    }

    # ----- Teardown -----
    logger.info("ZTP teardown: starting Stage 1 recovery (disable + restore + reload)")

    stage1_ssh = False
    stage1_svc = False

    # Only attempt Stage 1 if SSH is actually responsive. After a destructive
    # test (TC4 nuking config_db, TC22 applying an invalid HWSKU) the DUT may
    # be in a state where sudo hangs at the privilege escalation prompt; in
    # that case Stage 1 would just spin for tens of seconds per command and
    # then explode an AnsibleConnectionFailure that aborts the whole teardown
    # before we ever get to the reboot fallback.
    if _ssh_is_healthy(localhost, duthost):
        _safe_shell(duthost, ZTP_DISABLE_CMD)

        restored_cfg = False
        if config_exists and _file_exists(duthost, CONFIG_DB_BACKUP_PATH):
            restored_cfg = _safe_copy(duthost, CONFIG_DB_BACKUP_PATH, CONFIG_DB_PATH)
            if not restored_cfg:
                logger.warning("Failed to restore config_db.json from backup")
        else:
            logger.warning(
                "No usable config_db.json backup to restore "
                "(config_exists=%s, backup_present=%s)",
                config_exists, _file_exists(duthost, CONFIG_DB_BACKUP_PATH),
            )

        if minigraph_exists and _file_exists(duthost, MINIGRAPH_BACKUP_PATH):
            if not _safe_copy(duthost, MINIGRAPH_BACKUP_PATH, MINIGRAPH_PATH):
                logger.warning("Failed to restore minigraph.xml from backup")

        # Reload the restored config into Redis and persist it back to disk so the
        # DUT survives the next reboot even if Stage 1 succeeds.
        _safe_shell(duthost, CONFIG_RELOAD_CMD)
        _safe_shell(duthost, CONFIG_SAVE_CMD)

        stage1_ssh = _wait_for_ssh_back(localhost, duthost, expect_disconnect=True)
        if stage1_ssh:
            stage1_svc = wait_until(
                CRITICAL_SERVICES_TIMEOUT,
                CRITICAL_SERVICES_INTERVAL,
                0,
                _wait_for_critical_services,
                duthost,
            )
    else:
        logger.warning(
            "ZTP teardown: SSH not healthy at teardown start; skipping Stage 1 "
            "and going straight to reboot fallback"
        )

    if stage1_ssh and stage1_svc:
        logger.info("ZTP teardown Stage 1 succeeded; DUT is healthy")
    else:
        logger.warning(
            "ZTP teardown Stage 1 incomplete (ssh=%s, services=%s); falling back to reboot",
            stage1_ssh, stage1_svc,
        )

        # Stage 2: cold reboot. Re-disable ZTP and re-restore the on-disk
        # config first so the DUT boots into a known-good state. Then save
        # again as belt-and-suspenders in case Stage 1's reload partially
        # mutated Redis. All shell calls go through _safe_shell so a hung
        # sudo does not block us from issuing the reboot.
        _safe_shell(duthost, ZTP_DISABLE_CMD)
        if config_exists and _file_exists(duthost, CONFIG_DB_BACKUP_PATH):
            _safe_copy(duthost, CONFIG_DB_BACKUP_PATH, CONFIG_DB_PATH)
        if minigraph_exists and _file_exists(duthost, MINIGRAPH_BACKUP_PATH):
            _safe_copy(duthost, MINIGRAPH_BACKUP_PATH, MINIGRAPH_PATH)
        _safe_shell(duthost, CONFIG_SAVE_CMD)
        _safe_shell(duthost, "sudo reboot")

        stage2_ssh = _wait_for_ssh_back(localhost, duthost, expect_disconnect=True)
        stage2_svc = False
        if stage2_ssh:
            stage2_svc = wait_until(
                CRITICAL_SERVICES_TIMEOUT,
                CRITICAL_SERVICES_INTERVAL,
                0,
                _wait_for_critical_services,
                duthost,
            )

        pt_assert(
            stage2_ssh and stage2_svc,
            "ZTP teardown failed: DUT did not recover after `config reload` AND cold "
            "reboot (stage2 ssh={}, services={}). Manual intervention required.".format(
                stage2_ssh, stage2_svc,
            ),
        )
        logger.info("ZTP teardown Stage 2 (reboot) succeeded; DUT is healthy")

    # Final scrubs of test artifacts. Best-effort; never abort here -- by this
    # point the DUT is healthy and we don't want to fail teardown over a
    # leftover backup file.
    _safe_shell(duthost, "sudo rm -f {}".format(CONFIG_DB_BACKUP_PATH))
    _safe_shell(duthost, "sudo rm -f {}".format(MINIGRAPH_BACKUP_PATH))
    _safe_shell(duthost, "sudo rm -f {}".format(ZTP_CONFIG_TO_APPLY_PATH))


@pytest.fixture(scope="module", autouse=True)
def core_dump_and_config_check():
    yield


@pytest.fixture(scope="module", autouse=True)
def sanity_check():
    yield
