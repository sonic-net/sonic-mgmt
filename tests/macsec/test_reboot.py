'''This script is to test the MACsec behavior across reboots.

test_macsec_after_reboot does a cold reboot of the MACsec DUT (line card) and runs against every
MACsec controlled link and, on multi-asic DUTs, against every frontend asic.

Flow:
Step 1: Wait for MKA to converge on all controlled links and record a baseline
        (sessions per asic and the SAKs in APPL_DB)
Step 2: Save the config on the DUT (restored on teardown) and reboot it
Step 3: Verify that
        - the sessions on every asic are re-established,
        - APPL_DB is consistent with the neighbors on every controlled link,
        - every controlled link is up on both ends,
        - the SAKs were renegotiated,
        - DUT -> neighbor traffic flows over the MACsec links.

Timeouts follow the platform reboot tests: defaults come from tests.common.reboot.reboot_ctrl_dict and
can be overridden per DUT with ``plt_reboot_dict`` in the inventory (see ``get_plt_reboot_ctrl``).
'''

import logging
import pytest
from contextlib import contextmanager

from tests.common import reboot
from tests.common.helpers.assertions import pytest_assert
from tests.common.macsec.macsec_helper import check_appl_db, get_ipnetns_prefix, get_macsec_sessions, \
    getns_prefix, MACSEC_ENABLE_RE
from tests.common.macsec.recovery_helpers import MKA_CONVERGE_DELAY, MKA_CONVERGE_INTERVAL, MKA_CONVERGE_TIMEOUT, \
    snapshot_appl_db_saks, wait_for_mka_converged
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.reboot import REBOOT_TYPE_COLD, check_reboot_cause, reboot_ctrl_dict
from tests.common.utilities import get_plt_reboot_ctrl, ping_ip, wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.macsec_required,
    pytest.mark.disable_loganalyzer,
    pytest.mark.disable_memory_utilization,
    pytest.mark.topology("t0", "t2", "lrh", "urh", "t0-sonic"),
]

# Seconds to wait for the DUT to initialize after a reboot on a modular chassis
CHASSIS_REBOOT_WAIT = 240
# Seconds to wait for the sessions to settle before taking the baseline
SESSION_SETTLE_TIMEOUT = 120
# Seconds to wait for the reboot cause to be reported
REBOOT_CAUSE_TIMEOUT = 120

# Location of the config backup in the home directory of the DUT user (survives a reboot)
CONFIG_BACKUP_DIR = "~/macsec_reboot_test_config_backup"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def preserved_dut_config(macsec_duthost):
    """
    Back up the persisted config, save the running config (so MACsec survives a reboot)
    and restore the original persisted config on teardown.
    """
    dut = macsec_duthost
    dut.shell("sudo rm -rf {dir} && mkdir -p {dir} && sudo cp /etc/sonic/config_db*.json {dir}/".format(
        dir=CONFIG_BACKUP_DIR))
    dut.command("config save -y")
    yield
    try:
        dut.shell("sudo cp -f {dir}/config_db*.json /etc/sonic/".format(dir=CONFIG_BACKUP_DIR))
    except Exception as err:
        # keep the backup so that the config can be restored manually
        logger.warning("Failed to restore the original config on %s, backup kept in %s: %s",
                       dut.hostname, CONFIG_BACKUP_DIR, repr(err))
        return
    # delete the backup directory at the end of the test
    dut.shell("sudo rm -rf {dir}".format(dir=CONFIG_BACKUP_DIR), module_ignore_errors=True)


# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------

def log_macsec_state(dut, stage):
    """Best effort dump of the MACsec state of the DUT; never raises."""
    logger.error("Dumping MACsec state of %s (%s)", dut.hostname, stage)
    commands = ["show macsec{}".format(" -n {}".format(ns) if ns else "")
                for ns in dut.get_frontend_asic_namespace_list()]
    commands += [
        "docker ps -a",
        "ps aux | grep -w wpa_supplicant | grep -v grep",
        "sudo grep -iE 'macsec|wpa_supplicant' /var/log/syslog | tail -n 100",
    ]
    for cmd in commands:
        try:
            out = dut.shell(cmd, module_ignore_errors=True).get("stdout", "")
            logger.error("[%s] %s:\n%s", stage, cmd, out)
        except Exception as err:
            logger.error("[%s] failed to run '%s': %s", stage, cmd, repr(err))


@contextmanager
def dump_state_on_failure(dut, stage):
    """Dump the MACsec state of the DUT if the wrapped block fails (skips are not failures)."""
    try:
        yield
    except pytest.skip.Exception:
        raise
    except (Exception, pytest.fail.Exception):
        log_macsec_state(dut, stage)
        raise


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_recovery_timeout(dut, tc_name):
    """
    Time to wait for MACsec to recover. Defaults to the MKA convergence timeout and can be extended per DUT
    with the ``wait`` value of ``plt_reboot_dict`` in the inventory, as the platform reboot tests do.
    """
    timeout = MKA_CONVERGE_TIMEOUT
    plt_reboot_ctrl = get_plt_reboot_ctrl(dut, tc_name, REBOOT_TYPE_COLD)
    if plt_reboot_ctrl:
        timeout = max(timeout, plt_reboot_ctrl.get('wait', 0))
    logger.info("MACsec recovery timeout on %s: %ss", dut.hostname, timeout)
    return timeout


def get_active_ports(sessions):
    """Flatten ``{namespace: [ports]}`` into a set of ports."""
    return {port for ports in sessions.values() for port in ports}


def capture_baseline(dut, ctrl_links, policy, cipher_suite, send_sci):
    """
    Wait for MKA to converge and the sessions on all asics to settle, then record the sessions
    and the SAKs. Skips if the DUT has no MACsec session at all.
    """
    with dump_state_on_failure(dut, "before the reboot"):
        pytest_assert(wait_for_mka_converged(dut, ctrl_links, policy, cipher_suite, send_sci),
                      "MKA did not converge on all controlled links before the reboot")

        prev = {"sessions": None}

        def _sessions_stable():
            cur = get_macsec_sessions(dut)
            stable = cur == prev["sessions"]
            prev["sessions"] = cur
            return stable

        pytest_assert(wait_until(SESSION_SETTLE_TIMEOUT, 10, 0, _sessions_stable),
                      "MACsec sessions did not stabilize before the reboot")
        sessions = prev["sessions"]
        logger.info("MACsec sessions before the reboot: %s", sessions)
        if not get_active_ports(sessions):
            pytest.skip("No MACsec session found on {}".format(dut.hostname))

        missing = sorted(set(ctrl_links) - get_active_ports(sessions))
        pytest_assert(not missing, "Controlled ports without a MACsec session before the reboot: {} ({})"
                      .format(missing, sessions))

        saks = snapshot_appl_db_saks(dut, ctrl_links)
        pytest_assert(saks, "No SAK found in APPL_DB before the reboot")
    return {"sessions": sessions, "saks": saks}


def get_saks_per_port(saks):
    """Group a ``snapshot_appl_db_saks`` result by port: ``{port: {sak, ...}}``."""
    per_port = {}
    for (port, _sci, _an, _direction), sak in saks.items():
        per_port.setdefault(port, set()).add(sak)
    return per_port


def check_sessions_restored(dut, baseline, timeout):
    """All sessions of all asics must come back; the failure message names the asic."""
    pre_sessions = baseline["sessions"]
    restored = wait_until(timeout, 15, 0, lambda: get_macsec_sessions(dut) == pre_sessions)
    post_sessions = get_macsec_sessions(dut)
    logger.info("MACsec sessions after the reboot: %s", post_sessions)
    for ns_key, pre_list in pre_sessions.items():
        pytest_assert(pre_list == post_sessions.get(ns_key),
                      "MACsec sessions not restored on {} after the reboot. before={}, after={}"
                      .format(ns_key, pre_list, post_sessions.get(ns_key)))
    pytest_assert(restored and pre_sessions == post_sessions,
                  "MACsec sessions not restored after the reboot. before={}, after={}"
                  .format(pre_sessions, post_sessions))


def check_all_ports_macsec_ok(dut, ctrl_links):
    """Every controlled link must be MACsec-enabled on both ends."""
    for port, nbr in ctrl_links.items():
        pytest_assert(
            wait_until(60, 5, 0, lambda p=port, n=nbr: dut.iface_macsec_ok(p) and n["host"].iface_macsec_ok(n["port"])),
            "MACsec not ok on {} <-> {}:{}".format(port, nbr["name"], nbr["port"]))

        macsec_status = dut.shell("show macsec {} {}".format(getns_prefix(dut, port), port))['stdout'].splitlines()
        logger.debug("macsec status of %s: %s", port, macsec_status)
        pytest_assert(macsec_status, "Empty 'show macsec' output for {}".format(port))
        pytest_assert(port in macsec_status[0], "Unexpected macsec status header for {}: {}"
                      .format(port, macsec_status[0]))
        pytest_assert(any(MACSEC_ENABLE_RE.match(line) for line in macsec_status),
                      "MACsec not enabled on {}: {}".format(port, macsec_status))


def check_saks_renegotiated(dut, ctrl_links, baseline):
    """
    After the reboot MKA starts from scratch, so the SAKs of every port are expected to differ from the
    ones before. A reused SAK means the session was not really re-established (stale state).
    """
    post_saks = snapshot_appl_db_saks(dut, ctrl_links)
    pytest_assert(post_saks, "No SAK found in APPL_DB after the reboot")
    pre_per_port = get_saks_per_port(baseline["saks"])
    post_per_port = get_saks_per_port(post_saks)
    for port in ctrl_links:
        pytest_assert(post_per_port.get(port), "No SAK found in APPL_DB for {} after the reboot".format(port))
        reused = pre_per_port.get(port, set()) & post_per_port[port]
        if not reused:
            continue
        pytest.fail("SAK(s) on {} were not renegotiated after the reboot".format(port))


def check_dut_to_neighbor_traffic(dut, ctrl_links, upstream_links):
    """Ping the upstream neighbors that are reachable over a MACsec controlled link."""
    checked = 0
    for up_port, up_link in upstream_links.items():
        if up_port not in ctrl_links:
            continue
        dst_ip = up_link["local_ipv4_addr"]
        pytest_assert(
            wait_until(60, 5, 0, ping_ip, dut, dst_ip, count=4, cmd_prefix=get_ipnetns_prefix(dut, up_port)),
            "Ping from {} to upstream neighbor {} over MACsec port {} failed".format(dut.hostname, dst_ip, up_port))
        checked += 1
    if not checked:
        logger.warning("No upstream link over a MACsec controlled port, data plane check skipped")


def verify_macsec_recovered(dut, ctrl_links, upstream_links, baseline, policy, cipher_suite, send_sci,
                            timeout):
    with dump_state_on_failure(dut, "after the reboot"):
        check_sessions_restored(dut, baseline, timeout)
        pytest_assert(
            wait_until(timeout, MKA_CONVERGE_INTERVAL, MKA_CONVERGE_DELAY, check_appl_db,
                       dut, ctrl_links, policy, cipher_suite, send_sci),
            "APPL_DB is not consistent with the neighbors after the reboot")
        check_all_ports_macsec_ok(dut, ctrl_links)
        check_saks_renegotiated(dut, ctrl_links, baseline)
        check_dut_to_neighbor_traffic(dut, ctrl_links, upstream_links)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.reboot
def test_macsec_after_reboot(request, macsec_duthost, localhost, ctrl_links, upstream_links, policy, cipher_suite,
                             send_sci, wait_mka_establish, preserved_dut_config):
    """
    Cold reboot the MACsec DUT and verify that MACsec is re-established on all controlled links of all asics.
    """
    dut = macsec_duthost
    timeout = get_recovery_timeout(dut, request.node.nodeid)

    baseline = capture_baseline(dut, ctrl_links, policy, cipher_suite, send_sci)

    # 0 selects the default wait of the reboot type; modular chassis line cards need longer to initialize
    wait = CHASSIS_REBOOT_WAIT if dut.get_facts().get("modular_chassis") else 0
    reboot(dut, localhost, reboot_type=REBOOT_TYPE_COLD, wait=wait)
    wait_critical_processes(dut)
    pytest_assert(wait_until(REBOOT_CAUSE_TIMEOUT, 20, 30, check_reboot_cause, dut, REBOOT_TYPE_COLD),
                  "Unexpected reboot cause after cold reboot, expected pattern: {}"
                  .format(reboot_ctrl_dict[REBOOT_TYPE_COLD]["cause"]))

    verify_macsec_recovered(dut, ctrl_links, upstream_links, baseline, policy, cipher_suite, send_sci, timeout)
