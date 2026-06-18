"""
Tests for the PrefixListMgr refactor and the new SUPPRESS_PREFIX type.

Reference test plan:
    docs/testplan/PrefixListMgr-Refactor-Test-Plan.md

Reference SONiC change:
    https://github.com/sonic-net/sonic-buildimage/pull/26937

The companion file ``tests/bgp/test_prefix_list.py`` continues to cover the
ANCHOR_PREFIX end-to-end data-plane regression (TC-A2 in the test plan) and
is intentionally not duplicated here.
"""
import logging
import random
import re
import time
import uuid

import pytest
import yaml

from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.utilities import wait_until


pytestmark = [
    pytest.mark.topology("t0", "t1", "t2"),
    pytest.mark.disable_loganalyzer,  # we explicitly scan syslog inside the cases.
]

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CONSTANTS_FILE = "/etc/sonic/constants.yml"
CHASSISDB_CONF = "/etc/sonic/chassisdb.conf"

ANCHOR_TYPE = "ANCHOR_PREFIX"
SUPPRESS_TYPE = "SUPPRESS_PREFIX"
UNKNOWN_TYPE = "FOO_TYPE"

DEFAULT_ANCHOR_PL_NAME = "ANCHOR_CONTRIBUTING_ROUTES"
DEFAULT_SUPPRESS_IPV4_NAME = "SUPPRESS_IPV4_PREFIX"
DEFAULT_SUPPRESS_IPV6_NAME = "SUPPRESS_IPV6_PREFIX"

CUSTOM_SUPPRESS_IPV4_NAME = "CUSTOM_IPV4_PREFIX"
CUSTOM_SUPPRESS_IPV6_NAME = "CUSTOM_IPV6_PREFIX"

ANCHOR_TEST_PREFIXES = {
    "ipv4": "205.168.0.0/24",
    "ipv6": "50c0::/48",
}
SUPPRESS_TEST_PREFIXES = {
    "ipv4": "192.168.100.0/24",
    "ipv6": "2001:db8:abcd::/48",
}
MALFORMED_PREFIX = "999.999.0.0/24"
DB_ONLY_BAD_PREFIX = "not-a-prefix"

BGPCFGD_RUNNING_TIMEOUT = 60
BGPCFGD_RUNNING_INTERVAL = 5


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

def get_device_metadata(duthost):
    """Return (type, subtype) from DEVICE_METADATA.localhost."""
    config_facts = duthost.config_facts(
        host=duthost.hostname, source="running"
    )["ansible_facts"]
    localhost = config_facts.get("DEVICE_METADATA", {}).get("localhost", {})
    return localhost.get("type", ""), localhost.get("subtype", "")


def is_upstream_spine(duthost):
    dev_type, subtype = get_device_metadata(duthost)
    return (
        dev_type == "UpperSpineRouter"
        or (dev_type == "SpineRouter" and subtype == "UpstreamLC")
    )


def has_chassisdb_conf(duthost):
    return duthost.stat(path=CHASSISDB_CONF)["stat"]["exists"]


def asic_ns_for_db_cli(duthost, asic_index):
    """Build the sonic-db-cli namespace flag for a given frontend asic index."""
    if duthost.is_multi_asic and asic_index is not None:
        return "-n asic{}".format(asic_index)
    return ""


def asic_ns_for_vtysh(duthost, asic_index):
    """Build the vtysh namespace flag for a given frontend asic index."""
    if duthost.is_multi_asic and asic_index is not None:
        return "-n {}".format(asic_index)
    return ""


def op_prefix_with_cmd(duthost, prefix_type, prefix, action, ignore_error=False):
    """Run ``sudo prefix_list <action> <type> <prefix>``."""
    pytest_assert(
        action in ("add", "remove"),
        "Invalid action {!r}, must be add/remove".format(action),
    )
    cmd = "sudo prefix_list {} {} {}".format(action, prefix_type, prefix)
    return duthost.shell(cmd, module_ignore_errors=ignore_error)


def prefix_list_status(duthost):
    """Return raw stdout of ``sudo prefix_list status``."""
    return duthost.shell("sudo prefix_list status")["stdout"]


def verify_status_contains(duthost, prefix_type, prefix):
    """
    Check that ``status`` reports the (type, prefix) tuple once per frontend
    asic (the CLI writes the entry on every FrontEnd asic).
    """
    stdout = prefix_list_status(duthost)
    expected = len(duthost.get_frontend_asic_ids())
    needle = "('{}', '{}')".format(prefix_type, prefix)
    count = stdout.count(needle)
    if count != expected:
        logger.info(
            "Expected %d occurrences of %s in status output, got %d. Output:\n%s",
            expected, needle, count, stdout,
        )
        return False
    return True


def verify_config_db_entry(duthost, prefix_type, prefix, present):
    """
    Check CONFIG_DB ``PREFIX_LIST|<type>|<prefix>`` key existence on every
    frontend asic.
    """
    key = 'PREFIX_LIST|{}|{}'.format(prefix_type, prefix)
    for asic_index in duthost.get_frontend_asic_ids():
        ns = asic_ns_for_db_cli(duthost, asic_index)
        cmd = 'sonic-db-cli {} CONFIG_DB keys "{}"'.format(ns, key).strip()
        out = duthost.shell(cmd)["stdout"].strip()
        has_key = key in out
        if has_key != present:
            logger.info(
                "CONFIG_DB key '%s' presence mismatch on asic %s: want=%s got=%s",
                key, asic_index, present, has_key,
            )
            return False
    return True


def write_config_db_key_directly(duthost, prefix_type, prefix):
    """Bypass the CLI and write straight into CONFIG_DB on every frontend asic."""
    key = 'PREFIX_LIST|{}|{}'.format(prefix_type, prefix)
    for asic_index in duthost.get_frontend_asic_ids():
        ns = asic_ns_for_db_cli(duthost, asic_index)
        duthost.shell(
            'sonic-db-cli {} CONFIG_DB hset "{}" NULL NULL'.format(ns, key).strip()
        )


def delete_config_db_key_directly(duthost, prefix_type, prefix):
    key = 'PREFIX_LIST|{}|{}'.format(prefix_type, prefix)
    for asic_index in duthost.get_frontend_asic_ids():
        ns = asic_ns_for_db_cli(duthost, asic_index)
        duthost.shell(
            'sonic-db-cli {} CONFIG_DB DEL "{}"'.format(ns, key).strip(),
            module_ignore_errors=True,
        )


def fetch_vtysh_prefix_list(duthost, asic_index, ipv, name):
    """Return stdout of ``vtysh -n <n> -c 'show <ip|ipv6> prefix-list <name>'``."""
    ns = asic_ns_for_vtysh(duthost, asic_index)
    cmd = 'vtysh {} -c "show {} prefix-list {}"'.format(ns, ipv, name).strip()
    return duthost.shell(cmd, module_ignore_errors=True)["stdout"]


def verify_frr_prefix_list_entry(duthost, name, prefix, ipv, present=True):
    """
    Assert (return bool) whether the given prefix entry exists in the FRR
    prefix-list on every frontend asic.
    """
    for asic_index in duthost.get_frontend_asic_ids():
        stdout = fetch_vtysh_prefix_list(duthost, asic_index, ipv, name)
        # `permit <prefix>` (possibly with seq <n>) is what the template emits.
        has_entry = re.search(
            r"\bpermit\s+{}\b".format(re.escape(prefix)), stdout
        ) is not None
        if has_entry != present:
            logger.info(
                "FRR prefix-list mismatch on asic %s: name=%s prefix=%s ipv=%s "
                "want_present=%s got_present=%s stdout=\n%s",
                asic_index, name, prefix, ipv, present, has_entry, stdout,
            )
            return False
    return True


def get_suppress_pl_names(duthost):
    """Return (ipv4_name, ipv6_name) for SUPPRESS_PREFIX from constants.yml,
    falling back to the registry defaults if the section is missing."""
    if not duthost.stat(path=CONSTANTS_FILE)["stat"]["exists"]:
        return DEFAULT_SUPPRESS_IPV4_NAME, DEFAULT_SUPPRESS_IPV6_NAME
    raw = duthost.shell("cat {}".format(CONSTANTS_FILE))["stdout"]
    data = yaml.safe_load(raw) or {}
    pl = (
        data.get("constants", {})
        .get("bgp", {})
        .get("prefix_list", {})
        .get(SUPPRESS_TYPE, {})
    )
    return (
        pl.get("ipv4_name", DEFAULT_SUPPRESS_IPV4_NAME),
        pl.get("ipv6_name", DEFAULT_SUPPRESS_IPV6_NAME),
    )


def bgp_container_name(duthost, asic_index):
    return "bgp{}".format(asic_index) if (
        duthost.is_multi_asic and asic_index is not None
    ) else "bgp"


def bgp_container_names(duthost):
    return [
        bgp_container_name(duthost, asic_index)
        for asic_index in duthost.get_frontend_asic_ids()
    ]


def bgp_service_name(duthost, asic_index):
    return "bgp@{}".format(asic_index) if (
        duthost.is_multi_asic and asic_index is not None
    ) else "bgp"


def bgp_service_container_pairs(duthost):
    return [
        (bgp_service_name(duthost, asic_index),
         bgp_container_name(duthost, asic_index))
        for asic_index in duthost.get_frontend_asic_ids()
    ]


def bgpcfgd_running(duthost):
    """Return True iff bgpcfgd is RUNNING in the bgp container(s) of all
    frontend asics.

    We deliberately bypass ``MultiAsicSonicHost.is_service_running`` here:
    that helper re-appends the asic index to the docker name, so an already
    asic-suffixed container name like ``bgp0`` gets mangled to ``bgp00``
    (one digit per layer), and ``docker exec bgp00 supervisorctl ...`` fails
    on every ASIC, making the check incorrectly report False on every multi
    ASIC DUT. Calling ``sonichost.is_service_running`` directly performs the
    raw ``docker exec <container> supervisorctl status <svc>`` with the
    exact container name we built."""
    sonichost = getattr(duthost, "sonichost", duthost)
    for container in bgp_container_names(duthost):
        if not sonichost.is_service_running("bgpcfgd", container):
            return False
    return True


def wait_for_bgpcfgd(duthost, timeout=BGPCFGD_RUNNING_TIMEOUT):
    pytest_assert(
        wait_until(timeout, BGPCFGD_RUNNING_INTERVAL, 0, bgpcfgd_running, duthost),
        "bgpcfgd did not come up within {}s on {}".format(timeout, duthost.hostname),
    )


def start_bgp_container(duthost, service, container):
    """Best-effort start for a bgp container left stopped after restart."""
    duthost.shell(
        "sudo systemctl reset-failed {0}; sudo systemctl start {0}".format(service),
        module_ignore_errors=True,
    )
    duthost.shell("sudo docker start {}".format(container), module_ignore_errors=True)


def restart_bgp_container(duthost):
    """Restart the bgp container on every frontend asic and wait for bgpcfgd.

    ``sudo systemctl restart bgp`` occasionally exits non-zero on real DUTs
    when systemd races with docker (the unit's start helper returns before
    the container has fully come up). The bgp container itself still comes
    up correctly a few seconds later, so we tolerate a non-zero rc here and
    rely on :func:`wait_for_bgpcfgd` to confirm that bgpcfgd is actually
    RUNNING. On some builds a failed restart can leave the container stopped,
    so we do a bounded start fallback before failing."""
    service_container_pairs = bgp_service_container_pairs(duthost)
    for service, _ in service_container_pairs:
        duthost.shell(
            "sudo systemctl restart {}".format(service),
            module_ignore_errors=True,
        )
    if not wait_until(60, BGPCFGD_RUNNING_INTERVAL, 0, bgpcfgd_running, duthost):
        for service, container in service_container_pairs:
            start_bgp_container(duthost, service, container)
    wait_for_bgpcfgd(duthost, timeout=180)


def apply_constants_to_bgpcfgd(duthost):
    """Propagate the current host ``/etc/sonic/constants.yml`` into every
    frontend ASIC's bgp container and bounce just ``bgpcfgd`` so it re-reads
    it.

    Background: a ``systemctl restart bgp@<N>`` is not portable across our
    testbeds for refreshing the constants file. On real (single-ASIC) DUTs
    ``/etc/sonic/constants.yml`` is bind-mounted read-only into the bgp
    container from the host, so editing the host file plus a systemctl
    restart works; but ``docker cp`` into that mount fails with
    ``mounted volume is marked read-only``. On the multi-ASIC VS testbed
    (vlab-08) the per-ASIC ``bgp<N>`` container's ``/etc/sonic/constants.yml``
    is NOT taken from the host file (it is provided by the container image),
    so editing the host file alone has no effect even after a systemctl
    restart of the ``bgp@<N>`` service.

    To handle both cases with one code path:

    1. Best-effort ``docker cp`` the (already-updated) host
       ``constants.yml`` into each bgp container. This overwrites the
       container-provided copy on testbeds where the file lives in the
       container's writable layer (vlab-08 multi-ASIC); on real DUTs the
       command fails because the destination is read-only, which we ignore
       — the file is already up to date there via the host bind-mount.
    2. Restart only the ``bgpcfgd`` supervisord program inside each bgp
       container. This is sufficient to force a fresh ``read_constants()``
       call without cycling the whole container."""
    for container in bgp_container_names(duthost):
        duthost.shell(
            "sudo docker cp {0} {1}:{0}".format(CONSTANTS_FILE, container),
            module_ignore_errors=True,
        )
        duthost.shell(
            "sudo docker exec {} supervisorctl restart bgpcfgd".format(container),
            module_ignore_errors=True,
        )
    pytest_assert(
        wait_until(BGPCFGD_RUNNING_TIMEOUT, BGPCFGD_RUNNING_INTERVAL, 0,
                   bgpcfgd_running, duthost),
        "bgpcfgd did not come up within {}s on {} after constants reload".format(
            BGPCFGD_RUNNING_TIMEOUT, duthost.hostname),
    )


def place_syslog_marker(duthost):
    """Inject a unique marker into /var/log/syslog and return the marker string.

    Used to window syslog assertions: after placing the marker, only lines
    after it are considered by collect_syslog_since_marker().
    Waits until the marker is confirmed present in the syslog file to avoid
    races with asynchronous rsyslog writes.
    """
    marker = "SONIC_TEST_MARKER_{}".format(uuid.uuid4().hex[:12])
    duthost.shell("logger -t SONIC_TEST '{}'".format(marker))
    duthost.shell(
        "timeout 5 bash -c \"while ! grep -q '{}' /var/log/syslog; do sleep 0.1; done\"".format(marker)
    )
    return marker


def collect_syslog_since_marker(duthost, marker, pattern):
    """Return lines from /var/log/syslog matching *pattern* after *marker*.

    Works on both single-ASIC and multi-ASIC platforms because all container
    daemons forward their logs to the host's /var/log/syslog via rsyslog.
    Filters out ansible audit lines that echo the grep pattern back.
    """
    cmd = (
        "sudo sed -n '/{marker}/,$p' /var/log/syslog "
        "| grep -v 'Invoked with _raw_params' "
        "| grep -E {pattern!r} || true"
    ).format(marker=marker, pattern=pattern)
    return duthost.shell(cmd)["stdout"]


# ---------------------------------------------------------------------------
# Cleanup fixture: belt-and-braces removal of anything this module wrote.
# ---------------------------------------------------------------------------

@pytest.fixture
def prefix_cleanup():
    """Tracks (duthost, type, prefix) tuples and cleans them up at teardown."""
    tracked = []

    def _track(duthost, prefix_type, prefix):
        tracked.append((duthost, prefix_type, prefix))

    yield _track

    for duthost, prefix_type, prefix in tracked:
        # Try the CLI first (it removes from CONFIG_DB on every frontend asic).
        op_prefix_with_cmd(duthost, prefix_type, prefix, "remove", ignore_error=True)
        # Belt-and-braces: also wipe the raw CONFIG_DB key in case the CLI was
        # rejected on this device (e.g. ANCHOR_PREFIX on a non-spine).
        delete_config_db_key_directly(duthost, prefix_type, prefix)


# ---------------------------------------------------------------------------
# Fixtures for picking duthosts by role.
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def rand_one_uplink_duthost(duthosts):
    """Pick one UpstreamLC / UpperSpineRouter duthost. Skip otherwise."""
    candidates = [
        dh for dh in duthosts
        if not dh.is_supervisor_node() and is_upstream_spine(dh)
    ]
    if not candidates:
        pytest.skip("No UpstreamLC / UpperSpineRouter duthost in this testbed")
    return random.choice(candidates)


@pytest.fixture(scope="module")
def rand_one_non_spine_duthost(duthosts):
    """Pick one non-spine, non-supervisor frontend duthost. Skip otherwise."""
    candidates = [
        dh for dh in duthosts
        if not dh.is_supervisor_node() and not is_upstream_spine(dh)
    ]
    if not candidates:
        pytest.skip("No non-spine frontend duthost in this testbed")
    return random.choice(candidates)


@pytest.fixture(scope="module")
def rand_one_frontend_duthost(duthosts):
    """Pick any frontend (non-supervisor) duthost."""
    candidates = [dh for dh in duthosts if not dh.is_supervisor_node()]
    if not candidates:
        pytest.skip("No frontend duthost in this testbed")
    return random.choice(candidates)


@pytest.fixture(scope="module")
def supervisor_duthost(duthosts):
    """Return the chassis supervisor duthost (skip on non-chassis testbeds)."""
    candidates = [dh for dh in duthosts if dh.is_supervisor_node()]
    if not candidates:
        pytest.skip("Testbed has no chassis supervisor")
    return candidates[0]


# ---------------------------------------------------------------------------
# Tests - Regression for ANCHOR_PREFIX
# ---------------------------------------------------------------------------

class TestAnchorPrefixRegression:
    """Regression coverage for ANCHOR_PREFIX (TC-A1, TC-A3, TC-A4, TC-A5).

    TC-A2 - re-run of the existing data-plane test ``test_prefix_list.py`` -
    has no new code by design and is therefore tracked in the test plan only.
    """

    def test_anchor_prefix_cli_round_trip(self, rand_one_uplink_duthost, prefix_cleanup):
        """TC-A1: prefix_list add/remove/status round-trip on an UpstreamLC."""
        duthost = rand_one_uplink_duthost
        v4 = ANCHOR_TEST_PREFIXES["ipv4"]
        v6 = ANCHOR_TEST_PREFIXES["ipv6"]

        for prefix in (v4, v6):
            prefix_cleanup(duthost, ANCHOR_TYPE, prefix)
            result = op_prefix_with_cmd(duthost, ANCHOR_TYPE, prefix, "add")
            pytest_assert(result["rc"] == 0,
                          "prefix_list add failed for {}: {}".format(prefix, result))

        # Status must show both prefixes once per frontend asic.
        pytest_assert(verify_status_contains(duthost, ANCHOR_TYPE, v4),
                      "ANCHOR v4 prefix not in `prefix_list status` output")
        pytest_assert(verify_status_contains(duthost, ANCHOR_TYPE, v6),
                      "ANCHOR v6 prefix not in `prefix_list status` output")

        # CONFIG_DB must have the keys.
        pytest_assert(verify_config_db_entry(duthost, ANCHOR_TYPE, v4, present=True),
                      "ANCHOR v4 missing from CONFIG_DB")
        pytest_assert(verify_config_db_entry(duthost, ANCHOR_TYPE, v6, present=True),
                      "ANCHOR v6 missing from CONFIG_DB")

        # FRR must render under the default ANCHOR_CONTRIBUTING_ROUTES name.
        pytest_assert(
            wait_until(
                30, 5, 0,
                verify_frr_prefix_list_entry,
                duthost, DEFAULT_ANCHOR_PL_NAME, v4, "ip", True,
            ),
            "ANCHOR v4 prefix did not appear in FRR prefix-list {}".format(
                DEFAULT_ANCHOR_PL_NAME),
        )
        pytest_assert(
            wait_until(
                30, 5, 0,
                verify_frr_prefix_list_entry,
                duthost, DEFAULT_ANCHOR_PL_NAME, v6, "ipv6", True,
            ),
            "ANCHOR v6 prefix did not appear in FRR prefix-list {}".format(
                DEFAULT_ANCHOR_PL_NAME),
        )

        # Remove and re-verify cleanup of all three views.
        for prefix in (v4, v6):
            result = op_prefix_with_cmd(duthost, ANCHOR_TYPE, prefix, "remove")
            pytest_assert(result["rc"] == 0,
                          "prefix_list remove failed for {}: {}".format(prefix, result))

        pytest_assert(verify_config_db_entry(duthost, ANCHOR_TYPE, v4, present=False),
                      "ANCHOR v4 key still in CONFIG_DB after remove")
        pytest_assert(verify_config_db_entry(duthost, ANCHOR_TYPE, v6, present=False),
                      "ANCHOR v6 key still in CONFIG_DB after remove")
        pytest_assert(
            wait_until(
                30, 5, 0,
                verify_frr_prefix_list_entry,
                duthost, DEFAULT_ANCHOR_PL_NAME, v4, "ip", False,
            ),
            "ANCHOR v4 still in FRR prefix-list after remove",
        )
        pytest_assert(
            wait_until(
                30, 5, 0,
                verify_frr_prefix_list_entry,
                duthost, DEFAULT_ANCHOR_PL_NAME, v6, "ipv6", False,
            ),
            "ANCHOR v6 still in FRR prefix-list after remove",
        )

    def test_anchor_prefix_rejected_on_non_spine_cli(self, rand_one_non_spine_duthost):
        """TC-A3 (part 1): CLI rejects ANCHOR_PREFIX on a non-spine device."""
        duthost = rand_one_non_spine_duthost
        prefix = ANCHOR_TEST_PREFIXES["ipv4"]

        result = op_prefix_with_cmd(
            duthost, ANCHOR_TYPE, prefix, "add", ignore_error=True
        )
        pytest_assert(
            result["rc"] != 0,
            "prefix_list add ANCHOR_PREFIX must fail on a non-spine device, "
            "got rc={} stdout={} stderr={}".format(
                result["rc"], result["stdout"], result["stderr"]),
        )
        stderr = result.get("stderr", "")
        pytest_assert(
            "Prefix type '{}' is not supported on device type".format(ANCHOR_TYPE)
            in stderr,
            "Unexpected CLI error message: {!r}".format(stderr),
        )
        pytest_assert(
            verify_config_db_entry(duthost, ANCHOR_TYPE, prefix, present=False),
            "ANCHOR_PREFIX leaked into CONFIG_DB despite CLI rejection",
        )

    def test_anchor_prefix_rejected_on_non_spine_direct_db(
            self, rand_one_non_spine_duthost):
        """TC-A3 (part 2): direct CONFIG_DB writes on a non-spine device must
        not render ANCHOR_PREFIX into FRR, and bgpcfgd must stay alive."""
        duthost = rand_one_non_spine_duthost
        prefix = ANCHOR_TEST_PREFIXES["ipv4"]

        try:
            write_config_db_key_directly(duthost, ANCHOR_TYPE, prefix)
            time.sleep(5)

            # FRR should NOT have rendered any ANCHOR entry.
            pytest_assert(
                verify_frr_prefix_list_entry(
                    duthost, DEFAULT_ANCHOR_PL_NAME, prefix, "ip", present=False),
                "ANCHOR_PREFIX appeared in FRR on a non-spine device",
            )
            # bgpcfgd must remain RUNNING. On multi-ASIC the per-ASIC bgpcfgd
            # may briefly transition through STARTING/BACKOFF when supervisor
            # restarts it after seeing the unsupported type; we tolerate that
            # transient blip and only fail if it does not return to RUNNING.
            pytest_assert(
                wait_until(60, BGPCFGD_RUNNING_INTERVAL, 0,
                           bgpcfgd_running, duthost),
                "bgpcfgd did not return to RUNNING after invalid "
                "ANCHOR_PREFIX write",
            )
        finally:
            delete_config_db_key_directly(duthost, ANCHOR_TYPE, prefix)

    def test_anchor_prefix_persists_through_reload(
            self, rand_one_uplink_duthost, prefix_cleanup):
        """TC-A4: ANCHOR_PREFIX survives ``config reload`` and ``docker restart bgp``."""
        duthost = rand_one_uplink_duthost
        v4 = ANCHOR_TEST_PREFIXES["ipv4"]

        prefix_cleanup(duthost, ANCHOR_TYPE, v4)
        pytest_assert(
            op_prefix_with_cmd(duthost, ANCHOR_TYPE, v4, "add")["rc"] == 0,
            "ANCHOR_PREFIX add failed",
        )
        pytest_assert(
            wait_until(
                30, 5, 0,
                verify_frr_prefix_list_entry,
                duthost, DEFAULT_ANCHOR_PL_NAME, v4, "ip", True,
            ),
            "ANCHOR_PREFIX did not show up in FRR before persistence step",
        )

        try:
            duthost.shell("sudo config save -y")
            config_reload(duthost, safe_reload=True, wait_for_bgp=True)
            wait_for_bgpcfgd(duthost)

            pytest_assert(
                verify_config_db_entry(duthost, ANCHOR_TYPE, v4, present=True),
                "ANCHOR_PREFIX missing from CONFIG_DB after config reload",
            )
            pytest_assert(
                wait_until(
                    60, 5, 0,
                    verify_frr_prefix_list_entry,
                    duthost, DEFAULT_ANCHOR_PL_NAME, v4, "ip", True,
                ),
                "ANCHOR_PREFIX missing from FRR after config reload",
            )

            restart_bgp_container(duthost)
            pytest_assert(
                wait_until(
                    60, 5, 0,
                    verify_frr_prefix_list_entry,
                    duthost, DEFAULT_ANCHOR_PL_NAME, v4, "ip", True,
                ),
                "ANCHOR_PREFIX missing from FRR after docker restart bgp",
            )
        finally:
            op_prefix_with_cmd(duthost, ANCHOR_TYPE, v4, "remove", ignore_error=True)
            duthost.shell("sudo config save -y", module_ignore_errors=True)

    def test_prefix_list_mgr_running_on_every_device(self, rand_one_frontend_duthost):
        """TC-A5: PrefixListMgr is now started unconditionally; old log line
        must be gone; bgpcfgd must be healthy.

        We restart ``bgpcfgd`` one container at a time, placing a unique
        syslog marker before each restart. This scopes every assertion to
        exactly the log output from that container's fresh bgpcfgd startup,
        eliminating false positives from stale lines in a previous image.
        Uses /var/log/syslog (not journalctl) so it works on multi-ASIC
        chassis where container daemons log via rsyslog.
        """
        duthost = rand_one_frontend_duthost
        spine = is_upstream_spine(duthost)

        for container in bgp_container_names(duthost):
            # Place marker, restart bgpcfgd, wait for it to come back
            marker = place_syslog_marker(duthost)
            duthost.shell(
                "sudo docker exec {} supervisorctl restart bgpcfgd".format(
                    container),
                module_ignore_errors=True,
            )
            sonichost = getattr(duthost, "sonichost", duthost)
            pytest_assert(
                wait_until(180, 5, 0,
                           lambda c=container: sonichost.is_service_running(
                               "bgpcfgd", c)),
                "bgpcfgd not RUNNING in {} within 180s".format(container),
            )

            # The pre-PR notice was tied to UpperSpineRouter/UpstreamLC and
            # should no longer appear at all after a fresh bgpcfgd startup.
            legacy = collect_syslog_since_marker(
                duthost, marker,
                "Prefix List Manager and AsPath Manager are enabled for "
                "UpperSpineRouter/UpstreamLC",
            )
            pytest_assert(
                not legacy.strip(),
                "Legacy 'Prefix List Manager and AsPath Manager are enabled'"
                " log line still produced after bgpcfgd restart in {} on"
                " {}:\n{}".format(container, duthost.hostname, legacy),
            )

            # On spine devices the new "AsPath Manager is enabled for <TYPE>"
            # line must appear. On non-spine devices it must not.
            if spine:
                new_line = collect_syslog_since_marker(
                    duthost, marker,
                    "AsPath Manager is enabled for",
                )
                pytest_assert(
                    new_line.strip(),
                    "Expected 'AsPath Manager is enabled for <DEVICE_TYPE>'"
                    " log line on spine device {} after bgpcfgd restart in"
                    " {}".format(duthost.hostname, container),
                )

            # bgpcfgd must not have logged a traceback since the restart.
            tracebacks = collect_syslog_since_marker(
                duthost, marker, "bgpcfgd.*Traceback",
            )
            pytest_assert(
                not tracebacks.strip(),
                "bgpcfgd recorded a traceback after restart in {} on"
                " {}:\n{}".format(container, duthost.hostname, tracebacks),
            )


# ---------------------------------------------------------------------------
# Tests - SUPPRESS_PREFIX
# ---------------------------------------------------------------------------

class TestSuppressPrefix:
    """Coverage for the new SUPPRESS_PREFIX type (TC-S1 .. TC-S6)."""

    @pytest.fixture(params=["ipv4", "ipv6"])
    def ip_version(self, request):
        return request.param

    def test_suppress_prefix_cli_round_trip(
            self, rand_one_frontend_duthost, prefix_cleanup):
        """TC-S1: SUPPRESS_PREFIX add/remove/status on any device."""
        duthost = rand_one_frontend_duthost
        v4 = SUPPRESS_TEST_PREFIXES["ipv4"]
        v6 = SUPPRESS_TEST_PREFIXES["ipv6"]

        for prefix in (v4, v6):
            prefix_cleanup(duthost, SUPPRESS_TYPE, prefix)
            result = op_prefix_with_cmd(duthost, SUPPRESS_TYPE, prefix, "add")
            pytest_assert(result["rc"] == 0,
                          "SUPPRESS_PREFIX add failed for {}: {}".format(prefix, result))

        pytest_assert(verify_status_contains(duthost, SUPPRESS_TYPE, v4),
                      "SUPPRESS v4 prefix not in `prefix_list status` output")
        pytest_assert(verify_status_contains(duthost, SUPPRESS_TYPE, v6),
                      "SUPPRESS v6 prefix not in `prefix_list status` output")
        pytest_assert(verify_config_db_entry(duthost, SUPPRESS_TYPE, v4, present=True),
                      "SUPPRESS v4 missing from CONFIG_DB")
        pytest_assert(verify_config_db_entry(duthost, SUPPRESS_TYPE, v6, present=True),
                      "SUPPRESS v6 missing from CONFIG_DB")

        for prefix in (v4, v6):
            pytest_assert(
                op_prefix_with_cmd(duthost, SUPPRESS_TYPE, prefix, "remove")["rc"] == 0,
                "SUPPRESS_PREFIX remove failed for {}".format(prefix),
            )
        pytest_assert(verify_config_db_entry(duthost, SUPPRESS_TYPE, v4, present=False),
                      "SUPPRESS v4 still in CONFIG_DB after remove")
        pytest_assert(verify_config_db_entry(duthost, SUPPRESS_TYPE, v6, present=False),
                      "SUPPRESS v6 still in CONFIG_DB after remove")

    def test_suppress_prefix_frr_rendering(
            self, rand_one_frontend_duthost, prefix_cleanup, ip_version):
        """TC-S2: SUPPRESS_PREFIX renders into FRR under the constants-derived
        name, for both IPv4 and IPv6."""
        duthost = rand_one_frontend_duthost
        prefix = SUPPRESS_TEST_PREFIXES[ip_version]
        ipv = "ip" if ip_version == "ipv4" else "ipv6"
        ipv4_name, ipv6_name = get_suppress_pl_names(duthost)
        pl_name = ipv4_name if ip_version == "ipv4" else ipv6_name

        prefix_cleanup(duthost, SUPPRESS_TYPE, prefix)
        pytest_assert(
            op_prefix_with_cmd(duthost, SUPPRESS_TYPE, prefix, "add")["rc"] == 0,
            "SUPPRESS_PREFIX add failed for {}".format(prefix),
        )

        pytest_assert(
            wait_until(
                30, 5, 0,
                verify_frr_prefix_list_entry,
                duthost, pl_name, prefix, ipv, True,
            ),
            "Did not see {} permit {} in FRR".format(pl_name, prefix),
        )

        pytest_assert(
            op_prefix_with_cmd(duthost, SUPPRESS_TYPE, prefix, "remove")["rc"] == 0,
            "SUPPRESS_PREFIX remove failed for {}".format(prefix),
        )
        pytest_assert(
            wait_until(
                30, 5, 0,
                verify_frr_prefix_list_entry,
                duthost, pl_name, prefix, ipv, False,
            ),
            "FRR still has {} permit {} after remove".format(pl_name, prefix),
        )

    def test_suppress_prefix_on_non_spine_device(
            self, rand_one_non_spine_duthost, prefix_cleanup):
        """TC-S3: SUPPRESS_PREFIX is allowed on non-spine devices via both the
        CLI and a direct CONFIG_DB write, and never emits the
        ``Device type ... not supported for SUPPRESS_PREFIX`` warning."""
        duthost = rand_one_non_spine_duthost
        prefix = SUPPRESS_TEST_PREFIXES["ipv4"]
        ipv4_name, _ = get_suppress_pl_names(duthost)

        # --- CLI path ---
        prefix_cleanup(duthost, SUPPRESS_TYPE, prefix)
        pytest_assert(
            op_prefix_with_cmd(duthost, SUPPRESS_TYPE, prefix, "add")["rc"] == 0,
            "SUPPRESS_PREFIX rejected by CLI on non-spine device",
        )
        pytest_assert(
            wait_until(
                30, 5, 0,
                verify_frr_prefix_list_entry,
                duthost, ipv4_name, prefix, "ip", True,
            ),
            "SUPPRESS_PREFIX did not appear in FRR on non-spine device",
        )
        op_prefix_with_cmd(duthost, SUPPRESS_TYPE, prefix, "remove")

        # --- Direct CONFIG_DB path ---
        try:
            marker = place_syslog_marker(duthost)
            write_config_db_key_directly(duthost, SUPPRESS_TYPE, prefix)
            pytest_assert(
                wait_until(
                    30, 5, 0,
                    verify_frr_prefix_list_entry,
                    duthost, ipv4_name, prefix, "ip", True,
                ),
                "SUPPRESS_PREFIX not picked up by PrefixListMgr from direct DB write",
            )
            unwanted_warn = collect_syslog_since_marker(
                duthost, marker,
                "PrefixListMgr:: Device type .* not supported for {}".format(
                    SUPPRESS_TYPE),
            )
            pytest_assert(
                not unwanted_warn.strip(),
                "Unexpected device-gating warning for SUPPRESS_PREFIX:\n{}".format(
                    unwanted_warn),
            )
        finally:
            delete_config_db_key_directly(duthost, SUPPRESS_TYPE, prefix)

    @pytest.fixture
    def constants_override(self, rand_one_non_spine_duthost):
        """Inject custom SUPPRESS_PREFIX names into constants.yml, restart bgp,
        and restore on teardown."""
        duthost = rand_one_non_spine_duthost
        pytest_require(
            duthost.stat(path=CONSTANTS_FILE)["stat"]["exists"],
            "constants.yml not present on DUT",
        )

        original = duthost.shell("sudo cat {}".format(CONSTANTS_FILE))["stdout"]
        data = yaml.safe_load(original) or {}
        constants = data.setdefault("constants", {})
        bgp = constants.setdefault("bgp", {})
        pl = bgp.setdefault("prefix_list", {})
        pl[SUPPRESS_TYPE] = {
            "ipv4_name": CUSTOM_SUPPRESS_IPV4_NAME,
            "ipv6_name": CUSTOM_SUPPRESS_IPV6_NAME,
        }
        new_yaml = yaml.safe_dump(data, default_flow_style=False)

        backup_path = "/tmp/constants.yml.prefix_list_test.bak"
        duthost.shell("sudo cp {} {}".format(CONSTANTS_FILE, backup_path))
        duthost.copy(content=new_yaml, dest=CONSTANTS_FILE)
        apply_constants_to_bgpcfgd(duthost)

        yield duthost

        duthost.shell("sudo cp {} {}".format(backup_path, CONSTANTS_FILE))
        duthost.shell("sudo rm -f {}".format(backup_path), module_ignore_errors=True)
        apply_constants_to_bgpcfgd(duthost)

    def test_suppress_prefix_constants_override(
            self, constants_override, prefix_cleanup):
        """TC-S4: ``constants.yml`` override is honored and default names are
        no longer used."""
        duthost = constants_override
        v4 = SUPPRESS_TEST_PREFIXES["ipv4"]
        v6 = SUPPRESS_TEST_PREFIXES["ipv6"]

        for prefix in (v4, v6):
            prefix_cleanup(duthost, SUPPRESS_TYPE, prefix)
            pytest_assert(
                op_prefix_with_cmd(duthost, SUPPRESS_TYPE, prefix, "add")["rc"] == 0,
                "SUPPRESS_PREFIX add failed for {}".format(prefix),
            )

        # Custom names must appear.
        pytest_assert(
            wait_until(
                30, 5, 0,
                verify_frr_prefix_list_entry,
                duthost, CUSTOM_SUPPRESS_IPV4_NAME, v4, "ip", True,
            ),
            "Custom IPv4 prefix-list name not used after constants.yml override",
        )
        pytest_assert(
            wait_until(
                30, 5, 0,
                verify_frr_prefix_list_entry,
                duthost, CUSTOM_SUPPRESS_IPV6_NAME, v6, "ipv6", True,
            ),
            "Custom IPv6 prefix-list name not used after constants.yml override",
        )

        # Default names must NOT appear.
        pytest_assert(
            verify_frr_prefix_list_entry(
                duthost, DEFAULT_SUPPRESS_IPV4_NAME, v4, "ip", present=False),
            "Default IPv4 prefix-list name still rendered when override is set",
        )
        pytest_assert(
            verify_frr_prefix_list_entry(
                duthost, DEFAULT_SUPPRESS_IPV6_NAME, v6, "ipv6", present=False),
            "Default IPv6 prefix-list name still rendered when override is set",
        )

    @pytest.fixture
    def constants_without_prefix_list(self, rand_one_non_spine_duthost):
        """Strip ``bgp.prefix_list`` from constants.yml to exercise the registry
        fallback path. Restore on teardown."""
        duthost = rand_one_non_spine_duthost
        pytest_require(
            duthost.stat(path=CONSTANTS_FILE)["stat"]["exists"],
            "constants.yml not present on DUT",
        )

        original = duthost.shell("sudo cat {}".format(CONSTANTS_FILE))["stdout"]
        data = yaml.safe_load(original) or {}
        bgp = data.get("constants", {}).get("bgp", {})
        had_section = "prefix_list" in bgp
        bgp.pop("prefix_list", None)
        new_yaml = yaml.safe_dump(data, default_flow_style=False)

        backup_path = "/tmp/constants.yml.prefix_list_fallback.bak"
        duthost.shell("sudo cp {} {}".format(CONSTANTS_FILE, backup_path))
        duthost.copy(content=new_yaml, dest=CONSTANTS_FILE)
        apply_constants_to_bgpcfgd(duthost)

        yield duthost, had_section

        duthost.shell("sudo cp {} {}".format(backup_path, CONSTANTS_FILE))
        duthost.shell("sudo rm -f {}".format(backup_path), module_ignore_errors=True)
        apply_constants_to_bgpcfgd(duthost)

    def test_suppress_prefix_constants_fallback(
            self, constants_without_prefix_list, prefix_cleanup):
        """TC-S5: without a ``bgp.prefix_list`` block, the registry defaults
        are used.

        Requires the DUT's original ``constants.yml`` to actually contain
        a ``bgp.prefix_list`` section: otherwise the fixture has nothing
        to strip and the test would pass trivially without exercising
        the fallback code path.
        """
        duthost, had_section = constants_without_prefix_list
        pytest_require(
            had_section,
            "constants.yml on {} did not originally contain a bgp.prefix_list "
            "block, so the registry-fallback path was already in effect; "
            "skipping to avoid a trivially-passing test".format(duthost.hostname),
        )
        v4 = SUPPRESS_TEST_PREFIXES["ipv4"]

        prefix_cleanup(duthost, SUPPRESS_TYPE, v4)
        pytest_assert(
            op_prefix_with_cmd(duthost, SUPPRESS_TYPE, v4, "add")["rc"] == 0,
            "SUPPRESS_PREFIX add failed in fallback test",
        )
        pytest_assert(
            wait_until(
                30, 5, 0,
                verify_frr_prefix_list_entry,
                duthost, DEFAULT_SUPPRESS_IPV4_NAME, v4, "ip", True,
            ),
            "Registry-default SUPPRESS_IPV4_PREFIX name was not used as fallback",
        )

    def test_suppress_prefix_persists_through_reload(
            self, rand_one_non_spine_duthost, prefix_cleanup):
        """TC-S6: SUPPRESS_PREFIX survives ``config reload`` and
        ``docker restart bgp``."""
        duthost = rand_one_non_spine_duthost
        v4 = SUPPRESS_TEST_PREFIXES["ipv4"]
        v6 = SUPPRESS_TEST_PREFIXES["ipv6"]
        ipv4_name, ipv6_name = get_suppress_pl_names(duthost)

        for prefix in (v4, v6):
            prefix_cleanup(duthost, SUPPRESS_TYPE, prefix)
            pytest_assert(
                op_prefix_with_cmd(duthost, SUPPRESS_TYPE, prefix, "add")["rc"] == 0,
                "SUPPRESS_PREFIX add failed for {}".format(prefix),
            )

        try:
            duthost.shell("sudo config save -y")
            config_reload(duthost, safe_reload=True, wait_for_bgp=True)
            wait_for_bgpcfgd(duthost)

            pytest_assert(
                wait_until(
                    60, 5, 0,
                    verify_frr_prefix_list_entry,
                    duthost, ipv4_name, v4, "ip", True,
                ),
                "SUPPRESS_PREFIX v4 missing from FRR after config reload",
            )
            pytest_assert(
                wait_until(
                    60, 5, 0,
                    verify_frr_prefix_list_entry,
                    duthost, ipv6_name, v6, "ipv6", True,
                ),
                "SUPPRESS_PREFIX v6 missing from FRR after config reload",
            )

            restart_bgp_container(duthost)
            pytest_assert(
                wait_until(
                    60, 5, 0,
                    verify_frr_prefix_list_entry,
                    duthost, ipv4_name, v4, "ip", True,
                ),
                "SUPPRESS_PREFIX v4 missing from FRR after docker restart bgp",
            )
            pytest_assert(
                wait_until(
                    60, 5, 0,
                    verify_frr_prefix_list_entry,
                    duthost, ipv6_name, v6, "ipv6", True,
                ),
                "SUPPRESS_PREFIX v6 missing from FRR after docker restart bgp",
            )
        finally:
            for prefix in (v4, v6):
                op_prefix_with_cmd(
                    duthost, SUPPRESS_TYPE, prefix, "remove", ignore_error=True,
                )
            duthost.shell("sudo config save -y", module_ignore_errors=True)


# ---------------------------------------------------------------------------
# Tests - Negative / Validation
# ---------------------------------------------------------------------------

class TestPrefixListNegative:
    """Negative / validation tests (TC-N1 .. TC-N5)."""

    def test_unknown_prefix_type_rejected_by_cli(self, rand_one_frontend_duthost):
        """TC-N1: the CLI's ``validate_operation`` rejects unknown types.

        On internal-202511 the ``prefix_list`` CLI does not exit non-zero on
        rejection: it prints the usage text to stdout and
        ``Invalid parameter <type>, Prefix type not supported`` to stderr,
        and crucially does *not* write the key to CONFIG_DB. We treat that
        - or a non-zero rc - as a valid rejection and additionally assert
        that CONFIG_DB stays clean."""
        duthost = rand_one_frontend_duthost
        result = op_prefix_with_cmd(
            duthost, UNKNOWN_TYPE, "10.0.0.0/24", "add", ignore_error=True,
        )
        combined = result.get("stderr", "") + "\n" + result.get("stdout", "")
        rejected = (
            result["rc"] != 0
            or "Prefix type not supported" in combined
            or "Invalid parameter" in combined
        )
        pytest_assert(
            rejected,
            "CLI must reject UNKNOWN type, got: {}".format(result),
        )
        pytest_assert(
            verify_config_db_entry(duthost, UNKNOWN_TYPE, "10.0.0.0/24", present=False),
            "Unknown-type key leaked into CONFIG_DB",
        )

    def test_unknown_prefix_type_via_direct_db_write(self, rand_one_frontend_duthost):
        """TC-N2: direct CONFIG_DB writes of an unknown type never modify FRR;
        bgpcfgd stays up."""
        duthost = rand_one_frontend_duthost
        bad_prefix = "10.0.0.0/24"

        try:
            write_config_db_key_directly(duthost, UNKNOWN_TYPE, bad_prefix)
            time.sleep(5)
            # On multi-ASIC bgpcfgd can briefly transition through
            # STARTING/BACKOFF when supervisor restarts it; tolerate the
            # blip and only fail on a permanent crash loop.
            pytest_assert(
                wait_until(60, BGPCFGD_RUNNING_INTERVAL, 0,
                           bgpcfgd_running, duthost),
                "bgpcfgd did not return to RUNNING after unknown-type write",
            )
            # Defensive: the unknown name must not appear in any FRR prefix-list.
            for asic_index in duthost.get_frontend_asic_ids():
                ns = asic_ns_for_vtysh(duthost, asic_index)
                out = duthost.shell(
                    'vtysh {} -c "show running-config" | grep prefix-list '
                    '| grep -i {} || true'.format(ns, UNKNOWN_TYPE),
                )["stdout"]
                pytest_assert(
                    not out.strip(),
                    "FRR rendered an entry for unknown type {}: {}".format(
                        UNKNOWN_TYPE, out),
                )
        finally:
            delete_config_db_key_directly(duthost, UNKNOWN_TYPE, bad_prefix)

    def test_malformed_prefix_rejected_via_cli(
            self, rand_one_frontend_duthost, prefix_cleanup):
        """TC-N3 (part 1): a malformed prefix never makes it through the
        ``prefix_list add`` pipeline as a usable entry.

        The CLI on some SONiC branches validates the prefix string at parse
        time (rc != 0); on others it just writes the raw value into CONFIG_DB
        and relies on PrefixListMgr to reject it. Either behavior is
        acceptable; the contract we test is:

          * either the CLI rejects the input (rc != 0), OR
                    * the CLI accepts it but FRR never renders the bad entry, and
                        bgpcfgd stays alive.
        """
        duthost = rand_one_frontend_duthost
        # Track the bad key for teardown regardless of which path the CLI
        # takes, so the malformed entry never leaks into CONFIG_DB / breaks
        # post-test YANG validation.
        prefix_cleanup(duthost, SUPPRESS_TYPE, MALFORMED_PREFIX)

        result = op_prefix_with_cmd(
            duthost, SUPPRESS_TYPE, MALFORMED_PREFIX, "add", ignore_error=True,
        )

        if result["rc"] != 0:
            # Path A: CLI parse-time rejection. CONFIG_DB must be clean.
            pytest_assert(
                verify_config_db_entry(
                    duthost, SUPPRESS_TYPE, MALFORMED_PREFIX, present=False),
                "CLI rejected the malformed prefix but key still in CONFIG_DB",
            )
            return

        # Path B: CLI accepted the malformed input. PrefixListMgr must not
        # render it into FRR, and bgpcfgd must stay healthy (we allow a
        # transient restart, only fail on a permanent crash loop).
        time.sleep(5)
        pytest_assert(
            wait_until(60, BGPCFGD_RUNNING_INTERVAL, 0,
                       bgpcfgd_running, duthost),
            "bgpcfgd did not return to RUNNING after CLI accepted malformed prefix",
        )
        for asic_index in duthost.get_frontend_asic_ids():
            ns = asic_ns_for_vtysh(duthost, asic_index)
            out = duthost.shell(
                'vtysh {} -c "show running-config" | grep prefix-list '
                '| grep -F {!r} || true'.format(ns, MALFORMED_PREFIX),
            )["stdout"]
            pytest_assert(
                not out.strip(),
                "FRR rendered an entry for the malformed prefix {} on "
                "asic {}: {}".format(MALFORMED_PREFIX, asic_index, out),
            )

    def test_malformed_prefix_via_direct_db_write(self, rand_one_frontend_duthost):
        """TC-N3 (part 2): direct DB write of a malformed prefix leaves FRR
        unchanged and bgpcfgd running."""
        duthost = rand_one_frontend_duthost
        try:
            write_config_db_key_directly(duthost, SUPPRESS_TYPE, DB_ONLY_BAD_PREFIX)
            time.sleep(5)
            # On multi-ASIC bgpcfgd can briefly transition through
            # STARTING/BACKOFF when supervisor restarts it; tolerate the
            # blip and only fail on a permanent crash loop.
            pytest_assert(
                wait_until(60, BGPCFGD_RUNNING_INTERVAL, 0,
                           bgpcfgd_running, duthost),
                "bgpcfgd did not return to RUNNING after malformed-prefix write",
            )
            for asic_index in duthost.get_frontend_asic_ids():
                ns = asic_ns_for_vtysh(duthost, asic_index)
                out = duthost.shell(
                    'vtysh {} -c "show running-config" | grep prefix-list '
                    '| grep -F {!r} || true'.format(ns, DB_ONLY_BAD_PREFIX),
                )["stdout"]
                pytest_assert(
                    not out.strip(),
                    "FRR rendered an entry for the malformed prefix {} on "
                    "asic {}: {}".format(DB_ONLY_BAD_PREFIX, asic_index, out),
                )
        finally:
            delete_config_db_key_directly(duthost, SUPPRESS_TYPE, DB_ONLY_BAD_PREFIX)

    def test_status_allowed_on_every_device(self, rand_one_frontend_duthost):
        """TC-N4: ``prefix_list status`` is read-only and returns exit 0
        regardless of device type, and never modifies CONFIG_DB."""
        duthost = rand_one_frontend_duthost
        before = {
            asic_index: duthost.shell(
                'sonic-db-cli {} CONFIG_DB keys "PREFIX_LIST|*"'.format(
                    asic_ns_for_db_cli(duthost, asic_index)
                ).strip(),
            )["stdout"]
            for asic_index in duthost.get_frontend_asic_ids()
        }

        result = duthost.shell("sudo prefix_list status", module_ignore_errors=True)
        pytest_assert(
            result["rc"] == 0,
            "prefix_list status returned non-zero: {}".format(result),
        )

        after = {
            asic_index: duthost.shell(
                'sonic-db-cli {} CONFIG_DB keys "PREFIX_LIST|*"'.format(
                    asic_ns_for_db_cli(duthost, asic_index)
                ).strip(),
            )["stdout"]
            for asic_index in duthost.get_frontend_asic_ids()
        }
        pytest_assert(
            before == after,
            "prefix_list status modified CONFIG_DB: before={} after={}".format(
                before, after),
        )

    @pytest.mark.topology("t2")
    def test_chassis_supervisor_skip(self, supervisor_duthost):
        """TC-N5: ``skip_chassis_supervisor`` is still honored - every
        ``prefix_list`` invocation on the supervisor returns 0 with the skip
        message, and CONFIG_DB is left untouched."""
        duthost = supervisor_duthost
        pytest_require(
            has_chassisdb_conf(duthost),
            "Supervisor node does not have /etc/sonic/chassisdb.conf",
        )

        for cmd in (
            "sudo prefix_list status",
            "sudo prefix_list add {} 10.0.0.0/24".format(SUPPRESS_TYPE),
            "sudo prefix_list add {} 10.0.0.0/24".format(ANCHOR_TYPE),
        ):
            result = duthost.shell(cmd, module_ignore_errors=True)
            pytest_assert(
                result["rc"] == 0,
                "{!r} did not exit 0 on supervisor: {}".format(cmd, result),
            )
            pytest_assert(
                "Skipping Operation on chassis supervisor" in result["stdout"],
                "Expected skip message not seen on supervisor for {!r}".format(cmd),
            )

        # CONFIG_DB on the supervisor must not have grown a PREFIX_LIST entry.
        sup_keys = duthost.shell(
            'sonic-db-cli CONFIG_DB keys "PREFIX_LIST|*"',
            module_ignore_errors=True,
        )["stdout"]
        pytest_assert(
            not sup_keys.strip(),
            "Supervisor CONFIG_DB got a PREFIX_LIST entry: {}".format(sup_keys),
        )
