"""
Tests for `show platform npu techsupport` CLI run as non-sudo user.

The package-installed 90-npu-techsupport (ALL ALL= NOPASSWD: generate_npu_dump) allows
any user to run generate_npu_dump without a password. We create a new user with no
sudo access and verify that user can run show platform npu techsupport (no new
sudoers.d file; only 90-npu-techsupport is used).
"""
import re
import logging
import pytest
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]

# Sudoers file installed by package: allows any user to run generate_npu_dump without password
NPU_TECHSUPPORT_SUDOERS = "/etc/sudoers.d/90-npu-techsupport"

# Name of the test user we create (no sudo; relies on 90-npu-techsupport only)
NPU_TECHSUPPORT_TEST_USER = "npu_tech_test"

# Default group: expected dump file name substrings from npu-techsupport.yaml (default group).
# Filenames are derived from show commands (e.g. "show platform npu global" -> platform.npu.global).
DEFAULT_GROUP_EXPECTED_IN_DUMP = [
    "platform.npu.global",
    "platform.npu.asic-errors",
    "platform.npu.counters",
    "platform.npu.event-trap",
    "platform.npu.trap",
    "platform.npu.lpts",
    "platform.npu.oq-debug",
    "platform.npu.rate-check",
    "platform.npu.resource",
    "platform.npu.ecmp",
    "platform.npu.lag.entries",
    "platform.npu.lag.members",
    "platform.npu.next-hop.entries",
    "platform.npu.next-hop.usage",
    "platform.npu.port.entries",
    "platform.npu.port.counters",
    "platform.npu.router.ports",
    "platform.npu.router.details",
    "platform.npu.router.entries",
    "platform.npu.router.port-counters",
    "platform.npu.router.route-table",
    "platform.npu.switch.entries",
    "platform.npu.switch.ports",
    "platform.npu.mac-state",
]

# PFC is always included: expected dump file substrings from inline PFC block.
# Inline block uses random interface from "show pfc priority"; filenames include .-i.<interface>.
# (e.g. platform.npu.rx.-i.Ethernet-BP452.punt), so we match by output type, not exact path.
PFC_EXPECTED_IN_DUMP = [
    "pfc.priority",
    "pfc.counters",
    "pfc.asymmetric",
    "punt",           # rx: platform.npu.rx.-i.<if>.punt
    "cgm_profile",    # rx: platform.npu.rx.-i.<if>.-t.<tc>.cgm_profile
    "cgm_global",     # rx and tx: platform.npu.rx/tx.-i.<if>.cgm_global
    "cgm_state",      # tx: platform.npu.tx.-i.<if>.cgm_state
    "voq_globals",    # single-ASIC: platform.npu.voq.voq_globals; multi-ASIC: ...-n.asic0.voq_globals
]

# Error patterns that must not appear in techsupport stdout or stderr
TECHSUPPORT_ERROR_PATTERNS = [
    "Traceback",
    "Permission denied",
    "failed with RC",
    "Error:",
    "command not found",
]


@pytest.fixture(scope="module")
def npu_techsupport_test_user(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    Create a non-sudo user (no sudo access). That user can still run techsupport
    because 90-npu-techsupport allows ALL users to run generate_npu_dump.
    Teardown removes the user only; no sudoers file is added.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    add_user = f"useradd -r -s /bin/false -M {NPU_TECHSUPPORT_TEST_USER}"
    result = duthost.shell(add_user, module_ignore_errors=True)
    if result["rc"] != 0 and "already exists" not in result.get("stderr", ""):
        pytest.skip(
            f"Could not create test user {NPU_TECHSUPPORT_TEST_USER}: "
            f"{result.get('stderr', result.get('stdout', ''))}"
        )
    yield NPU_TECHSUPPORT_TEST_USER
    duthost.shell(f"userdel -f {NPU_TECHSUPPORT_TEST_USER}", module_ignore_errors=True)


def _techsupport_runs_as_user(duthost, user, extra_args=""):
    """Run show platform npu techsupport as the given user (non-root, no sudo except via 90-npu-techsupport)."""
    cmd = f"sudo -u {user} show platform npu techsupport {extra_args}".strip()
    return duthost.shell(cmd, module_ignore_errors=True)


def _get_dump_path_from_stdout(stdout):
    """Extract generated dump path from techsupport stdout (/var/dump/sonic_npu_dump_*)."""
    match = re.search(r"(/var/dump/sonic_npu_dump_\S+\.tar(?:\.gz)?)", stdout)
    return match.group(1) if match else None


def _list_dump_contents(duthost, tar_path):
    """List files inside the techsupport tar (optionally gzipped)."""
    list_cmd = f"tar -tf {tar_path}" if tar_path.endswith(".tar") else f"tar -tzf {tar_path}"
    result = duthost.shell(list_cmd, module_ignore_errors=True)
    if result["rc"] != 0:
        return []
    return result["stdout"].splitlines()


def _dump_contains_expected_files(duthost, tar_path, expected_substrings):
    """Check that the dump tar contains paths matching the expected substrings (under dump/)."""
    files = _list_dump_contents(duthost, tar_path)
    dump_files = [f for f in files if "dump/" in f]
    found = []
    for sub in expected_substrings:
        if any(sub in f for f in dump_files):
            found.append(sub)
    return found


def _assert_no_error_messages(stdout, stderr, msg_prefix=""):
    """Assert that techsupport output contains no error messages."""
    combined = (stdout or "") + "\n" + (stderr or "")
    combined_lower = combined.lower()
    for pattern in TECHSUPPORT_ERROR_PATTERNS:
        search_in = combined_lower if pattern.islower() or pattern == pattern.lower() else combined
        if pattern.lower() in search_in.lower():
            pytest_assert(
                False,
                f"{msg_prefix}Output should not contain error pattern '{pattern}'"
            )
    if "password" in combined_lower and "sudo" in combined_lower:
        pytest_assert(False, f"{msg_prefix}Output suggests sudo password prompt")


def test_show_platform_npu_techsupport_sudoers_present(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Ensure sudoers rule for generate_npu_dump is installed so techsupport works for non-root.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    result = duthost.shell(f"test -f {NPU_TECHSUPPORT_SUDOERS} && cat {NPU_TECHSUPPORT_SUDOERS}", module_ignore_errors=True)
    if result["rc"] != 0:
        pytest.skip(f"Sudoers file {NPU_TECHSUPPORT_SUDOERS} not found; install sonic-platform-cisco package with npu techsupport sudoers.")
    pytest_assert(
        "generate_npu_dump" in result.get("stdout", ""),
        f"Sudoers file does not allow generate_npu_dump: {result.get('stdout', '')}"
    )


def test_show_platform_npu_techsupport_non_sudo_user(duthosts, enum_rand_one_per_hwsku_hostname,
                                                     npu_techsupport_test_user):
    """
    @summary: Run show platform npu techsupport as a created non-sudo user.
    PFC (rx, tx, voq) is always included; no option to disable. 90-npu-techsupport (ALL)
    allows this user to run generate_npu_dump. Verify no permission error, dump path printed,
    and default + PFC group outputs present in dump.
    """
    from tests.cisco.platform_tests.test_serviceability_basic import check_dshell_client

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    check_dshell_client(duthost)

    result = _techsupport_runs_as_user(duthost, npu_techsupport_test_user)
    stdout = result.get("stdout", "")
    stderr = result.get("stderr", "")
    logging.info("stdout: %s", stdout)
    logging.info("stderr: %s", stderr)
    logging.info("rc: %s", result.get("rc", ""))

    _assert_no_error_messages(stdout, stderr, msg_prefix="")

    dump_path = _get_dump_path_from_stdout(stdout)
    pytest_assert(dump_path, "Techsupport stdout should contain generated dump path (/var/dump/sonic_npu_dump_*)")

    found_default = _dump_contains_expected_files(duthost, dump_path, DEFAULT_GROUP_EXPECTED_IN_DUMP)
    missing_default = [e for e in DEFAULT_GROUP_EXPECTED_IN_DUMP if e not in found_default]
    pytest_assert(
        not missing_default,
        f"Default group outputs missing in dump: {missing_default}"
    )

    found_pfc = _dump_contains_expected_files(duthost, dump_path, PFC_EXPECTED_IN_DUMP)
    missing_pfc = [e for e in PFC_EXPECTED_IN_DUMP if e not in found_pfc]
    pytest_assert(
        not missing_pfc,
        f"Expected PFC (always included) dump to contain: {PFC_EXPECTED_IN_DUMP}; missing in tar: {missing_pfc}"
    )
