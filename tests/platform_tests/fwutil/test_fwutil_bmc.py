import os
import re
import uuid

import pytest

from fwutil_common import (
    BMC_COMPONENT, LATEST_VERSION_IDX, find_pattern, fwutil_log_entry_re, get_bmc_chassis_and_entries,
    get_bmc_fw_version, get_syslog_lines, install_bmc_fw, set_bmc_fw_to_target_version
)
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

pytestmark = [
    pytest.mark.topology("bmc"),
    pytest.mark.disable_memory_utilization,
    # /var/log is a tmpfs on the BMC, so the power cycle these tests perform wipes the syslog
    # marker LogAnalyzer writes at test start, and its extract_log step then fails the test in
    # teardown.
    pytest.mark.disable_loganalyzer,
]

# Error printed by fwutil when a firmware package is invalid / corrupted / fails verification.
FW_INSTALL_FAILED_RE = re.compile(r".*Error: Firmware install failed\.")

# The BMC platform code logs why pldm-fw refused a package, e.g. "BMC firmware install failed: ...:
# Error: PLDM Update error: component version identical to installed image; use --force-update to override".
BMC_INSTALL_FAILED = "BMC firmware install failed"
SAME_VERSION_REASON_RE = re.compile(r"component version identical to installed image")
DOWNGRADE_REASON_RE = re.compile(r"component version downgrade blocked")


def get_unique_pkg_path():
    """
    Return a unique package path, so that the syslog entries that mention it come from this test only.
    """
    return f"/tmp/bmc_fw_{uuid.uuid4().hex[:8]}.fwpkg"


def check_install_rejected(duthost, pkg, reason_re):
    """
    Fail unless fwutil logged a failed install of *pkg*, with the BMC giving a reason matching *reason_re*.
    """
    entry_re = fwutil_log_entry_re("install", pkg, "failure")
    lines = []

    def _rejected():
        lines[:] = get_syslog_lines(duthost, pkg)
        return (any(entry_re.search(line) for line in lines) and
                any(BMC_INSTALL_FAILED in line and reason_re.search(line) for line in lines))

    pytest_assert(wait_until(30, 2, 0, _rejected),
                  f"The BMC syslog does not show the install of {pkg} refused for '{reason_re.pattern}': {lines}")


def get_bmc_entries_or_skip(duthost, fw_pkg, minimum=1):
    """
    Return (chassis, BMC firmware entries), skipping the test when there are not enough of them.
    """
    chassis, entries = get_bmc_chassis_and_entries(duthost, fw_pkg)

    if len(entries) < minimum:
        pytest.skip(f"Need at least {minimum} BMC firmware entries in firmware.json for chassis {chassis}")
    if minimum > 1 and entries[LATEST_VERSION_IDX]["version"] == entries[-1]["version"]:
        pytest.skip("Need two distinct BMC firmware versions in firmware.json")
    return chassis, entries


def get_techsupport_dump_path(duthost):
    """
    Run ``show techsupport`` and return the path of the generated dump archive.
    """
    out = duthost.command("show techsupport")
    for line in reversed(out["stdout_lines"]):
        line = line.strip()
        if line.endswith(".tar.gz") and "sonic_dump" in line:
            return line
    pytest.fail("Could not determine the techsupport dump path from `show techsupport` output")


def check_bmc_version_in_techsupport(duthost, version):
    """
    Fail unless ``version`` appears in the fwutil status file of a freshly collected techsupport.
    """
    pytest_assert(version, "No BMC firmware version reported by `fwutil show status`")

    dump_path = get_techsupport_dump_path(duthost)
    # techsupport stores the `fwutil show status` output in dump/fwutil.status
    status_file = os.path.join(os.path.basename(dump_path)[:-len(".tar.gz")], "dump", "fwutil.status")
    out = duthost.shell(f"tar -xzOf {dump_path} {status_file}", module_ignore_errors=True)

    pytest_assert(out["rc"] == 0, f"techsupport dump {dump_path} does not contain {status_file}")
    pytest_assert(version in out["stdout"],
                  f"BMC version {version} was not captured in {status_file} of techsupport dump {dump_path}")


def upgrade_from_oldest(request, duthost, localhost, pdu_controller, fw_pkg, from_file):
    """Downgrade the BMC to the oldest firmware, then upgrade it back to the newest one.

    A deployed BMC already runs the newest firmware, so the downgrade is what gives the test
    something to upgrade from. Both versions are named explicitly instead of letting call_fwutil
    pick one on its own: the BMC enforces anti-rollback, so stepping back to the oldest build only
    works with --force-update. The conftest fixture restores the newest firmware afterwards.
    """
    chassis, entries = get_bmc_entries_or_skip(duthost, fw_pkg, minimum=2)
    newest = entries[LATEST_VERSION_IDX]

    set_bmc_fw_to_target_version(request, duthost, localhost, pdu_controller, chassis, entries[-1])

    install_bmc_fw(request, duthost, localhost, pdu_controller, chassis, newest, from_file=from_file)
    pytest_assert(get_bmc_fw_version(duthost) == newest["version"],
                  f"BMC firmware was not upgraded to {newest['version']}")


def test_fwutil_bmc_install_upgrade(request, duthost, localhost, pdu_controller, fw_pkg):
    """
    Verify that ``fwutil install`` upgrades the BMC firmware from a package named on the command line.
    """
    upgrade_from_oldest(request, duthost, localhost, pdu_controller, fw_pkg, from_file=True)


def test_fwutil_bmc_update_upgrade(request, duthost, localhost, pdu_controller, fw_pkg):
    """Verify that ``fwutil update`` upgrades the BMC firmware.

    Unlike ``fwutil install`` the package is not named on the command line, fwutil resolves it from
    platform_components.json in the current image.
    """
    upgrade_from_oldest(request, duthost, localhost, pdu_controller, fw_pkg, from_file=False)


@pytest.mark.parametrize("invalid_fw_type", ["not_a_package", "corrupted_package"])
def test_fwutil_bmc_reject_invalid_input(duthost, fw_pkg, invalid_fw_type):
    """
    Verify that fwutil rejects an invalid BMC firmware package and leaves the BMC untouched.
    """
    initial_version = get_bmc_fw_version(duthost)
    pytest_assert(initial_version, "BMC component not found in `fwutil show status` output")

    invalid_fw = "/tmp/bmc_invalid_fw.fwpkg"
    try:
        if invalid_fw_type == "not_a_package":
            # A random blob that is not a firmware package at all.
            duthost.shell(f"head -c 4096 /dev/urandom > {invalid_fw}")
        else:
            # A real firmware package truncated so that it fails verification.
            # Download the full package and keep only the first 1MB to corrupt it.
            _, entries = get_bmc_entries_or_skip(duthost, fw_pkg)
            fw_url = entries[LATEST_VERSION_IDX]["firmware"]
            valid_fw = os.path.join("/tmp", os.path.basename(fw_url))
            duthost.get_url(url=fw_url, dest=valid_fw)
            duthost.shell(f"head -c 1048576 {valid_fw} > {invalid_fw}")
            duthost.command(f"rm -f {valid_fw}", module_ignore_errors=True)

        out = duthost.command(
            f"fwutil install chassis component {BMC_COMPONENT} fw {invalid_fw} -y",
            module_ignore_errors=True)

        pytest_assert(out["rc"] != 0, "fwutil should fail installing invalid firmware, but returned rc=0")
        pytest_assert(find_pattern(out["stdout_lines"] + out["stderr_lines"], FW_INSTALL_FAILED_RE),
                      "Expected 'Error: Firmware install failed.' in the fwutil output")

        # A rejected install must not change the installed firmware.
        pytest_assert(get_bmc_fw_version(duthost) == initial_version,
                      "BMC firmware version changed after a rejected install")
    finally:
        duthost.command(f"rm -f {invalid_fw}", module_ignore_errors=True)


def test_fwutil_bmc_reject_same_version(duthost, fw_pkg):
    """
    Verify that fwutil refuses to install the running BMC firmware version without --force-update.
    """
    initial_version = get_bmc_fw_version(duthost)
    pytest_assert(initial_version, "BMC component not found in `fwutil show status` output")

    _, entries = get_bmc_entries_or_skip(duthost, fw_pkg)
    same = next((e for e in entries if e["version"] == initial_version), None)
    if same is None:
        pytest.skip(f"No firmware entry matching the installed version {initial_version}")

    same_version_pkg = get_unique_pkg_path()
    try:
        duthost.get_url(url=same["firmware"], dest=same_version_pkg)
        out = duthost.command(
            f"fwutil install chassis component {BMC_COMPONENT} fw {same_version_pkg} -y",
            module_ignore_errors=True)

        pytest_assert(out["rc"] != 0,
                      "fwutil should refuse installing the same version without --force-update")
        check_install_rejected(duthost, same_version_pkg, SAME_VERSION_REASON_RE)
        pytest_assert(get_bmc_fw_version(duthost) == initial_version,
                      "BMC firmware version changed after a same-version install attempt")
    finally:
        duthost.command(f"rm -f {same_version_pkg}", module_ignore_errors=True)


@pytest.mark.parametrize("force_downgrade", [False, True])
def test_fwutil_bmc_downgrade(request, duthost, localhost, pdu_controller, fw_pkg, force_downgrade):
    """
    Verify that a BMC firmware downgrade is rejected, and succeeds with ``--force-update``.
    """
    chassis, entries = get_bmc_entries_or_skip(duthost, fw_pkg, minimum=2)
    newest, oldest = entries[LATEST_VERSION_IDX], entries[-1]

    set_bmc_fw_to_target_version(request, duthost, localhost, pdu_controller, chassis, newest)

    if not force_downgrade:
        # Without --force-update, a downgrade must be rejected and leave the version unchanged.
        oldest_pkg = get_unique_pkg_path()
        try:
            duthost.get_url(url=oldest["firmware"], dest=oldest_pkg)
            out = duthost.command(
                f"fwutil install chassis component {BMC_COMPONENT} fw {oldest_pkg} -y",
                module_ignore_errors=True)

            pytest_assert(out["rc"] != 0, "fwutil should refuse a downgrade without --force-update")
            check_install_rejected(duthost, oldest_pkg, DOWNGRADE_REASON_RE)
            pytest_assert(get_bmc_fw_version(duthost) == newest["version"],
                          "BMC firmware version changed after a rejected downgrade")
        finally:
            duthost.command(f"rm -f {oldest_pkg}", module_ignore_errors=True)
        return

    # With --force-update the downgrade succeeds.
    install_bmc_fw(request, duthost, localhost, pdu_controller, chassis, oldest, force=True)


def test_fwutil_bmc_firmware_in_log_and_techsupport(request, duthost, localhost, pdu_controller, fw_pkg):
    """Verify that techsupport captures the BMC firmware version before and after an upgrade.

    That the upgrade is logged is checked by install_bmc_fw() before the power cycle, which wipes the
    BMC syslog.
    """
    chassis, entries = get_bmc_entries_or_skip(duthost, fw_pkg, minimum=2)

    # Check the bmc version is captured before test
    check_bmc_version_in_techsupport(duthost, get_bmc_fw_version(duthost))

    set_bmc_fw_to_target_version(request, duthost, localhost, pdu_controller, chassis, entries[-1])

    # Techsupport captures the current BMC version before the upgrade.
    check_bmc_version_in_techsupport(duthost, get_bmc_fw_version(duthost))

    # Upgrade the BMC firmware to the newest defined version and power-cycle to activate it.
    install_bmc_fw(request, duthost, localhost, pdu_controller, chassis, entries[LATEST_VERSION_IDX])

    # Techsupport captures the (new) BMC version after the upgrade.
    check_bmc_version_in_techsupport(duthost, get_bmc_fw_version(duthost))
