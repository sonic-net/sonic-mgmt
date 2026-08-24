import os
import logging
import threading
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

# Thread lock to prevent concurrent archive creation
_archive_lock = threading.Lock()

HOST_ARCHIVE_DIR = "/host"
METADATA_ARCHIVE = "metadata.tar.gz"
UPGRADE_SCRIPTS_ARCHIVE = "upgrade-scripts.tar.gz"
HOST_METADATA_ARCHIVE = os.path.join(HOST_ARCHIVE_DIR, METADATA_ARCHIVE)
HOST_UPGRADE_SCRIPTS_ARCHIVE = os.path.join(
    HOST_ARCHIVE_DIR, UPGRADE_SCRIPTS_ARCHIVE)


def _extract_script_archive(duthost, localhost, host_archive, source_path):
    """Extract a staged archive, or create a fresh one from the checkout."""
    archive_stat = duthost.stat(path=host_archive)
    if archive_stat["stat"]["exists"]:
        duthost.unarchive(src=host_archive, dest="/tmp/anpscripts/", remote_src="yes")
        duthost.file(path=host_archive, state="absent")
        return

    # The fallback archive is local to the test controller, so remote_src must
    # remain unset when Ansible transfers and extracts it.
    with _archive_lock:
        fallback_archive = os.path.basename(host_archive)
        localhost.archive(path=source_path + "/", dest=fallback_archive, exclusion_patterns=[".git"])
        duthost.unarchive(src=fallback_archive, dest="/tmp/anpscripts/")


def _failed_due_to_isc_dhcp_relay_fix_server_inaccessible(result) -> bool:
    """
    Postupgrade actions fetch the DHCP relay from a production server which can't be reached from the test environment.
    We don't want to fail the test in this case. This function checks if the error message indicates that the DHCP
    relay server is inaccessible.
    """
    # The error code returned by the postupgrade_actions script for this type of failure
    postupgrade_dhcp_relay_delay_fix_failure = 138
    rc_matches = result.get("rc") == postupgrade_dhcp_relay_delay_fix_failure
    stderr = result.get("stderr")
    stderr_matches = stderr and "curl: (28) Connection timed out" in stderr
    return rc_matches and stderr_matches


def run_postupgrade_actions(duthost, localhost, tbinfo, metadata_process, skip_postupgrade_actions,
                            check_failed=True, check_stderr=True):
    if not metadata_process:
        duthost.file(path=HOST_UPGRADE_SCRIPTS_ARCHIVE, state="absent")
        return
    if skip_postupgrade_actions:
        logger.info("Skipping postupgrade_actions")
        duthost.file(path=HOST_UPGRADE_SCRIPTS_ARCHIVE, state="absent")
        return
    base_path = os.path.dirname(__file__)
    if "sonic-mgmt-int" in base_path:
        upgrade_scripts_path = os.path.join(base_path, "../../../sonic-upgrade-scripts/sonic-upgrade-scripts")
        postupgrade_actions_data_dir_path = os.path.join(
            base_path,
            "../../../sonic-upgrade-scripts/sonic-upgrade-scripts/postupgrade_actions_data")
        postupgrade_actions_path = os.path.join(
            base_path,
            "../../../sonic-upgrade-scripts/sonic-upgrade-scripts/postupgrade_actions")
    else:
        upgrade_scripts_path = os.path.join(base_path, "../../sonic-upgrade-scripts/sonic-upgrade-scripts")
        postupgrade_actions_data_dir_path = os.path.join(
            base_path,
            "../../sonic-upgrade-scripts/sonic-upgrade-scripts/postupgrade_actions_data")
        postupgrade_actions_path = os.path.join(
            base_path,
            "../../sonic-upgrade-scripts/sonic-upgrade-scripts/postupgrade_actions")
    pytest_assert(os.path.exists(upgrade_scripts_path), "SONiC upgrade scripts not found in {}"
                  .format(upgrade_scripts_path))
    pytest_assert(os.path.exists(postupgrade_actions_path), "SONiC upgrade postupgrade_action script not found in {}"
                  .format(postupgrade_actions_path))
    pytest_assert(os.path.exists(postupgrade_actions_data_dir_path),
                  "SONiC upgrade scripts postupgrade_action data directory not found in {}"
                  .format(postupgrade_actions_data_dir_path))

    logger.info("Step 1 Copy the scripts and data directory to the DUT")
    duthost.file(path="/tmp/anpscripts", state="absent")
    duthost.file(path="/tmp/anpscripts", state="directory")
    _extract_script_archive(
        duthost,
        localhost,
        host_archive=HOST_UPGRADE_SCRIPTS_ARCHIVE,
        source_path=upgrade_scripts_path)

    duthost.command("chmod +x /tmp/anpscripts/postupgrade_actions")
    result = duthost.command("/usr/bin/sudo /tmp/anpscripts/postupgrade_actions", module_ignore_errors=True)
    logger.info("Postupgrade_actions result: {}".format(str(result)))

    errors = None
    if "stderr" in result:
        errors = result.get("stderr")
        platform_info = duthost.command("show platform summary")["stdout"]
        if "DCS-7050CX3-32S" in platform_info and "DCS-7050CX3-32S-SSD" not in platform_info:
            logger.warning("Failed executing postupgrade_actions, not failing due to running on unexpected hardware. "
                           "Errors: {}".format(errors))
        elif _failed_due_to_isc_dhcp_relay_fix_server_inaccessible(result):
            logger.warning("Failed executing postupgrade_actions, "
                           "not failing due to DHCP relay server being inaccessible. Errors: {}".format(errors))

    failed = result.get('failed')

    pytest_assert(not ((check_failed and failed) or (check_stderr and errors)),
                  "Failed executing postupgrade_actions. Errors: {}, Failed: {}".format(errors, failed))
    duthost.command("rm -rf /tmp/anpscripts", module_ignore_errors=True)


def run_bgp_neighbor(duthost, localhost, tbinfo, metadata_process, skip_bgp_neighbor,
                     check_failed=True, check_stderr=True):

    # Known harmless stderr lines to ignore
    HARMLESS_STDERR = [
        "Warning: 'sonic_installer' command is deprecated and will be removed in the future",
        "Please use 'sonic-installer' instead",
    ]
    # vtysh usage warning on multi-ASIC devices (vtysh requires -n <namespace>)
    VTYSH_USAGE_PREFIX = "Usage: /usr/bin/vtysh"

    if not metadata_process or skip_bgp_neighbor:
        logger.info("Skipping bgp_neighbor")
        duthost.file(path=HOST_METADATA_ARCHIVE, state="absent")
        duthost.shell("config bgp startup all")
        return
    base_path = os.path.dirname(__file__)
    if "sonic-mgmt-int" in base_path:
        metadata_scripts_path = os.path.join(base_path, "../../../sonic-metadata/scripts")
        bgp_neighbor_path = os.path.join(base_path, "../../../sonic-metadata/scripts/bgp_neighbor")
    else:
        metadata_scripts_path = os.path.join(base_path, "../../sonic-metadata/scripts")
        bgp_neighbor_path = os.path.join(base_path, "../../sonic-metadata/scripts/bgp_neighbor")
    pytest_assert(os.path.exists(metadata_scripts_path), "SONiC Metadata scripts not found in {}"
                  .format(metadata_scripts_path))
    pytest_assert(os.path.exists(bgp_neighbor_path), "SONiC Metadata bgp_neighbor script not found in {}"
                  .format(bgp_neighbor_path))

    logger.info("Step 1 Copy the script into DUT")
    duthost.file(path="/tmp/anpscripts", state="absent")
    duthost.file(path="/tmp/anpscripts", state="directory")
    _extract_script_archive(
        duthost,
        localhost,
        host_archive=HOST_METADATA_ARCHIVE,
        source_path=metadata_scripts_path)

    duthost.command("chmod +x /tmp/anpscripts/bgp_neighbor")
    result = duthost.command("/usr/bin/sudo /tmp/anpscripts/bgp_neighbor startup 0.0.0.0", module_ignore_errors=True)
    logger.info("bgp_neighbor startup result: {}".format(str(result)))

    errors = None
    if 'stderr' in result:
        # Filter out known harmless stderr lines (deprecation warning, vtysh multi-ASIC usage)
        unexpected_lines = [line for line in result.get('stderr_lines', [])
                            if line not in HARMLESS_STDERR
                            and not line.startswith(VTYSH_USAGE_PREFIX)]
        if unexpected_lines:
            errors = "\n".join(unexpected_lines)

    failed = result.get('failed')

    pytest_assert(not ((check_failed and failed) or (check_stderr and errors)),
                  "Failed executing bgp_neighbor startup. std_err: {}".format(errors))
    duthost.command("rm -rf /tmp/anpscripts", module_ignore_errors=True)
