"""Helpers for the snapshot warm vs cold boot tests."""

import json
import logging
import os
from typing import Dict
from tests.common.db_comparison import DBType, SnapshotDiff
from tests.common.platform.device_utils import check_neighbors, check_services, get_current_sonic_version, \
    verify_no_coredumps

logger = logging.getLogger(__name__)


def run_presnapshot_checks(duthost, tbinfo):
    """
    Run system stability checks before taking database snapshots.

    Performs a series of validation checks to ensure the system has stabilized
    and is in a consistent state before capturing Redis database snapshots.
    This helps ensure snapshot accuracy and reliability.

    Args:
        duthost: The device under test host object
        tbinfo: Testbed information object containing topology details

    The checks include:
        - Service status verification
        - Neighbor connectivity validation
        - Core dump detection (expecting zero core dumps)
    """

    check_services(duthost)
    check_neighbors(duthost, tbinfo)
    verify_no_coredumps(duthost, 0)


def record_diff(pytest_request, diff: Dict[DBType, SnapshotDiff], base_dir: str, diff_name: str):
    """
    Record snapshot differences to both custom messages and disk files.

    This function processes snapshot differences by writing metrics to pytest
    custom messages for test reporting and saving detailed diff data to disk
    for offline analysis and debugging.

    Args:
        pytest_request: pytest request object for accessing test context
        diff (Dict[DBType, SnapshotDiff]): Dictionary mapping database types
                                          to their corresponding snapshot diffs
        base_dir (str): Base directory path where diff files will be stored
        diff_name (str): Descriptive name for this diff (used in filenames and metrics)
    """

    logger.info(f"Recording diff snapshots with name {diff_name}")

    if not os.path.exists(base_dir):
        os.makedirs(base_dir, exist_ok=True)

    for db_snapshot_diff in diff.values():
        # Record the diff metrics to the custom msg
        db_snapshot_diff.write_metrics_to_custom_msg(pytest_request, msg_suffix=f"warm_vs_cold_boot.{diff_name}")
        # Record the diff snapshot to disk
        db_snapshot_diff.write_snapshot_to_disk(base_dir, diff_name)


def write_upgrade_path_summary(summary_file_path: str, duthost, base_os_version: str):
    """
    Write a summary of the upgrade path information to a JSON file.

    Creates a summary file containing key information about the upgrade test
    including hardware SKU, hostname, and version details for tracking
    and analysis purposes.

    Args:
        summary_file_path (str): Path where the summary JSON file will be written
        duthost: The device under test host object
        base_os_version (str): The base OS version before upgrade
    """
    current_version = get_current_sonic_version(duthost)
    upgrade_path_summary = {
        "hwsku": duthost.facts["hwsku"],
        "hostname": duthost.hostname,
        "base_ver": base_os_version,
        "target_ver": current_version
    }
    with open(summary_file_path, "w") as f:
        json.dump(upgrade_path_summary, f, indent=4)


def backup_device_logs(duthost, backup_dir: str, fetch_logs_before_reboot=False):
    """
    Backup device log files from the DUT to the local filesystem.

    This function fetches log files (syslog, sairedis.rec, swss.rec) from the
    device under test and saves them to a local backup directory. Optionally,
    it can also fetch logs that were saved warm-reboot in the going down path.

    Args:
        duthost: The device under test host object for executing commands
        backup_dir (str): Local directory path where log files will be stored
        fetch_logs_before_reboot (bool, optional): If True, also fetch logs
                                                 from /host/logs_before_reboot.
                                                 Defaults to False.
    """

    def fetch_logs_from_path(source_path: str, dest_dir: str):
        """Fetch log files from a specific path on the DUT to a local directory."""
        log_files_cmd = (f"sudo find {source_path} -type f -regex "
                         "'.*/\(syslog.*\|sairedis.rec.*\|swss.rec.*\)'")  # noqa F401
        log_files = duthost.shell(log_files_cmd)["stdout_lines"]
        os.makedirs(dest_dir, exist_ok=True)
        for log_file in log_files:
            logger.info(f"Fetching log file {log_file} to {dest_dir}")
            dest_path = os.path.join(dest_dir, os.path.basename(log_file))
            duthost.fetch(src=log_file, dest=dest_path, flat=True)

    # Fetch main log files from /var/log
    fetch_logs_from_path("/var/log", backup_dir)

    # Optionally fetch logs from before reboot
    if fetch_logs_before_reboot:
        logs_before_reboot_backup_dir = os.path.join(backup_dir, "logs_before_reboot")
        fetch_logs_from_path("/host/logs_before_reboot", logs_before_reboot_backup_dir)
