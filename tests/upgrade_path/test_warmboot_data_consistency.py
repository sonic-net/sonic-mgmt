import json
import os
import pytest
import logging
from tests.common.helpers.snapshot_warm_vs_cold_boot_helpers import backup_device_logs, record_diff, \
    run_presnapshot_checks, write_upgrade_path_summary
from tests.common.snapshot_comparison.warm_vs_cold import AFTER_COLDBOOT, AFTER_WARMBOOT, prune_expected_from_diff
from tests.upgrade_path.utilities import boot_into_base_image, cleanup_prev_images
from tests.common.db_comparison import SonicRedisDBSnapshotter, DBType
from tests.common import reboot
from tests.common.helpers.upgrade_helpers import install_sonic, restore_image  # noqa F401
from tests.common.platform.device_utils import get_current_sonic_version, verify_dut_health  # noqa F401

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.disable_memory_utilization,
    pytest.mark.skip_check_dut_health
]
logger = logging.getLogger(__name__)


def _resolve_test_params(request):
    """
    Parse and validate test parameters from pytest command line options.

    Extracts base and target image lists from pytest configuration and validates
    that each contains exactly one image for the A->B upgrade test scenario.

    Args:
        request: pytest request object containing configuration options

    Returns:
        tuple: (base_image, target_image)
            - base_image (str): The base image to start the upgrade from
            - target_image (str): The target image to upgrade to

    Raises:
        pytest.skip: If image lists don't contain exactly one image each
    """
    base_image_list = request.config.getoption("base_image_list")
    base_image_list = base_image_list.split(',')
    if len(base_image_list) != 1:
        pytest.skip("base_image_list should contain only one image for A->B upgrade test")
    base_image = base_image_list[0]

    target_image_list = request.config.getoption("target_image_list")
    target_image_list = target_image_list.split(',')
    if len(target_image_list) != 1:
        pytest.skip("target_image_list should contain only one image for A->B upgrade test")
    target_image = target_image_list[0]

    return base_image, target_image


def test_warmboot_data_consistency(localhost, duthosts, rand_one_dut_hostname, tbinfo, request,
                                    verify_dut_health, restore_image):  # noqa F811
    """
    Test comparing Redis database snapshots between warm boot and cold boot scenarios.

    This test performs a comprehensive comparison of Redis database states after
    warm boot versus cold boot to identify any differences in system behavior.
    The test follows this sequence:

    1. Install base image and boot into clean state
    2. Install target image
    3. Perform warm reboot and take database snapshots
    4. Perform cold reboot and take database snapshots
    5. Compare snapshots and analyze differences
    6. Prune expected differences and report unexpected ones

    Args:
        localhost: Local host fixture for running commands
        duthosts: Dictionary of device under test hosts
        rand_one_dut_hostname: Randomly selected DUT hostname for testing
        tbinfo: Testbed information containing topology and configuration
        request: pytest request object for accessing test parameters
    """
    duthost = duthosts[rand_one_dut_hostname]
    from_image, to_image = _resolve_test_params(request)

    # Install base image, erase config and boot into base image so there is a clean slate for the upgrade test
    cleanup_prev_images(duthost)
    boot_into_base_image(duthost, localhost, from_image, tbinfo)

    logger.info(f"DUT {duthost.hostname} booted into base image {from_image}")

    # Take a note of the base OS version for upgrade path summary reporting later on
    base_os_version = get_current_sonic_version(duthost)

    # Install target image
    logger.info(f"Installing {to_image} on {duthost.hostname}")
    install_sonic(duthost, to_image, tbinfo)

    logger.info(f"Target image {to_image} installed on {duthost.hostname}")
    backup_device_logs(duthost, "logs/base_image_device_logs")

    # Warm upgrade to target image
    reboot(duthost, localhost, reboot_type="warm", wait_warmboot_finalizer=True, safe_reboot=True)

    # Now all data needed for the upgrade path summary has been collected, write it out
    upgrade_summary_path = os.path.join("logs", "test_upgrade_path_summary.json")
    write_upgrade_path_summary(upgrade_summary_path, duthost, base_os_version)
    logger.info(f"Upgrade path summary written to {upgrade_summary_path}")

    data_dir = "logs/warm-vs-cold-boot-snapshots"
    snapshot_dbs = [DBType.APPL, DBType.STATE, DBType.CONFIG, DBType.ASIC]
    sonic_redis_db_snapshotter = SonicRedisDBSnapshotter(duthost, data_dir)

    logger.info("Checking system is stable after warm reboot...")
    run_presnapshot_checks(duthost, tbinfo)
    logger.info("System is stable after warm reboot")

    logger.info("Taking snapshots of Redis DB after warm boot")
    after_warmboot_snapshot_name = AFTER_WARMBOOT
    sonic_redis_db_snapshotter.take_snapshot(after_warmboot_snapshot_name, snapshot_dbs)
    backup_device_logs(duthost, "logs/warm_boot_device_logs", fetch_logs_before_reboot=True)

    logger.info("Cold booting to capture snapshot for comparison")
    reboot(duthost, localhost, reboot_type="cold", safe_reboot=True)

    logger.info("Checking system is stable after load_minigraph (cold reboot)...")
    run_presnapshot_checks(duthost, tbinfo)
    logger.info("System is stable after load_minigraph (cold reboot)")

    logger.info("Taking snapshots of Redis DB after cold boot")
    after_coldboot_snapshot_name = AFTER_COLDBOOT
    sonic_redis_db_snapshotter.take_snapshot(after_coldboot_snapshot_name, snapshot_dbs)
    backup_device_logs(duthost, "logs/cold_boot_device_logs")

    logger.info("Comparing snapshots after warm vs cold boot ...")
    diff = sonic_redis_db_snapshotter.diff_snapshots(after_warmboot_snapshot_name, after_coldboot_snapshot_name)

    # Write metrics to custom message and dump snapshots to disk before pruning
    record_diff(request, diff, data_dir, "pre_prune")

    prune_expected_from_diff(diff)

    # Write metrics to custom message and dump snapshots to disk after pruning
    record_diff(request, diff, data_dir, "post_prune")

    # Log warn any diffs after pruning
    for db_type, db_snapshot in diff.items():
        if db_snapshot.diff:
            pretty_diff = json.dumps(db_snapshot.diff, indent=4)
            logger.warning(f"Differences found in {db_type.name} DB:\n{pretty_diff}")
        else:
            logger.info(f"No differences found in {db_type.name} DB")
