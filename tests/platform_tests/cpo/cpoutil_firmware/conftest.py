"""Fixtures for cpoutil ELS firmware management tests.

``duthost`` is the framework's session-scoped fixture; do not redefine it here,
or session-scoped fixtures that depend on it fail with ScopeMismatch.
"""
import json
import logging
import os
import shutil
import tempfile

import pytest

from tests.common.helpers.firmware_helper import show_firmware
from tests.common.cpo_utils import (
    get_cpo_json_path,
    is_cpo_switch,
    cpoutil_show_fwversion,
    normalize_fw_version,
    recover_els_ports,
    assert_els_running,
    start_xcvrd,
    stop_xcvrd,
    FW_ACTIVE,
    FW_RUNNING_IMAGE,
    FW_COMMITTED_IMAGE,
    CPOUTIL_FW_STAGE_DIR,
)

logger = logging.getLogger(__name__)

CORRUPTED_FW_FILENAME = "corrupted_fw.bin"
CORRUPTED_FW_SIZE = 1024


@pytest.fixture(scope="session", autouse=True)
def is_cpo_supported(duthost):
    """Skip the entire module if the DUT does not support CPO."""
    if not is_cpo_switch(duthost):
        pytest.skip(f"CPO not supported: {get_cpo_json_path(duthost)} not found")


@pytest.fixture(scope="module")
def els_indices(duthost):
    """Return a sorted list of ELS index integers available on the DUT."""
    return sorted(int(target[3:]) for target in cpoutil_show_fwversion(duthost, "els"))


@pytest.fixture(scope="function")
def els_firmware_binaries(duthost, localhost):
    """Stage firmware binaries on the DUT.

    firmware.json ELS entries: [0] default image (used for restore),
    [1] target image (used by tests). With a single entry, the default image is
    also the target image. Images are downloaded to the test host
    and copied to the DUT, so the DUT needs no route to the firmware server.
    The staging directory is removed at the end of restore_els_firmware.

    Returns:
        dict: {"default": dut_path, "target": dut_path, "corrupted": dut_path,
               "default_version": str, "target_version": str}
    """
    fw_json_path = os.path.join(
        os.path.dirname(__file__), "..", "..", "fwutil", "firmware.json"
    )
    with open(fw_json_path) as f:
        fw_data = json.load(f)

    # Chassis name as used by tests/platform_tests/fwutil/fwutil_common.py
    fw_status = show_firmware(duthost)
    chassis_name = list(fw_status["chassis"].keys())[0]
    chassis_entry = fw_data.get("chassis", {}).get(chassis_name, {})
    els_entries = chassis_entry.get("component", {}).get("ELS", [])
    if not els_entries:
        pytest.skip(f"No ELS firmware entry in firmware.json for chassis {chassis_name}")

    duthost.shell(f"mkdir -p {CPOUTIL_FW_STAGE_DIR}")

    paths = {}
    local_dir = tempfile.mkdtemp(prefix="cpoutil_firmware_")
    try:
        for role, entry in [("default", els_entries[0]), ("target", els_entries[-1])]:
            fw_url = entry["firmware"]
            fw_filename = os.path.basename(fw_url)
            local_path = os.path.join(local_dir, fw_filename)
            dut_path = f"{CPOUTIL_FW_STAGE_DIR}/{fw_filename}"
            logger.info(f"Downloading ELS {role} firmware {fw_url} to the test host")
            localhost.get_url(url=fw_url, dest=local_path)
            assert os.path.getsize(local_path) > 0, f"Downloaded firmware is empty: {fw_url}"
            duthost.copy(src=local_path, dest=dut_path)
            paths[role] = dut_path
            paths[f"{role}_version"] = normalize_fw_version(entry["version"])
    finally:
        shutil.rmtree(local_dir, ignore_errors=True)

    corrupted_path = f"{CPOUTIL_FW_STAGE_DIR}/{CORRUPTED_FW_FILENAME}"
    duthost.shell(f"head -c {CORRUPTED_FW_SIZE} /dev/zero > {corrupted_path}")
    paths["corrupted"] = corrupted_path

    logger.info(f"Firmware binaries staged on DUT: {paths}")
    return paths


@pytest.fixture(scope="function")
def dom_polling_disabled(duthost):
    """Stop xcvrd during firmware operations to avoid I2C contention.

    Stopping xcvrd, unlike per-port DOM polling changes, does not modify
    CONFIG_DB.
    """
    stop_xcvrd(duthost)

    yield

    start_xcvrd(duthost)


@pytest.fixture(scope="function")
def restore_els_firmware(duthost, els_firmware_binaries, els_indices):
    """After each test, bring every ELS back to the default firmware, committed.

    An ELS needs restore if it does not run the default firmware, or runs an
    uncommitted image (Running Image != Committed Image). Those ELS are first
    reset and their ports admin toggled. The reset recovers an ELS that stopped
    responding after a failed run, brings back the ports a run took down, and
    returns the ELS to its committed image; an ELS may already be restored after
    it. The ELS still not restored are upgraded in parallel, and their ports,
    which the upgrade's run took down, recovered.
    """
    default_fw = els_firmware_binaries["default"]
    default_version = els_firmware_binaries["default_version"]

    yield

    def not_restored():
        fwinfo = cpoutil_show_fwversion(duthost, "els")
        needs = [
            idx for idx in els_indices
            if fwinfo[f"els{idx}"].get(FW_ACTIVE) != default_version
            or fwinfo[f"els{idx}"].get(FW_RUNNING_IMAGE) != fwinfo[f"els{idx}"].get(FW_COMMITTED_IMAGE)
        ]
        return fwinfo, needs

    fwinfo, needs_restore = not_restored()
    if needs_restore:
        # Step 1: reset, which returns the ELS to its committed image and may
        # already bring it back to the default firmware
        logger.info(f"Resetting ELS {needs_restore}")
        recover_els_ports(duthost, needs_restore)
        fwinfo, needs_restore = not_restored()

    if needs_restore:
        # Step 2: upgrade the rest in parallel, then recover the ports the run took down
        logger.info(f"Upgrading ELS {needs_restore} to {default_fw}")
        tasks = [
            duthost.shell(
                f"cpoutil firmware upgrade els {idx} --raw {default_fw}",
                module_async=True,
            )
            for idx in needs_restore
        ]
        # Wait for every upgrade before checking, so none is left running.
        # The async path returns the result without failing on a non-zero rc.
        failed = {}
        for idx, (pool, async_result) in zip(needs_restore, tasks):
            try:
                result = async_result.get()
            finally:
                pool.terminate()
                pool.join()
            if result["rc"] != 0:
                failed[idx] = f"rc={result['rc']}: {result['stdout']} {result['stderr']}"
        assert not failed, f"Restore upgrade failed: {failed}"
        recover_els_ports(duthost, needs_restore)
        fwinfo = cpoutil_show_fwversion(duthost, "els")

    # Step 3: verify every ELS runs the default firmware, committed
    for idx in els_indices:
        assert_els_running(f"els{idx}", fwinfo[f"els{idx}"], default_version)

    duthost.shell(f"sudo rm -rf {CPOUTIL_FW_STAGE_DIR}")
