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
from tests.common.utilities import wait_until
from tests.platform_tests.cpo.cpoutil_firmware.cpoutil_helpers import (
    cpoutil_show_fwversion,
    normalize_fw_version,
    start_firmware_background,
    wait_for_process,
    cleanup_background_logs,
    cpoutil_reset_interface,
    els_ports,
    start_xcvrd,
    stop_xcvrd,
    FW_ACTIVE,
    PORT_LINK_TIMEOUT,
    CPOUTIL_FW_STAGE_DIR,
)

logger = logging.getLogger(__name__)

CPO_JSON_PATH = "/usr/share/sonic/device/{}/cpo.json"
CORRUPTED_FW_FILENAME = "corrupted_fw.bin"
CORRUPTED_FW_SIZE = 1024


@pytest.fixture(scope="session", autouse=True)
def cpo_supported(duthost):
    """Skip the entire module if the DUT does not support CPO."""
    platform = duthost.facts["platform"]
    cpo_json_path = CPO_JSON_PATH.format(platform)
    if not duthost.stat(path=cpo_json_path)["stat"]["exists"]:
        pytest.skip(f"CPO not supported: {cpo_json_path} not found")


@pytest.fixture(scope="module")
def els_indices(duthost):
    """Return a sorted list of ELS index integers available on the DUT."""
    return sorted(int(target[3:]) for target in cpoutil_show_fwversion(duthost, "els"))


@pytest.fixture(scope="function")
def els_firmware_binaries(duthost, localhost):
    """Stage firmware binaries on the DUT.

    firmware.json ELS entries: [0] default image (used for restore),
    [1] target image (used by tests). Images are downloaded to the test host
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
    if len(els_entries) < 2:
        pytest.skip(
            f"Need 2 ELS firmware entries in firmware.json for chassis {chassis_name}, "
            f"got {len(els_entries)}"
        )

    duthost.shell(f"mkdir -p {CPOUTIL_FW_STAGE_DIR}")

    paths = {}
    local_dir = tempfile.mkdtemp(prefix="cpoutil_firmware_")
    try:
        for role, entry in [("default", els_entries[0]), ("target", els_entries[1])]:
            fw_url = entry["firmware"]
            fw_filename = os.path.basename(fw_url)
            local_path = os.path.join(local_dir, fw_filename)
            dut_path = f"{CPOUTIL_FW_STAGE_DIR}/{fw_filename}"
            logger.info("Downloading ELS %s firmware %s to the test host", role, fw_url)
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

    logger.info("Firmware binaries staged on DUT: %s", paths)
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
    """After each test, upgrade ELS not running the default firmware back to it.

    The ELS are upgraded in parallel, then verified. The upgrade runs the new
    image, which takes the ports of each restored ELS down, so their ports are
    recovered afterwards.
    """
    default_fw = els_firmware_binaries["default"]
    default_version = els_firmware_binaries["default_version"]

    yield

    # Step 1: check which ELS need restore
    fwinfo = cpoutil_show_fwversion(duthost, "els")

    needs_restore = []
    for idx in els_indices:
        active = fwinfo[f"els{idx}"][FW_ACTIVE]
        if active != default_version:
            needs_restore.append(idx)
            logger.info(f"ELS{idx} needs restore: active={active}, expected={default_version}")

    if not needs_restore:
        logger.info("All ELS already running default firmware, no restore needed")
        duthost.shell(f"sudo rm -rf {CPOUTIL_FW_STAGE_DIR}")
        return

    # Step 2: upgrade in parallel (one background process per ELS)
    logger.info("Restoring %d ELS to default firmware: %s", len(needs_restore), default_fw)
    pids = [start_firmware_background(duthost, "upgrade", idx, default_fw) for idx in needs_restore]
    for pid in pids:
        wait_for_process(duthost, pid)

    # Step 3: verify all ELS are running the default version
    fwinfo_post = cpoutil_show_fwversion(duthost, "els")

    restore_failed = [
        f"els{idx}: active={fwinfo_post[f'els{idx}'][FW_ACTIVE]}"
        for idx in needs_restore
        if fwinfo_post[f"els{idx}"][FW_ACTIVE] != default_version
    ]
    assert not restore_failed, f"Restore to {default_version} failed: {restore_failed}"

    # Step 4: bring the ports of the restored ELS back up.
    stop_xcvrd(duthost)
    ports_by_els = {}
    for idx in needs_restore:
        ports = els_ports(duthost, idx)
        cpoutil_reset_interface(duthost, ports[0])
        ports_by_els[idx] = ports
    start_xcvrd(duthost)
    all_ports = [p for ports in ports_by_els.values() for p in ports]
    duthost.shutdown_multiple(all_ports)
    duthost.no_shutdown_multiple(all_ports)
    assert wait_until(PORT_LINK_TIMEOUT, 10, 0, duthost.links_status_up, all_ports), (
        f"Ports did not come up after restore: {all_ports}"
    )

    cleanup_background_logs(duthost)
    duthost.shell(f"sudo rm -rf {CPOUTIL_FW_STAGE_DIR}")
