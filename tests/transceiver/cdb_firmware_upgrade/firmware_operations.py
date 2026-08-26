import logging
import time
from contextlib import contextmanager

from tests.common.platform.interface_utils import (
    get_physical_to_logical_port_mapping,
    wait_ports_oper_status,
)
from tests.transceiver.attribute_parser.attribute_keys import (
    BASE_ATTRIBUTES_KEY,
    CDB_FIRMWARE_UPGRADE_ATTRIBUTES_KEY,
    SYSTEM_ATTRIBUTES_KEY,
)
from tests.transceiver.common import cli_helpers, dmesg_helpers, scenario_ops
from tests.transceiver.cdb_firmware_upgrade.utils.firmware_utils import resolve_binary_path
from tests.transceiver.common.cli_parser_helper import (
    FW_ACTIVE,
    FW_COMMITTED_IMAGE,
    FW_INACTIVE,
    FW_RUNNING_IMAGE,
)

logger = logging.getLogger(__name__)

I2C_ERROR_PATTERN = r"i2c.*(error|fail|timeout|nack)|(error|fail).*i2c"
THERMALCTLD = "thermalctld"


def select_target_version(firmware_versions, banks):
    """Select the next version, after the active one, that is in neither bank."""
    active = banks.get(FW_ACTIVE, "")
    inactive = banks.get(FW_INACTIVE, "")
    start = firmware_versions.index(active) + 1 if active in firmware_versions else 0
    for offset in range(len(firmware_versions)):
        next_version = firmware_versions[(start + offset) % len(firmware_versions)]
        if next_version not in (active, inactive):
            return next_version
    return firmware_versions[0]


def _verify_running_committed_unchanged(after_banks, before_banks):
    """Running/Committed bank letters are the same before and after a download."""
    failures = []
    for field in (FW_RUNNING_IMAGE, FW_COMMITTED_IMAGE):
        if after_banks.get(field) != before_banks.get(field):
            failures.append(
                f"{field} changed from {before_banks.get(field)} to "
                f"{after_banks.get(field)} after download"
            )
    return failures


def _verify_running_matches_committed(after_banks, operation):
    """The running image is also the committed one."""
    running = after_banks.get(FW_RUNNING_IMAGE)
    committed = after_banks.get(FW_COMMITTED_IMAGE)
    if running != committed:
        return [f"Committed Image {committed} != Running Image {running} after {operation}"]
    return []


def _verify_running_bank_changed(duthost, port, before_banks):
    """The firmware run swapped the running bank."""
    after_banks, err = cli_helpers.sfputil_show_fwversion(duthost, port)
    if err:
        return [err]
    if after_banks.get(FW_RUNNING_IMAGE) == before_banks.get(FW_RUNNING_IMAGE):
        return [
            f"Running Image {after_banks.get(FW_RUNNING_IMAGE)} did not change after firmware run"
        ]
    return []


def _verify_committed_bank_matches_running(duthost, port):
    """The firmware commit pointed the committed bank at the running one."""
    after_banks, err = cli_helpers.sfputil_show_fwversion(duthost, port)
    if err:
        return [err]
    return _verify_running_matches_committed(after_banks, "firmware commit")


def _stop_thermalctld(duthost):
    status, _ = duthost.get_pmon_daemon_status(THERMALCTLD)
    if status is None:
        return False, "could not determine thermalctld status"
    if status != "RUNNING":
        return False, None
    duthost.stop_pmon_daemon_service(THERMALCTLD)
    status, _ = duthost.get_pmon_daemon_status(THERMALCTLD)
    if status != "STOPPED":
        return False, f"thermalctld status after stop is {status or 'unknown'}"
    return True, None


def _start_thermalctld(duthost, was_stopped):
    if not was_stopped:
        return None
    duthost.start_pmon_daemon(THERMALCTLD)
    status, _ = duthost.get_pmon_daemon_status(THERMALCTLD)
    if status != "RUNNING":
        return f"thermalctld status after start is {status or 'unknown'}"
    return None


@contextmanager
def thermalctld_stopped_if_required(duthost, cdb_attrs, failures):
    """Stop thermalctld for the duration of the block when the module requires it."""
    stopped = False
    if cdb_attrs.get("thermalctld_disabling_required", False):
        stopped, err = _stop_thermalctld(duthost)
        if err:
            failures.append(f"failed to stop thermalctld: {err}")
    try:
        yield
    finally:
        err = _start_thermalctld(duthost, stopped)
        if err:
            failures.append(f"failed to restart thermalctld: {err}")


def _scan_i2c_errors(duthost, dmesg_start_uptime, operation):
    """Return per-port failures for new I2C dmesg errors."""
    i2c_errors, dmesg_err = dmesg_helpers.scan_new_dmesg_errors(
        duthost, dmesg_start_uptime, set(), I2C_ERROR_PATTERN
    )
    if dmesg_err:
        return [dmesg_err]
    if i2c_errors:
        return [f"I2C error(s) in dmesg during {operation}: {'; '.join(i2c_errors[:3])}"]
    return []


def verify_firmware_downloaded(duthost, port, before_banks, target_version, download_err):
    """Active/Running/Committed banks unchanged, the inactive bank has ``target_version``."""
    if download_err:
        return [f"download failed: {download_err}"]

    after_banks, err = cli_helpers.sfputil_show_fwversion(duthost, port)
    if err:
        return [err]

    failures = []
    if after_banks.get(FW_ACTIVE) != before_banks.get(FW_ACTIVE):
        failures.append(
            f"active firmware changed from {before_banks.get(FW_ACTIVE)} to "
            f"{after_banks.get(FW_ACTIVE)} after download"
        )
    if after_banks.get(FW_INACTIVE) != target_version:
        failures.append(
            f"inactive firmware {after_banks.get(FW_INACTIVE) or 'N/A'} != "
            f"downloaded {target_version}"
        )
    failures += _verify_running_committed_unchanged(after_banks, before_banks)
    return failures


def perform_firmware_download(duthost, port, port_context, metadata_map,
                              target_version=None, expect_link_up=True):
    """Download firmware to ``port`` and verify the firmware downloaded successfully.

    Returns a list of per-port failure strings (empty on success).
    """
    cdb_attrs = port_context["cdb_attrs"]
    vendor, pn = port_context["vendor"], port_context["pn"]
    physical_index = port_context["physical_index"]

    before_banks, err = cli_helpers.sfputil_show_fwversion(duthost, port)
    if err:
        return [err]

    if target_version is None:
        target_version = select_target_version(
            cdb_attrs.get("firmware_versions"), before_banks,
        )

    fwfile, err = resolve_binary_path(metadata_map, vendor, pn, target_version)
    if err:
        return [err]

    if expect_link_up:
        if wait_ports_oper_status(duthost, [port], "up", 0):
            return ["port must be operationally up before download"]

    failures = []
    with thermalctld_stopped_if_required(duthost, cdb_attrs, failures):
        if not failures and cdb_attrs.get("firmware_download_cdb_abort_support", True):
            status, abort_err = cli_helpers.issue_cdb_fw_abort(duthost, physical_index)
            if abort_err:
                logger.warning("Port %s: pre-download CDB abort failed (proceeding): %s", port, abort_err)
            else:
                logger.info("Port %s: pre-download CDB abort status=%s", port, status)

        if not failures:
            dmesg_start_uptime, dmesg_start_err = dmesg_helpers.capture_dmesg_uptime_watermark(duthost)
            if dmesg_start_err:
                failures.append(dmesg_start_err)
            else:
                timeout_sec = cdb_attrs["firmware_download_timeout_minutes"] * 60
                elapsed, dl_err = cli_helpers.sfputil_firmware_download(duthost, port, fwfile, timeout_sec)
                logger.info("Port %s: firmware download %s took %ss", port, target_version, elapsed)

                failures += verify_firmware_downloaded(
                    duthost, port, before_banks, target_version, dl_err,
                )
                if expect_link_up and not dl_err:
                    if wait_ports_oper_status(duthost, [port], "up", 0):
                        failures.append("link went down during firmware download")

                # TODO: no link flap should occur during firmware download,
                # need to add check for link flap.

                failures += _scan_i2c_errors(duthost, dmesg_start_uptime, "download")
    return failures


def verify_firmware_activation(duthost, port, before_banks, dual_bank_supported,
                               activated_version=None):
    """Verifies the bank swap took effect."""
    after_banks, err = cli_helpers.sfputil_show_fwversion(duthost, port)
    if err:
        return [err]

    failures = []
    if dual_bank_supported:
        if after_banks.get(FW_ACTIVE) != before_banks.get(FW_INACTIVE):
            failures.append("active firmware not updated after activation")
        if after_banks.get(FW_INACTIVE) != before_banks.get(FW_ACTIVE):
            failures.append("previous active firmware not preserved in inactive bank after swap")
        if after_banks.get(FW_RUNNING_IMAGE) == before_banks.get(FW_RUNNING_IMAGE):
            failures.append("Running Image did not change after activation")
        failures += _verify_running_matches_committed(after_banks, "activation")
    elif activated_version is None:
        failures.append("activated_version is required for a single-bank module")
    elif after_banks.get(FW_ACTIVE) != activated_version:
        failures.append(f"active firmware {after_banks.get(FW_ACTIVE)} != activated {activated_version}")

    return failures


def perform_firmware_activation(duthost, port, port_context,
                                before_banks=None, activated_version=None):
    """Activate the inactive-bank firmware on ``port``.

    Returns a list of per-port failure strings (empty on success).
    """
    cdb_attrs = port_context["cdb_attrs"]
    system_attrs = port_context["system_attrs"]
    subports = port_context["subports"]
    dual_bank = cdb_attrs.get("dual_bank_supported", True)
    run_timeout = cdb_attrs["firmware_run_timeout_sec"]
    commit_timeout = cdb_attrs["firmware_commit_timeout_sec"]
    recover_sec = system_attrs["transceiver_reset_i2c_recover_sec"]
    startup_wait = system_attrs["port_startup_wait_sec"]
    shutdown_wait = system_attrs["port_shutdown_wait_sec"]

    if before_banks is None:
        before_banks, err = cli_helpers.sfputil_show_fwversion(duthost, port)
        if err:
            return [err]

    failures = scenario_ops.perform_ports_shutdown(duthost, subports, shutdown_wait)
    dmesg_start_uptime = None
    try:
        if not failures:
            with thermalctld_stopped_if_required(duthost, cdb_attrs, failures):
                if not failures:
                    dmesg_start_uptime, dmesg_start_err = dmesg_helpers.capture_dmesg_uptime_watermark(duthost)
                    if dmesg_start_err:
                        failures.append(dmesg_start_err)

                if not failures:
                    run_elapsed, run_err = cli_helpers.sfputil_firmware_run(duthost, port, run_timeout)
                    logger.info("Port %s: firmware run took %ss", port, run_elapsed)
                    if run_err:
                        failures.append(f"firmware run failed: {run_err}")
                    elif dual_bank:
                        failures += _verify_running_bank_changed(duthost, port, before_banks)

                if not failures:
                    commit_elapsed, commit_err = cli_helpers.sfputil_firmware_commit(duthost, port, commit_timeout)
                    logger.info("Port %s: firmware commit took %ss", port, commit_elapsed)
                    if commit_err:
                        failures.append(f"firmware commit failed: {commit_err}")
                    elif dual_bank:
                        failures += _verify_committed_bank_matches_running(duthost, port)

                if not failures:
                    failures += _scan_i2c_errors(duthost, dmesg_start_uptime, "activation")

        if not failures:
            failures += scenario_ops.perform_sfputil_reset(
                duthost, [port], [], shutdown_wait, startup_wait
            )
            time.sleep(recover_sec)
    finally:
        failures += scenario_ops.perform_ports_startup(duthost, subports, startup_wait)

    if not failures:
        failures += verify_firmware_activation(
            duthost, port, before_banks, dual_bank, activated_version=activated_version,
        )
    return failures


def activation_op(duthost, port, port_context, metadata_map):
    """``execute_on_ports`` per-port callable: activate selected firmware."""
    cdb_attrs = port_context["cdb_attrs"]
    if not cdb_attrs.get("dual_bank_supported", True):
        banks, err = cli_helpers.sfputil_show_fwversion(duthost, port)
        if err:
            return [err]
        target_version = select_target_version(
            cdb_attrs.get("firmware_versions"), banks,
        )
        failures = perform_firmware_download(
            duthost, port, port_context, metadata_map, target_version=target_version,
        )
        if failures:
            return failures
        return perform_firmware_activation(
            duthost, port, port_context, activated_version=target_version,
        )
    return perform_firmware_activation(duthost, port, port_context)


def restore_module_to_original(duthost, port, port_context, metadata_map):
    """Restore a module to its original state."""
    cdb_attrs = port_context["cdb_attrs"]
    system_attrs = port_context["system_attrs"]
    gold_firmware = cdb_attrs.get("gold_firmware_version")
    dual_bank = cdb_attrs.get("dual_bank_supported", True)

    failures = []
    banks, err = cli_helpers.sfputil_show_fwversion(duthost, port)
    if err:
        return [err]

    if banks.get(FW_ACTIVE) != gold_firmware:
        if not dual_bank or banks.get(FW_INACTIVE) != gold_firmware:
            failures += perform_firmware_download(
                duthost, port, port_context, metadata_map,
                target_version=gold_firmware, expect_link_up=False,
            )
        if not failures:
            failures += perform_firmware_activation(
                duthost, port, port_context, activated_version=gold_firmware,
            )
        if not failures and dual_bank:
            banks, err = cli_helpers.sfputil_show_fwversion(duthost, port)
            if err:
                failures.append(err)

    if not failures and dual_bank:
        orig_inactive = cdb_attrs.get("inactive_firmware_version")
        if not orig_inactive:
            failures.append("inactive_firmware_version is not defined for dual-bank module")
        elif banks.get(FW_INACTIVE) != orig_inactive:
            failures += perform_firmware_download(
                duthost, port, port_context, metadata_map,
                target_version=orig_inactive, expect_link_up=False,
            )

    failures += scenario_ops.perform_ports_startup(
        duthost, port_context["subports"], system_attrs["port_startup_wait_sec"],
    )
    return failures


def execute_on_ports(duthost, port_attributes_dict, qualifying_ports, lport_to_pport,
                     metadata_map, per_port_fn, prefetch=None):
    """Invoke ``per_port_fn`` on every qualifying CDB firmware port and aggregate failures.

    ``prefetch(duthost, qualifying_ports, lport_to_pport)`` runs once before the
    loop and its result is exposed as ``port_context["prefetched"]``.

    Returns ``(all_failures, num_ports)``, the caller ``pytest.fail``s or logs.
    """
    pport_to_lport = get_physical_to_logical_port_mapping(lport_to_pport)
    prefetched = prefetch(duthost, qualifying_ports, lport_to_pport) if prefetch else None
    all_failures = []
    for port in qualifying_ports:
        base_attrs = port_attributes_dict[port].get(BASE_ATTRIBUTES_KEY, {})
        vendor = base_attrs.get("normalized_vendor_name")
        pn = base_attrs.get("normalized_vendor_pn")
        physical_index = lport_to_pport.get(port)
        if physical_index is None:
            all_failures.append(f"{port}: could not resolve physical port index")
            continue
        port_context = {
            "cdb_attrs": port_attributes_dict[port].get(CDB_FIRMWARE_UPGRADE_ATTRIBUTES_KEY, {}),
            "system_attrs": port_attributes_dict[port].get(SYSTEM_ATTRIBUTES_KEY, {}),
            "vendor": vendor, "pn": pn, "physical_index": physical_index,
            "subports": pport_to_lport.get(physical_index, [port]),
            "prefetched": prefetched,
        }
        all_failures += [f"{port}: {f}" for f in per_port_fn(duthost, port, port_context, metadata_map)]
    return all_failures, len(qualifying_ports)
