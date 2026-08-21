import logging
from contextlib import contextmanager

from tests.common.platform.interface_utils import (
    get_physical_to_logical_port_mapping,
    wait_ports_oper_status,
)
from tests.transceiver.attribute_parser.attribute_keys import (
    BASE_ATTRIBUTES_KEY,
    CDB_FIRMWARE_UPGRADE_ATTRIBUTES_KEY,
    DOM_ATTRIBUTES_KEY,
    SYSTEM_ATTRIBUTES_KEY,
)
from tests.transceiver.common import cli_helpers, dmesg_helpers, scenario_ops
from tests.transceiver.common.db_helpers import resolve_port_namespace
from tests.transceiver.cdb_firmware_upgrade.utils.firmware_utils import resolve_binary_path
from tests.transceiver.dom import dom_helpers
from tests.transceiver.eeprom import eeprom_content
from tests.transceiver.common.cli_parser_helper import (
    FW_ACTIVE,
    FW_COMMITTED_IMAGE,
    FW_INACTIVE,
    FW_RUNNING_IMAGE,
)

logger = logging.getLogger(__name__)

I2C_ERROR_PATTERN = r"i2c.*(error|fail|timeout|nack)|(error|fail).*i2c"
THERMALCTLD = "thermalctld"
DOM_REFRESH_POLL_INTERVAL_SEC = 20


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


def select_distinct_version(firmware_versions, gold_version):
    """Select the version differing from ``gold_version`` in minor AND point.

    Returns ``None`` when no entry qualifies.
    """
    gold_parts = gold_version.split(".")[1:] if gold_version else []
    for version in firmware_versions or []:
        parts = version.split(".")[1:]
        if parts and len(parts) == len(gold_parts) and all(p != g for p, g in zip(parts, gold_parts)):
            return version
    return None


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


def verify_static_eeprom_unchanged(duthost, port_attributes_dict, ports, lport_to_first_subport_mapping):
    """Static EEPROM content still matches inventory after a firmware operation."""
    failures = eeprom_content.verify_eeprom_static_recovered(
        duthost,
        port_attributes_dict,
        lport_to_first_subport_mapping,
        wait_sec=0,
        ports=ports,
    )
    return [f"static EEPROM check failed after firmware operation: {failure}" for failure in failures]


def verify_dom_refreshed(duthost, port_attributes_dict, ports, lport_to_first_subport_mapping):
    """Re-enable DOM polling, then confirm sensor data is republished and in range."""
    dom_attrs = port_attributes_dict[ports[0]].get(DOM_ATTRIBUTES_KEY, {})
    if dom_attrs.get("data_max_age_min") is None:
        logger.info("No data_max_age_min configured; skipping DOM refresh verification")
        return []

    plan_by_port = dom_helpers.build_dom_availability_plan(
        port_attributes_dict, ports, lport_to_first_subport_mapping,
    )

    stale_by_port, _ = dom_helpers.read_dom_sensor_data(duthost, ports)
    stale_timestamps = {
        port: stale_by_port.get(port, {}).get("last_update_time") for port in ports
    }

    def _check_republished():
        sensor_by_port, read_errors = dom_helpers.read_dom_sensor_data(duthost, ports)
        failures = [f"STATE_DB read: {read_error}" for read_error in read_errors]
        for port in ports:
            updated = sensor_by_port.get(port, {}).get("last_update_time")
            if updated is not None and updated == stale_timestamps[port]:
                failures.append(f"{port}: DOM data not republished since polling was re-enabled")
        port_failures, _, _ = dom_helpers.validate_dom_plan_fields(
            duthost, ports, sensor_by_port, plan_by_port,
            dom_helpers.dom_field_available,
            include_freshness_only=True,
        )
        return failures + port_failures

    enabled_ports = []
    try:
        for port in ports:
            namespace = resolve_port_namespace(duthost, port)
            enabled_ports.append((port, namespace))
            err = cli_helpers.set_dom_polling(duthost, port, enable=True, namespace=namespace)
            if err:
                return [f"failed to re-enable DOM polling on {port}: {err}"]

        failures = scenario_ops.poll_ports_recovered(
            _check_republished, dom_attrs["dom_info_recover_sec"],
            DOM_REFRESH_POLL_INTERVAL_SEC, "DOM refresh",
        )
        if failures:
            return failures

        sensor_by_port, read_errors = dom_helpers.read_dom_sensor_data(duthost, ports)
        port_failures, _, _ = dom_helpers.validate_dom_plan_fields(
            duthost, ports, sensor_by_port, plan_by_port,
            dom_helpers.dom_field_in_operational_range,
            include_freshness_only=True,
        )
        return [f"STATE_DB read: {read_error}" for read_error in read_errors] + port_failures
    finally:
        for port, namespace in enabled_ports:
            err = cli_helpers.set_dom_polling(duthost, port, enable=False, namespace=namespace)
            if err:
                logger.warning("Failed to restore DOM polling disabled on %s: %s", port, err)


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
                duthost, [port], [], shutdown_wait, startup_wait,
                recover_wait_sec=recover_sec,
            )
    finally:
        failures += scenario_ops.perform_ports_startup(duthost, subports, startup_wait)

    if not failures:
        failures += verify_firmware_activation(
            duthost, port, before_banks, dual_bank, activated_version=activated_version,
        )
    return failures


def perform_firmware_upgrade(duthost, port, port_context, metadata_map, target_version=None):
    """Download ``target_version`` then activate it."""
    if target_version is None:
        banks, err = cli_helpers.sfputil_show_fwversion(duthost, port)
        if err:
            return [err]
        target_version = select_target_version(
            port_context["cdb_attrs"].get("firmware_versions"), banks,
        )

    failures = perform_firmware_download(
        duthost, port, port_context, metadata_map, target_version=target_version,
    )
    if failures:
        return failures
    return perform_firmware_activation(
        duthost, port, port_context, activated_version=target_version,
    )


def activation_op(duthost, port, port_context, metadata_map):
    """``execute_on_ports`` per-port callable: activate selected firmware."""
    if not port_context["cdb_attrs"].get("dual_bank_supported", True):
        return perform_firmware_upgrade(duthost, port, port_context, metadata_map)
    return perform_firmware_activation(duthost, port, port_context)


def distinct_version_upgrade_op(duthost, port, port_context, metadata_map):
    """TC5 per-port op: full upgrade to the version fully distinct from gold."""
    cdb_attrs = port_context["cdb_attrs"]
    target_version = select_distinct_version(
        cdb_attrs.get("firmware_versions"), cdb_attrs.get("gold_firmware_version"),
    )
    if target_version is None:
        return ["no firmware version differs from gold in both minor and point"]
    logger.info("Port %s: upgrading to distinct version %s", port, target_version)
    return perform_firmware_upgrade(
        duthost, port, port_context, metadata_map, target_version=target_version,
    )


def download_post_reset_op(duthost, port, port_context, metadata_map):
    """TC9 per-port op: download, reset the module, then re-verify the download."""
    cdb_attrs = port_context["cdb_attrs"]
    system_attrs = port_context["system_attrs"]
    subports = port_context["subports"]

    before_banks, err = cli_helpers.sfputil_show_fwversion(duthost, port)
    if err:
        return [err]
    target_version = select_target_version(cdb_attrs.get("firmware_versions"), before_banks)

    failures = perform_firmware_download(
        duthost, port, port_context, metadata_map, target_version=target_version,
    )
    if failures:
        return failures

    failures += scenario_ops.perform_sfputil_reset(
        duthost, [port], subports,
        system_attrs["port_shutdown_wait_sec"],
        system_attrs["port_startup_wait_sec"],
        recover_wait_sec=system_attrs["transceiver_reset_i2c_recover_sec"],
    )
    return failures + verify_firmware_downloaded(
        duthost, port, before_banks, target_version, None,
    )


def download_low_power_op(duthost, port, port_context, metadata_map):
    """TC10 per-port op: download while the module is held in low-power mode."""
    system_attrs = port_context["system_attrs"]

    failures = []
    try:
        failures += scenario_ops.perform_lpmode_set(duthost, port, low_power=True)
        if not failures:
            failures += perform_firmware_download(
                duthost, port, port_context, metadata_map, expect_link_up=False,
            )
        if not failures:
            failures += scenario_ops.verify_lpmode(duthost, port, low_power=True)
    finally:
        failures += scenario_ops.perform_lpmode_set(duthost, port, low_power=False)
        failures += wait_ports_oper_status(
            duthost, port_context["subports"], "up",
            system_attrs["port_startup_wait_sec"],
        )
    return failures


def download_admin_down_op(duthost, port, port_context, metadata_map):
    """TC11 per-port op: download while every subport is admin-down."""
    system_attrs = port_context["system_attrs"]
    subports = port_context["subports"]

    failures = []
    try:
        failures += scenario_ops.perform_ports_shutdown(
            duthost, subports, system_attrs["port_shutdown_wait_sec"],
        )
        if not failures:
            failures += perform_firmware_download(
                duthost, port, port_context, metadata_map, expect_link_up=False,
            )
        if not failures:
            failures += wait_ports_oper_status(duthost, subports, "down", 1)
    finally:
        failures += scenario_ops.perform_ports_startup(
            duthost, subports, system_attrs["port_startup_wait_sec"],
        )
    return failures


def upgrade_stress_op(duthost, port, port_context, metadata_map):
    """TC14 per-port op: repeat the full upgrade, stopping at the first bad iteration."""
    iterations = port_context["cdb_attrs"]["firmware_upgrade_stress_iterations"]
    for iteration in range(1, iterations + 1):
        logger.info("Port %s: firmware upgrade stress iteration %d/%d", port, iteration, iterations)
        failures = perform_firmware_upgrade(duthost, port, port_context, metadata_map)
        if failures:
            return [f"iteration {iteration}/{iterations}: {failure}" for failure in failures]
    return []


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
                     metadata_map, per_port_fn, lport_to_first_subport_mapping=None,
                     prefetch=None, verify_post_operation=False):
    """Invoke ``per_port_fn`` on every qualifying CDB firmware port and aggregate failures.

    ``prefetch(duthost, qualifying_ports, lport_to_pport)`` runs once before the
    loop and its result is exposed as ``port_context["prefetched"]``.

    ``verify_post_operation`` runs the checks once every port is done: static
    EEPROM unchanged, then DOM polling re-enabled and in operational range.

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

    if verify_post_operation and qualifying_ports and not all_failures:
        all_failures += verify_static_eeprom_unchanged(
            duthost, port_attributes_dict, qualifying_ports, lport_to_first_subport_mapping,
        )
        all_failures += verify_dom_refreshed(
            duthost, port_attributes_dict, qualifying_ports, lport_to_first_subport_mapping,
        )
    return all_failures, len(qualifying_ports)
