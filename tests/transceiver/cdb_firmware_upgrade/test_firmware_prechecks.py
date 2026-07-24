"""CDB firmware-upgrade pre-checks: TC1 (firmware version) and TC2 (abort support).

These baseline checks are meant to run FIRST in the CDB firmware-upgrade
sequence -- the later download/upgrade tests assume each module starts on its
gold firmware and advertises CDB abort support, which TC1/TC2 validate.  See
the ``docs/testplan/transceiver/cdb_firmware_upgrade_test_plan.md``.
"""
import logging

import pytest

from tests.transceiver.attribute_parser.attribute_keys import (
    CDB_FIRMWARE_UPGRADE_ATTRIBUTES_KEY,
)
from tests.transceiver.cdb_firmware_upgrade.port_selection import (
    get_qualifying_ports,
    resolve_ports_under_test,
)
from tests.transceiver.common import cli_helpers

logger = logging.getLogger(__name__)

ACTIVE_FIRMWARE_KEY = "Active Firmware"
INACTIVE_FIRMWARE_KEY = "Inactive Firmware"


def _run_per_port_check(duthost, port_attributes_dict, lport_to_first_subport, lport_to_pport, check_fn):
    """Iterate qualifying ports, run ``check_fn``, and aggregate failures.

    Args:
        duthost: DUT host fixture.
        port_attributes_dict: ``{port: {attr_block: {...}}}`` inventory map.
        lport_to_first_subport: first-sub-port mapping fixture.
        lport_to_pport: ``{logical_port: physical_index}`` map (resolved once)
            used to resolve ``ports_under_test``.
        check_fn: callable ``(duthost, port, port_attrs, all_failures) -> None``
            that appends a ``"<port>: <failure>"`` string to ``all_failures``.

    Returns:
        tuple[list[str], int]: the per-port failure entries, and the number of
        qualifying ports that were checked.
    """
    ports_under_test = resolve_ports_under_test(lport_to_pport, port_attributes_dict)
    qualifying_ports = get_qualifying_ports(
        port_attributes_dict, lport_to_first_subport, ports_under_test
    )
    all_failures = []
    for port in qualifying_ports:
        check_fn(duthost, port, port_attributes_dict[port], all_failures)
    return all_failures, len(qualifying_ports)


def _check_firmware_versions(duthost, port, port_attrs, all_failures):
    """Per-port check: Active/Inactive firmware banks vs gold inventory.

    A qualifying port MUST define ``gold_firmware_version``; a missing value is
    an inventory gap and fails the test.  For dual-bank modules
    ``inactive_firmware_version`` is likewise mandatory (it is optional only
    when ``dual_bank_supported`` is false), so a dual-bank module missing it
    also fails.
    """
    cdb_attrs = port_attrs.get(CDB_FIRMWARE_UPGRADE_ATTRIBUTES_KEY, {})
    expected_active = cdb_attrs.get("gold_firmware_version")
    dual_bank_supported = cdb_attrs.get("dual_bank_supported", True)
    expected_inactive = cdb_attrs.get("inactive_firmware_version")

    if not expected_active:
        all_failures.append(f"{port}: gold_firmware_version not defined")
        return
    if dual_bank_supported and not expected_inactive:
        all_failures.append(
            f"{port}: inactive_firmware_version not defined for dual-bank module"
        )
        return

    parsed, err = cli_helpers.sfputil_show_fwversion(duthost, port)
    if err:
        all_failures.append(f"{port}: {err}")
        return

    actual_active = parsed.get(ACTIVE_FIRMWARE_KEY, "")
    if actual_active != expected_active:
        all_failures.append(
            f"{port}: active firmware mismatch: expected '{expected_active}', "
            f"got '{actual_active or 'N/A'}'"
        )

    if dual_bank_supported:
        actual_inactive = parsed.get(INACTIVE_FIRMWARE_KEY, "")
        if actual_inactive != expected_inactive:
            all_failures.append(
                f"{port}: inactive firmware mismatch: expected '{expected_inactive}', "
                f"got '{actual_inactive or 'N/A'}'"
            )


def _check_abort_support(abort_support_map, lport_to_pport, port, port_attrs, all_failures):
    """Per-port check: advertised CDB firmware-download abort support vs inventory.

    """
    cdb_attrs = port_attrs.get(CDB_FIRMWARE_UPGRADE_ATTRIBUTES_KEY, {})
    expected_abort_support = cdb_attrs.get("firmware_download_cdb_abort_support", True)

    physical_index = lport_to_pport.get(port)
    if physical_index is None:
        all_failures.append(f"{port}: could not resolve physical port index")
        return

    actual_abort_support, err = abort_support_map.get(
        physical_index, (None, "no CDB abort-support result for the port")
    )
    if err:
        all_failures.append(f"{port}: {err}")
        return

    if actual_abort_support != expected_abort_support:
        all_failures.append(
            f"{port}: CDB firmware-download abort support mismatch: "
            f"expected {expected_abort_support} "
            f"(firmware_download_cdb_abort_support), got {actual_abort_support} "
            f"(from EEPROM via get_module_fw_mgmt_feature)"
        )
        return
    logger.debug("Port %s CDB abort support verified: %s", port, actual_abort_support)


def test_firmware_versions(
    duthost, port_attributes_dict, lport_to_first_subport_mapping, get_lport_to_pport_mapping,
    dom_polling_disabled,
):
    """Verify each CMIS active-optical module runs its gold firmware.

    Active Firmware MUST equal ``gold_firmware_version``; for dual-bank modules
    Inactive Firmware MUST equal ``inactive_firmware_version``.  A qualifying
    port with no configured ``gold_firmware_version`` fails the test.

    DOM polling on the ports under test is disabled for the duration of the test
    by the ``dom_polling_disabled`` fixture.
    """
    all_failures, num_ports = _run_per_port_check(
        duthost, port_attributes_dict, lport_to_first_subport_mapping,
        get_lport_to_pport_mapping, _check_firmware_versions,
    )
    logger.info("Verified firmware version on %d port(s)", num_ports)
    if all_failures:
        pytest.fail("Firmware version verification failures:\n" + "\n".join(all_failures))


def test_cdb_abort_support(
    duthost, port_attributes_dict, lport_to_first_subport_mapping, get_lport_to_pport_mapping,
    dom_polling_disabled,
):
    """Verify advertised CDB firmware-download abort capability.

    DOM polling on the ports under test is disabled for the duration of the test
    by the ``dom_polling_disabled`` fixture.
    """
    lport_to_pport = get_lport_to_pport_mapping
    ports_under_test = resolve_ports_under_test(lport_to_pport, port_attributes_dict)
    qualifying_ports = get_qualifying_ports(
        port_attributes_dict, lport_to_first_subport_mapping, ports_under_test
    )

    physical_indices = []
    for port in qualifying_ports:
        physical_index = lport_to_pport.get(port)
        if physical_index is not None and physical_index not in physical_indices:
            physical_indices.append(physical_index)
    abort_support_map = cli_helpers.get_module_cdb_abort_support_map(duthost, physical_indices)

    all_failures = []
    for port in qualifying_ports:
        _check_abort_support(
            abort_support_map, lport_to_pport, port, port_attributes_dict[port], all_failures
        )
    logger.info("Verified CDB abort support on %d port(s)", len(qualifying_ports))
    if all_failures:
        pytest.fail("CDB firmware-download abort verification failures:\n" + "\n".join(all_failures))
