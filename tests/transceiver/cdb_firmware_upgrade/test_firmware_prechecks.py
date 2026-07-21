"""CDB firmware-upgrade pre-checks: TC1 (firmware version) and TC2 (abort support).

These baseline checks are meant to run FIRST in the CDB firmware-upgrade
sequence -- the later download/upgrade tests assume each module starts on its
gold firmware and advertises CDB abort support, which TC1/TC2 validate.  See
the ``docs/testplan/transceiver/cdb_firmware_upgrade_test_plan.md``.
"""
import logging

import pytest

from tests.common.platform.interface_utils import (
    get_physical_to_logical_port_mapping,
    is_first_subport,
)
from tests.transceiver.attribute_parser.attribute_keys import (
    CDB_FIRMWARE_UPGRADE_ATTRIBUTES_KEY,
    EEPROM_ATTRIBUTES_KEY,
)
from tests.transceiver.common import cli_helpers

logger = logging.getLogger(__name__)

ACTIVE_FIRMWARE_KEY = "Active Firmware"
INACTIVE_FIRMWARE_KEY = "Inactive Firmware"


def _resolve_ports_under_test(lport_to_pport, port_attributes_dict):
    """Resolve the set of logical ports the check should run on.

    ``ports_under_test`` is an optional DUT-level CDB attribute. When it is
    absent or empty the check runs on every qualifying port. When it is
    present the physical indices are mapped to their logical ports and only
    those logical ports are returned.

    Returns:
        set[str] | None: the logical ports to test, or ``None``
    """
    if not port_attributes_dict:
        return None
    cdb_attrs = next(iter(port_attributes_dict.values())).get(
        CDB_FIRMWARE_UPGRADE_ATTRIBUTES_KEY, {}
    )
    ports_under_test = cdb_attrs.get("ports_under_test")
    if not ports_under_test:
        return None
    ports_under_test = set(ports_under_test)
    pport_to_lport_mapping = get_physical_to_logical_port_mapping(lport_to_pport)
    resolved_ports = set()
    for pindex in ports_under_test:
        resolved_ports.update(pport_to_lport_mapping.get(pindex, []))
    return resolved_ports


def _get_qualifying_ports(port_attributes_dict, lport_to_first_subport, ports_under_test):
    """Return the ``(port, port_attrs)`` pairs the checks should run on.

    A port qualifies only when it has attributes, is the first breakout sub-port
    of its group, and is a non-DAC CMIS module (``cmis_active_optical``).

    Args:
        port_attributes_dict: ``{port: {attr_block: {...}}}`` inventory map.
        lport_to_first_subport: first-sub-port mapping fixture.
        ports_under_test: set of logical ports to restrict to.

    Returns:
        list[tuple[str, dict]]: the qualifying ``(port, port_attrs)`` pairs.
    """
    qualifying_ports = []
    for port, port_attrs in port_attributes_dict.items():
        if not port_attrs:
            logger.debug("Port %s has no attributes, skipping", port)
            continue
        if ports_under_test is not None and port not in ports_under_test:
            logger.debug("Port %s is not in ports_under_test, skipping", port)
            continue
        if not is_first_subport(port, lport_to_first_subport):
            logger.debug("Port %s is not the first breakout sub-port, skipping", port)
            continue

        eeprom_attrs = port_attrs.get(EEPROM_ATTRIBUTES_KEY, {})
        if not eeprom_attrs.get("cmis_active_optical"):
            logger.debug("Port %s: cmis_active_optical is not True, skipping", port)
            continue

        qualifying_ports.append((port, port_attrs))
    return qualifying_ports


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
        list[str]: one ``"<port>: <failure>"`` entry per failure found.
    """
    ports_under_test = _resolve_ports_under_test(lport_to_pport, port_attributes_dict)
    all_failures = []
    for port, port_attrs in _get_qualifying_ports(
        port_attributes_dict, lport_to_first_subport, ports_under_test
    ):
        check_fn(duthost, port, port_attrs, all_failures)
    return all_failures


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

    if not expected_active or (dual_bank_supported and not expected_inactive):
        all_failures.append(f"{port}: mandatory attribute not defined")
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
    duthost, port_attributes_dict, lport_to_first_subport_mapping, get_lport_to_pport_mapping
):
    """Verify each CMIS active-optical module runs its gold firmware.

    Active Firmware MUST equal ``gold_firmware_version``; for dual-bank modules
    Inactive Firmware MUST equal ``inactive_firmware_version``.  A qualifying
    port with no configured ``gold_firmware_version`` fails the test.

    Prerequisite: DOM monitoring must be disabled on the ports under test before
    this runs.
    """
    all_failures = _run_per_port_check(
        duthost, port_attributes_dict, lport_to_first_subport_mapping,
        get_lport_to_pport_mapping, _check_firmware_versions,
    )
    if all_failures:
        pytest.fail("Firmware version verification failures:\n" + "\n".join(all_failures))


def test_cdb_abort_support(
    duthost, port_attributes_dict, lport_to_first_subport_mapping, get_lport_to_pport_mapping
):
    """Verify advertised CDB firmware-download abort capability.

    Prerequisite: DOM monitoring must be disabled on the ports under test before
    this runs.
    """
    lport_to_pport = get_lport_to_pport_mapping
    ports_under_test = _resolve_ports_under_test(lport_to_pport, port_attributes_dict)
    qualifying_ports = _get_qualifying_ports(
        port_attributes_dict, lport_to_first_subport_mapping, ports_under_test
    )

    physical_indices = []
    for port, _ in qualifying_ports:
        physical_index = lport_to_pport.get(port)
        if physical_index is not None and physical_index not in physical_indices:
            physical_indices.append(physical_index)
    abort_support_map = cli_helpers.get_module_cdb_abort_support_map(duthost, physical_indices)

    all_failures = []
    for port, port_attrs in qualifying_ports:
        _check_abort_support(abort_support_map, lport_to_pport, port, port_attrs, all_failures)
    if all_failures:
        pytest.fail("CDB firmware-download abort verification failures:\n" + "\n".join(all_failures))
