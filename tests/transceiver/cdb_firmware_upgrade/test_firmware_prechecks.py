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
from tests.transceiver.common import cli_helpers

logger = logging.getLogger(__name__)

ACTIVE_FIRMWARE_KEY = "Active Firmware"
INACTIVE_FIRMWARE_KEY = "Inactive Firmware"


def _run_per_port_check(duthost, port_attributes_dict, qualifying_ports, lport_to_pport,
                        check_fn, prefetch=None):
    """Iterate qualifying ports, run ``check_fn``, and aggregate failures.

    Args:
        duthost: DUT host fixture.
        port_attributes_dict: ``{port: {attr_block: {...}}}`` inventory map.
        qualifying_ports: ports to check (from the ``cdb_firmware_qualifying_ports`` fixture).
        lport_to_pport: ``{logical_port: physical_index}`` map, passed to ``prefetch``.
        check_fn: callable ``(duthost, port, port_attrs, all_failures, prefetched) -> None``
            that appends a ``"<port>: <failure>"`` string to ``all_failures``.
        prefetch: optional callable
            ``(duthost, qualifying_ports, lport_to_pport) -> prefetched`` run once before
            iterating; its result is passed to every ``check_fn`` call.  Lets a check
            batch a single DUT query once and share it across ports.

    Returns:
        tuple[list[str], int]: the per-port failure entries, and the number of
        qualifying ports that were checked.
    """
    prefetched = prefetch(duthost, qualifying_ports, lport_to_pport) if prefetch else None
    all_failures = []
    for port in qualifying_ports:
        check_fn(duthost, port, port_attributes_dict[port], all_failures, prefetched)
    return all_failures, len(qualifying_ports)


def _check_firmware_versions(duthost, port, port_attrs, all_failures, prefetched=None):
    """Per-port check: Active/Inactive firmware banks vs gold inventory.

    A qualifying port MUST define ``gold_firmware_version``; a missing value is
    an inventory gap and fails the test.  For dual-bank modules
    ``inactive_firmware_version`` is likewise mandatory (it is optional only
    when ``dual_bank_supported`` is false), so a dual-bank module missing it
    also fails.

    Args:
        duthost: DUT host fixture used to run ``sfputil show fwversion``.
        port: logical port being checked.
        port_attrs: this port's attribute blocks from ``port_attributes_dict``.
        all_failures: shared list; a ``"<port>: <failure>"`` string is appended on mismatch.
        prefetched: unused; kept for the shared ``check_fn`` signature.

    Returns:
        None. Any mismatch/error is appended to ``all_failures``.
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


def _build_abort_support_map(duthost, qualifying_ports, lport_to_pport):
    """Batch the CDB abort-support query for all qualifying ports into one DUT call.

    Returns ``{logical_port: (abort_supported, err)}`` keyed by logical port, so
    ``_check_abort_support`` needs no physical-index lookup of its own.
    """
    physical_indices = []
    for port in qualifying_ports:
        physical_index = lport_to_pport.get(port)
        if physical_index is not None and physical_index not in physical_indices:
            physical_indices.append(physical_index)
    abort_support_map = cli_helpers.get_module_cdb_abort_support_map(duthost, physical_indices)

    result = {}
    for port in qualifying_ports:
        physical_index = lport_to_pport.get(port)
        if physical_index is None:
            result[port] = (None, "could not resolve physical port index")
        else:
            result[port] = abort_support_map.get(
                physical_index, (None, "no CDB abort-support result for the port")
            )
    return result


def _check_abort_support(duthost, port, port_attrs, all_failures, prefetched):
    """Per-port check: advertised CDB firmware-download abort support vs inventory.

    Args:
        duthost: DUT host fixture (unused; kept for the shared ``check_fn`` signature).
        port: logical port being checked.
        port_attrs: this port's attribute blocks from ``port_attributes_dict``.
        all_failures: shared list; a ``"<port>: <failure>"`` string is appended on mismatch.
        prefetched: ``{logical_port: (abort_supported, err)}`` map

    Returns:
        None. Any mismatch/error is appended to ``all_failures``.
    """
    cdb_attrs = port_attrs.get(CDB_FIRMWARE_UPGRADE_ATTRIBUTES_KEY, {})
    expected_abort_support = cdb_attrs.get("firmware_download_cdb_abort_support", True)

    actual_abort_support, err = prefetched[port]
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
    duthost, port_attributes_dict, cdb_firmware_qualifying_ports, get_lport_to_pport_mapping,
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
        duthost, port_attributes_dict, cdb_firmware_qualifying_ports,
        get_lport_to_pport_mapping, _check_firmware_versions,
    )
    logger.info("Verified firmware version on %d port(s)", num_ports)
    if all_failures:
        pytest.fail("Firmware version verification failures:\n" + "\n".join(all_failures))


def test_cdb_abort_support(
    duthost, port_attributes_dict, cdb_firmware_qualifying_ports, get_lport_to_pport_mapping,
    dom_polling_disabled,
):
    """Verify advertised CDB firmware-download abort capability.

    DOM polling on the ports under test is disabled for the duration of the test
    by the ``dom_polling_disabled`` fixture.
    """
    all_failures, num_ports = _run_per_port_check(
        duthost, port_attributes_dict, cdb_firmware_qualifying_ports,
        get_lport_to_pport_mapping, _check_abort_support,
        prefetch=_build_abort_support_map,
    )
    logger.info("Verified CDB abort support on %d port(s)", num_ports)
    if all_failures:
        pytest.fail("CDB firmware-download abort verification failures:\n" + "\n".join(all_failures))
