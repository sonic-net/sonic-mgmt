"""CDB firmware-upgrade pre-checks: TC1 (firmware version) and TC2 (abort support).

These baseline checks are meant to run FIRST in the CDB firmware-upgrade
sequence -- the later download/upgrade tests assume each module starts on its
gold firmware and advertises CDB abort support, which TC1/TC2 validate.  See
the ``docs/testplan/transceiver/cdb_firmware_upgrade_test_plan.md``.
"""
import logging

import pytest

from tests.transceiver.cdb_firmware_upgrade.firmware_operations import execute_on_ports
from tests.transceiver.common import cli_helpers
from tests.transceiver.common.cli_parser_helper import FW_ACTIVE, FW_INACTIVE

logger = logging.getLogger(__name__)


def _check_firmware_versions(duthost, port, port_context, metadata_map):
    """Per-port op: Active/Inactive firmware banks vs gold inventory.

    A qualifying port MUST define ``gold_firmware_version``; a missing value is
    an inventory gap and fails the test.  For dual-bank modules
    ``inactive_firmware_version`` is likewise mandatory (it is optional only
    when ``dual_bank_supported`` is false), so a dual-bank module missing it
    also fails.

    Returns a list of per-port failure strings (empty on success).
    """
    cdb_attrs = port_context["cdb_attrs"]
    expected_active = cdb_attrs.get("gold_firmware_version")
    dual_bank_supported = cdb_attrs.get("dual_bank_supported", True)
    expected_inactive = cdb_attrs.get("inactive_firmware_version")

    if not expected_active:
        return ["gold_firmware_version not defined"]
    if dual_bank_supported and not expected_inactive:
        return ["inactive_firmware_version not defined for dual-bank module"]

    parsed, err = cli_helpers.sfputil_show_fwversion(duthost, port)
    if err:
        return [err]

    failures = []
    actual_active = parsed.get(FW_ACTIVE, "")
    if actual_active != expected_active:
        failures.append(
            f"active firmware mismatch: expected '{expected_active}', "
            f"got '{actual_active or 'N/A'}'"
        )

    if dual_bank_supported:
        actual_inactive = parsed.get(FW_INACTIVE, "")
        if actual_inactive != expected_inactive:
            failures.append(
                f"inactive firmware mismatch: expected '{expected_inactive}', "
                f"got '{actual_inactive or 'N/A'}'"
            )
    return failures


def _build_abort_support_map(duthost, qualifying_ports, lport_to_pport):
    """Batch the CDB abort-support query for all qualifying ports into one DUT call.

    Returns ``{physical_index: (abort_supported, err)}``; the driver already
    resolves each port's physical index into ``port_context``.
    """
    physical_indices = []
    for port in qualifying_ports:
        physical_index = lport_to_pport.get(port)
        if physical_index is not None:
            physical_indices.append(physical_index)
    return cli_helpers.get_module_cdb_abort_support_map(duthost, physical_indices)


def _check_abort_support(duthost, port, port_context, metadata_map):
    """Per-port op: advertised CDB firmware-download abort support vs inventory.

    Returns a list of per-port failure strings (empty on success).
    """
    expected_abort_support = port_context["cdb_attrs"].get("firmware_download_cdb_abort_support", True)
    actual_abort_support, err = port_context["prefetched"].get(
        port_context["physical_index"], (None, "no CDB abort-support result for the port")
    )
    if err:
        return [err]

    if actual_abort_support != expected_abort_support:
        return [
            "CDB firmware-download abort support mismatch: "
            f"expected {expected_abort_support} "
            f"(firmware_download_cdb_abort_support), got {actual_abort_support} "
            "(from EEPROM via get_module_fw_mgmt_feature)"
        ]
    logger.debug("Port %s CDB abort support verified: %s", port, actual_abort_support)
    return []


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
    all_failures, num_ports = execute_on_ports(
        duthost, port_attributes_dict, cdb_firmware_qualifying_ports,
        get_lport_to_pport_mapping, None, _check_firmware_versions,
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
    all_failures, num_ports = execute_on_ports(
        duthost, port_attributes_dict, cdb_firmware_qualifying_ports,
        get_lport_to_pport_mapping, None, _check_abort_support,
        prefetch=_build_abort_support_map,
    )
    logger.info("Verified CDB abort support on %d port(s)", num_ports)
    if all_failures:
        pytest.fail("CDB firmware-download abort verification failures:\n" + "\n".join(all_failures))
