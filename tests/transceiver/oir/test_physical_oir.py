"""Physical Online Insertion and Removal (OIR).

Implements the Physical OIR test cases TC1-TC4 from
``docs/testplan/transceiver/online_insertion_removal_testplan.md``; the TC5/TC6
hot-swap cases are not implemented here.

Every insertion / removal is performed by a human: the test prints a prompt on
the terminal (pytest capture suspended) and blocks until the operator confirms,
then waits for the DUT to observe the new presence state before verifying it.
One prompt covers every port under test, so the operator handles the whole set
in a single pass.  Per-port failures are aggregated into a single
``pytest.fail`` so one run surfaces every issue across every port under test.
"""
import logging

import pytest

from tests.common.platform.interface_utils import wait_ports_oper_status
from tests.transceiver.attribute_parser.attribute_keys import (
    DOM_ATTRIBUTES_KEY,
    PHYSICAL_OIR_ATTRIBUTES_KEY,
    SYSTEM_ATTRIBUTES_KEY,
)
from tests.transceiver.common import scenario_ops
from tests.transceiver.common.health_checks import capture_baseline
from tests.transceiver.common.verification import standard_port_recovery_and_verification
from tests.transceiver.eeprom import datapath
from tests.transceiver.eeprom.eeprom_content import (
    verify_eeprom_static_recovered,
    verify_firmware_info_recovered,
)
from tests.transceiver.oir import oir_helpers

logger = logging.getLogger(__name__)


def _parents_of(lports, lport_to_first_subport_mapping):
    """Return the first sub-ports of the modules ``lports`` belong to."""
    return sorted({lport_to_first_subport_mapping.get(port, port) for port in lports})


def _all_ports(oir_pport_to_lports, port_attributes_dict):
    """Return physical ports, logical ports, and each port's OIR attribute shard."""
    pports = list(oir_pport_to_lports)
    lports = [port for ports in oir_pport_to_lports.values() for port in ports]
    unconfigured = [
        port for port in lports
        if not port_attributes_dict.get(port, {}).get(PHYSICAL_OIR_ATTRIBUTES_KEY)
    ]
    if unconfigured:
        pytest.fail(f"port(s) under test without PHYSICAL_OIR_ATTRIBUTES: {unconfigured}")
    return pports, lports, {
        port: port_attributes_dict[port][PHYSICAL_OIR_ATTRIBUTES_KEY] for port in lports
    }


def _bulk_waits(port_attributes_dict, lports):
    """Return the (shutdown, startup) settle budgets scaled to an all-at-once OIR.

    The slowest port under test sets the budget: a bulk OIR is only settled once
    every module has settled.
    """
    system_attrs = [port_attributes_dict[port].get(SYSTEM_ATTRIBUTES_KEY, {}) for port in lports]
    return (
        scenario_ops.scale_bulk_wait(
            max(attrs["port_shutdown_wait_sec"] for attrs in system_attrs), len(lports)),
        scenario_ops.scale_bulk_wait(
            max(attrs["port_startup_wait_sec"] for attrs in system_attrs), len(lports)),
    )


def _dom_recover_wait(port_attributes_dict, lports, wait_sec):
    """Return ``wait_sec`` plus the slowest port's DOM republish budget.

    ``TRANSCEIVER_DOM_SENSOR`` / ``TRANSCEIVER_FIRMWARE_INFO`` are republished on
    xcvrd's delayed DOM cycle, so both need the settle budget plus that cycle.
    """
    return wait_sec + max(
        (port_attributes_dict[port].get(DOM_ATTRIBUTES_KEY, {}).get("dom_info_recover_sec", 0)
         for port in lports), default=0)


def _verify_eeprom_recovered(duthost, port_attributes_dict, lport_to_first_subport_mapping,
                             lports, wait_sec):
    """TC2 EEPROM results: inventory content, CMIS DataPath fields and firmware."""
    target_attributes = {port: port_attributes_dict[port] for port in lports}
    failures = []

    static_failures = verify_eeprom_static_recovered(
        duthost, port_attributes_dict, lport_to_first_subport_mapping, wait_sec,
        ports=lports,
        # The module was just re-seated, so the first I2C read is legitimately slow.
        enforce_timeout=False,
    )
    if static_failures:
        failures.append("static EEPROM content:\n  " + "\n  ".join(static_failures))

    datapath_failures = datapath.verify_datapath_recovered(
        duthost, port_attributes_dict, wait_sec,
        ports=datapath.cmis_active_optical_ports(target_attributes),
    )
    if datapath_failures:
        failures.append("DataPath fields:\n  " + "\n  ".join(datapath_failures))

    firmware_failures = verify_firmware_info_recovered(
        duthost, port_attributes_dict,
        _dom_recover_wait(port_attributes_dict, lports, wait_sec), ports=lports)
    if firmware_failures:
        failures.append("firmware versions:\n  " + "\n  ".join(firmware_failures))

    return failures


def _capture_table_baseline(duthost, lports):
    """Snapshot the seated modules' STATE_DB tables, plus any scan failures."""
    baseline_tables, errors = oir_helpers.capture_state_tables(duthost, lports)
    return baseline_tables, [f"STATE_DB baseline: {error}" for error in errors]


def _verify_removal(duthost, port_attributes_dict, lports, flap_baseline, watermark, wait_sec):
    """TC1 expected results for the ports whose module was just removed."""
    failures = wait_ports_oper_status(duthost, lports, "down", wait_sec)
    failures += oir_helpers.verify_presence_clis(duthost, lports, present=False)
    failures += oir_helpers.verify_state_tables_removed(duthost, lports, wait_sec)
    failures += oir_helpers.verify_other_ports_up(duthost, port_attributes_dict, lports)
    failures += oir_helpers.verify_flap_count_increment(duthost, lports, flap_baseline)
    failures += oir_helpers.verify_no_kernel_errors(duthost, watermark)
    return failures


def _verify_insertion(duthost, port_attributes_dict, lport_to_first_subport_mapping,
                      oir_attrs_by_port, lports, health_baseline, watermark, wait_sec,
                      baseline_tables=None, insert_flap_baseline=None, expected_flap_increment=1):
    """TC2 expected results for the ports whose module was just inserted."""
    failures = oir_helpers.verify_presence_clis(duthost, lports, present=True)
    failures += oir_helpers.verify_state_tables_present(
        duthost, lports, _parents_of(lports, lport_to_first_subport_mapping), wait_sec,
        baseline_tables=baseline_tables)

    recovery = standard_port_recovery_and_verification(
        duthost, lports, {port: port_attributes_dict[port] for port in lports},
        link_up_timeout_sec=wait_sec,
        health_baseline=health_baseline,
        lport_to_first_subport_mapping=lport_to_first_subport_mapping,
    )
    if not recovery["passed"]:
        failures.append(recovery["details"])

    # TC2 step 8: the local port must come up without flapping across the
    # insertion itself, which a post-recovery sentinel alone cannot see.
    if insert_flap_baseline is not None:
        failures += oir_helpers.verify_flap_count_increment(
            duthost, lports, insert_flap_baseline, expected_increment=expected_flap_increment)

    failures += _verify_eeprom_recovered(
        duthost, port_attributes_dict, lport_to_first_subport_mapping, lports, wait_sec)

    # TC2 step 3: DOM data must be republished with valid, fresh values once the
    # module is back (VDM / PM re-publication is covered by the STATE_DB table
    # check above, which is driven by the pre-removal baseline).
    dom_failures = oir_helpers.verify_dom_data_recovered(
        duthost, port_attributes_dict, lport_to_first_subport_mapping, lports,
        _dom_recover_wait(port_attributes_dict, lports, wait_sec))
    if dom_failures:
        failures.append("DOM sensor data:\n  " + "\n  ".join(dom_failures))

    failures += oir_helpers.verify_no_link_flap(duthost, oir_attrs_by_port)
    failures += oir_helpers.verify_no_kernel_errors(duthost, watermark)
    return failures


def test_physical_oir_removal(
    request, duthost, port_attributes_dict, physical_oir_dut_attributes, oir_pport_to_lports,
):
    """TC1: verify DUT state after every module under test is physically removed."""
    pports, lports, oir_attrs_by_port = _all_ports(oir_pport_to_lports, port_attributes_dict)
    shutdown_wait, startup_wait = _bulk_waits(port_attributes_dict, lports)

    flap_baseline = oir_helpers.get_flap_counts(duthost, lports)
    watermark = oir_helpers.capture_kernel_error_watermark(duthost, oir_attrs_by_port)

    all_failures = oir_helpers.perform_oir(
        request, duthost, physical_oir_dut_attributes, pports, present=False,
        action="REMOVE the transceiver from every port listed below")
    if not all_failures:
        all_failures = _verify_removal(
            duthost, port_attributes_dict, lports, flap_baseline, watermark, shutdown_wait)

    # Re-seat so the next test starts from a fully linked-up switch.
    all_failures += oir_helpers.perform_oir(
        request, duthost, physical_oir_dut_attributes, pports, present=True,
        action="INSERT the transceiver back into every port listed below")
    all_failures += wait_ports_oper_status(duthost, lports, "up", startup_wait)

    if all_failures:
        pytest.fail("Physical OIR removal (TC1) failures:\n  - " + "\n  - ".join(all_failures))


def test_physical_oir_insertion(
    request, duthost, port_attributes_dict, physical_oir_dut_attributes, oir_pport_to_lports,
    lport_to_first_subport_mapping,
):
    """TC2: verify DUT state after every module under test is physically inserted."""
    pports, lports, oir_attrs_by_port = _all_ports(oir_pport_to_lports, port_attributes_dict)
    shutdown_wait, startup_wait = _bulk_waits(port_attributes_dict, lports)

    # Snapshot while the modules are still seated: it defines which module
    # dependent tables (flag / VDM / PM) must be republished after insertion.
    baseline_tables, setup_failures = _capture_table_baseline(duthost, lports)

    # Setup: every cage has to be empty before the insertion under test.
    setup_failures += oir_helpers.perform_oir(
        request, duthost, physical_oir_dut_attributes, pports, present=False,
        action="REMOVE the transceiver from every port listed below")
    setup_failures += wait_ports_oper_status(duthost, lports, "down", shutdown_wait)
    if setup_failures:
        pytest.fail("Physical OIR insertion (TC2) setup failures:\n  - " + "\n  - ".join(setup_failures))

    health_baseline = capture_baseline(duthost)
    watermark = oir_helpers.capture_kernel_error_watermark(duthost, oir_attrs_by_port)
    insert_flap_baseline = oir_helpers.get_flap_counts(duthost, lports)
    all_failures = oir_helpers.perform_oir(
        request, duthost, physical_oir_dut_attributes, pports, present=True,
        action="INSERT the transceiver into every port listed below")
    if not all_failures:
        all_failures = _verify_insertion(
            duthost, port_attributes_dict, lport_to_first_subport_mapping,
            oir_attrs_by_port, lports, health_baseline, watermark, startup_wait,
            baseline_tables=baseline_tables, insert_flap_baseline=insert_flap_baseline)

    if all_failures:
        pytest.fail("Physical OIR insertion (TC2) failures:\n  - " + "\n  - ".join(all_failures))


def test_physical_oir_simultaneous(
    request, duthost, port_attributes_dict, physical_oir_dut_attributes, oir_pport_to_lports,
    lport_to_first_subport_mapping,
):
    """TC3: remove and re-insert every module under test simultaneously."""
    if not physical_oir_dut_attributes["simultaneous_oir"]:
        pytest.skip("simultaneous_oir is False")

    pports, lports, oir_attrs_by_port = _all_ports(oir_pport_to_lports, port_attributes_dict)
    shutdown_wait, startup_wait = _bulk_waits(port_attributes_dict, lports)

    baseline_tables, all_failures = _capture_table_baseline(duthost, lports)
    flap_baseline = oir_helpers.get_flap_counts(duthost, lports)
    watermark = oir_helpers.capture_kernel_error_watermark(duthost, oir_attrs_by_port)
    all_failures += oir_helpers.perform_oir(
        request, duthost, physical_oir_dut_attributes, pports, present=False,
        action="REMOVE ALL the transceivers simultaneously")
    if not all_failures:
        all_failures = _verify_removal(
            duthost, port_attributes_dict, lports, flap_baseline, watermark, shutdown_wait)

    health_baseline = capture_baseline(duthost)
    watermark = oir_helpers.capture_kernel_error_watermark(duthost, oir_attrs_by_port)
    insert_flap_baseline = oir_helpers.get_flap_counts(duthost, lports)
    insert_failures = oir_helpers.perform_oir(
        request, duthost, physical_oir_dut_attributes, pports, present=True,
        action="INSERT ALL the transceivers simultaneously")
    all_failures += insert_failures or _verify_insertion(
        duthost, port_attributes_dict, lport_to_first_subport_mapping,
        oir_attrs_by_port, lports, health_baseline, watermark, startup_wait,
        baseline_tables=baseline_tables, insert_flap_baseline=insert_flap_baseline)

    if all_failures:
        pytest.fail("Simultaneous physical OIR (TC3) failures:\n  - " + "\n  - ".join(all_failures))


def test_physical_oir_stress(
    request, duthost, port_attributes_dict, physical_oir_dut_attributes, oir_pport_to_lports,
    lport_to_first_subport_mapping,
):
    """TC4: OIR every module repeatedly and verify recovery after the last insertion."""
    pports, lports, oir_attrs_by_port = _all_ports(oir_pport_to_lports, port_attributes_dict)
    iterations = physical_oir_dut_attributes["physical_oir_stress_iteration"]
    if not isinstance(iterations, int) or iterations < 1:
        pytest.fail(
            "physical_oir_stress_iteration must be a positive integer to exercise a stress "
            f"cycle, got {iterations!r}")
    _, startup_wait = _bulk_waits(port_attributes_dict, lports)

    all_failures = []
    baseline_tables, baseline_failures = _capture_table_baseline(duthost, lports)
    if baseline_failures:
        pytest.fail("Physical OIR stress (TC4) setup failures:\n  - " + "\n  - ".join(baseline_failures))
    health_baseline = capture_baseline(duthost)
    watermark = oir_helpers.capture_kernel_error_watermark(duthost, oir_attrs_by_port)
    insert_flap_baseline = None
    # Only the last insertion is verified; the earlier cycles just have to
    # complete and be observed by the DUT.
    for iteration in range(1, iterations + 1):
        logger.info("Physical OIR stress iteration %d/%d on %d module(s)",
                    iteration, iterations, len(pports))
        all_failures = oir_helpers.perform_oir(
            request, duthost, physical_oir_dut_attributes, pports, present=False,
            action=f"REMOVE ALL the transceivers (stress iteration {iteration}/{iterations})")
        if all_failures:
            break
        health_baseline = capture_baseline(duthost)
        watermark = oir_helpers.capture_kernel_error_watermark(duthost, oir_attrs_by_port)
        insert_flap_baseline = oir_helpers.get_flap_counts(duthost, lports)
        all_failures = oir_helpers.perform_oir(
            request, duthost, physical_oir_dut_attributes, pports, present=True,
            action=f"INSERT ALL the transceivers (stress iteration {iteration}/{iterations})")
        if all_failures:
            break

    if not all_failures:
        all_failures = _verify_insertion(
            duthost, port_attributes_dict, lport_to_first_subport_mapping,
            oir_attrs_by_port, lports, health_baseline, watermark, startup_wait,
            baseline_tables=baseline_tables, insert_flap_baseline=insert_flap_baseline)

    if all_failures:
        pytest.fail("Physical OIR stress (TC4) failures:\n  - " + "\n  - ".join(all_failures))
