"""Physical Online Insertion and Removal (OIR).

Implements the Physical OIR test cases (TC1-TC6) from
``docs/testplan/transceiver/online_insertion_removal_testplan.md``.

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
from tests.transceiver.common import scenario_ops
from tests.transceiver.common.health_checks import capture_baseline
from tests.transceiver.common.verification import standard_port_recovery_and_verification
from tests.transceiver.oir import oir_helpers

logger = logging.getLogger(__name__)


def _parents_of(lports, lport_to_first_subport_mapping):
    """Return the first sub-ports of the modules ``lports`` belong to."""
    return sorted({lport_to_first_subport_mapping.get(port, port) for port in lports})


def _all_ports(oir_pport_to_lports):
    """Return ``(physical indices, logical ports)`` for every port under test."""
    return (list(oir_pport_to_lports),
            [port for ports in oir_pport_to_lports.values() for port in ports])


def _bulk_waits(oir_system_attributes, num_ports):
    """Return the (shutdown, startup) settle budgets scaled to an all-at-once OIR."""
    return (
        scenario_ops.scale_bulk_wait(oir_system_attributes["port_shutdown_wait_sec"], num_ports),
        scenario_ops.scale_bulk_wait(oir_system_attributes["port_startup_wait_sec"], num_ports),
    )


def _prefix(pport, failures):
    """Tag ``failures`` with the physical port they came from."""
    return [f"physical port {pport}: {failure}" for failure in failures]


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
                      oir_attrs, lports, health_baseline, watermark, wait_sec):
    """TC2 expected results for the ports whose module was just inserted."""
    failures = oir_helpers.verify_presence_clis(duthost, lports, present=True)
    failures += oir_helpers.verify_state_tables_present(
        duthost, lports, _parents_of(lports, lport_to_first_subport_mapping), wait_sec)

    recovery = standard_port_recovery_and_verification(
        duthost, lports, {port: port_attributes_dict[port] for port in lports},
        link_up_timeout_sec=wait_sec,
        health_baseline=health_baseline,
        lport_to_first_subport_mapping=lport_to_first_subport_mapping,
    )
    if not recovery["passed"]:
        failures.append(recovery["details"])

    failures += oir_helpers.verify_no_link_flap(duthost, lports, oir_attrs["link_flap_monitor_timeout_sec"])
    failures += oir_helpers.verify_no_kernel_errors(duthost, watermark)
    return failures


def _verify_hot_swapped_module(duthost, lports, pport, expected_class, original_serials,
                               lport_to_first_subport_mapping, wait_sec):
    """Checks for a hot-swapped optic: readable EEPROM, new serial, expected class."""
    failures = oir_helpers.verify_presence_clis(duthost, lports, present=True)
    failures += oir_helpers.verify_state_tables_present(
        duthost, lports, _parents_of(lports, lport_to_first_subport_mapping), wait_sec)

    serials, err = oir_helpers.get_vendor_serials(duthost, lports)
    if err:
        failures.append(err)
    else:
        failures += [
            f"{port}: Vendor SN {serials[port]!r} unchanged after the hot swap"
            for port in lports if serials.get(port) and serials[port] == original_serials.get(port)
        ]

    class_name, class_err = oir_helpers.get_xcvr_api_class_names(duthost, [pport])[pport]
    if class_err:
        failures.append(class_err)
    elif class_name != expected_class:
        failures.append(f"XcvrApi class is {class_name}, expected {expected_class}")
    return failures


def test_physical_oir_removal(
    request, duthost, port_attributes_dict, physical_oir_attributes,
    oir_system_attributes, oir_pport_to_lports,
):
    """TC1: verify DUT state after every module under test is physically removed."""
    pports, lports = _all_ports(oir_pport_to_lports)
    shutdown_wait, startup_wait = _bulk_waits(oir_system_attributes, len(lports))

    flap_baseline = oir_helpers.get_flap_counts(duthost, lports)
    watermark = oir_helpers.capture_kernel_error_watermark(duthost, physical_oir_attributes)

    all_failures = oir_helpers.perform_oir(
        request, duthost, physical_oir_attributes, pports, present=False,
        action="REMOVE the transceiver from every port listed below")
    if not all_failures:
        all_failures = _verify_removal(
            duthost, port_attributes_dict, lports, flap_baseline, watermark, shutdown_wait)

    # Re-seat so the next test starts from a fully linked-up switch.
    all_failures += oir_helpers.perform_oir(
        request, duthost, physical_oir_attributes, pports, present=True,
        action="INSERT the transceiver back into every port listed below")
    all_failures += wait_ports_oper_status(duthost, lports, "up", startup_wait)

    if all_failures:
        pytest.fail("Physical OIR removal (TC1) failures:\n  - " + "\n  - ".join(all_failures))


def test_physical_oir_insertion(
    request, duthost, port_attributes_dict, physical_oir_attributes,
    oir_system_attributes, oir_pport_to_lports, lport_to_first_subport_mapping,
):
    """TC2: verify DUT state after every module under test is physically inserted."""
    pports, lports = _all_ports(oir_pport_to_lports)
    shutdown_wait, startup_wait = _bulk_waits(oir_system_attributes, len(lports))

    # Setup: every cage has to be empty before the insertion under test.
    setup_failures = oir_helpers.perform_oir(
        request, duthost, physical_oir_attributes, pports, present=False,
        action="REMOVE the transceiver from every port listed below")
    setup_failures += wait_ports_oper_status(duthost, lports, "down", shutdown_wait)
    if setup_failures:
        pytest.fail("Physical OIR insertion (TC2) setup failures:\n  - " + "\n  - ".join(setup_failures))

    health_baseline = capture_baseline(duthost)
    watermark = oir_helpers.capture_kernel_error_watermark(duthost, physical_oir_attributes)
    all_failures = oir_helpers.perform_oir(
        request, duthost, physical_oir_attributes, pports, present=True,
        action="INSERT the transceiver into every port listed below")
    if not all_failures:
        all_failures = _verify_insertion(
            duthost, port_attributes_dict, lport_to_first_subport_mapping,
            physical_oir_attributes, lports, health_baseline, watermark, startup_wait)

    if all_failures:
        pytest.fail("Physical OIR insertion (TC2) failures:\n  - " + "\n  - ".join(all_failures))


def test_physical_oir_simultaneous(
    request, duthost, port_attributes_dict, physical_oir_attributes,
    oir_system_attributes, oir_pport_to_lports, lport_to_first_subport_mapping,
):
    """TC3: remove and re-insert every module under test simultaneously."""
    if not physical_oir_attributes["simultaneous_oir"]:
        pytest.skip("simultaneous_oir is False")

    pports, lports = _all_ports(oir_pport_to_lports)
    shutdown_wait, startup_wait = _bulk_waits(oir_system_attributes, len(lports))

    flap_baseline = oir_helpers.get_flap_counts(duthost, lports)
    watermark = oir_helpers.capture_kernel_error_watermark(duthost, physical_oir_attributes)
    all_failures = oir_helpers.perform_oir(
        request, duthost, physical_oir_attributes, pports, present=False,
        action="REMOVE ALL the transceivers simultaneously")
    if not all_failures:
        all_failures = _verify_removal(
            duthost, port_attributes_dict, lports, flap_baseline, watermark, shutdown_wait)

    health_baseline = capture_baseline(duthost)
    watermark = oir_helpers.capture_kernel_error_watermark(duthost, physical_oir_attributes)
    insert_failures = oir_helpers.perform_oir(
        request, duthost, physical_oir_attributes, pports, present=True,
        action="INSERT ALL the transceivers simultaneously")
    all_failures += insert_failures or _verify_insertion(
        duthost, port_attributes_dict, lport_to_first_subport_mapping,
        physical_oir_attributes, lports, health_baseline, watermark, startup_wait)

    if all_failures:
        pytest.fail("Simultaneous physical OIR (TC3) failures:\n  - " + "\n  - ".join(all_failures))


def test_physical_oir_stress(
    request, duthost, port_attributes_dict, physical_oir_attributes,
    oir_system_attributes, oir_pport_to_lports, lport_to_first_subport_mapping,
):
    """TC4: OIR every module repeatedly and verify recovery after the last insertion."""
    pports, lports = _all_ports(oir_pport_to_lports)
    iterations = physical_oir_attributes["physical_oir_stress_iteration"]
    _, startup_wait = _bulk_waits(oir_system_attributes, len(lports))

    all_failures = []
    health_baseline = capture_baseline(duthost)
    watermark = oir_helpers.capture_kernel_error_watermark(duthost, physical_oir_attributes)
    # Only the last insertion is verified; the earlier cycles just have to
    # complete and be observed by the DUT.
    for iteration in range(1, iterations + 1):
        logger.info("Physical OIR stress iteration %d/%d on %d module(s)",
                    iteration, iterations, len(pports))
        all_failures = oir_helpers.perform_oir(
            request, duthost, physical_oir_attributes, pports, present=False,
            action=f"REMOVE ALL the transceivers (stress iteration {iteration}/{iterations})")
        if all_failures:
            break
        health_baseline = capture_baseline(duthost)
        watermark = oir_helpers.capture_kernel_error_watermark(duthost, physical_oir_attributes)
        all_failures = oir_helpers.perform_oir(
            request, duthost, physical_oir_attributes, pports, present=True,
            action=f"INSERT ALL the transceivers (stress iteration {iteration}/{iterations})")
        if all_failures:
            break

    if not all_failures:
        all_failures = _verify_insertion(
            duthost, port_attributes_dict, lport_to_first_subport_mapping,
            physical_oir_attributes, lports, health_baseline, watermark, startup_wait)

    if all_failures:
        pytest.fail("Physical OIR stress (TC4) failures:\n  - " + "\n  - ".join(all_failures))


@pytest.mark.parametrize("swap_kind", ["same_xcvr_api_class", "different_xcvr_api_class"])
def test_physical_oir_hot_swap(
    request, duthost, port_attributes_dict, physical_oir_attributes,
    oir_system_attributes, oir_pport_to_lports, lport_to_first_subport_mapping, swap_kind,
):
    """TC5/TC6: hot-swap in an optic of the same / of a different ``XcvrApi`` class.

    ``hot_swap_ports_under_test`` pairs a physical port index with the
    ``XcvrApi`` class name of the optic to swap in.  TC5 reuses the port's own
    class (one swap per port); TC6 walks every configured class.
    """
    hot_swap = physical_oir_attributes["hot_swap_ports_under_test"]
    if not hot_swap:
        pytest.skip("hot_swap_ports_under_test is empty")

    hot_swap_pports = sorted({pport for pport, _ in hot_swap})
    unknown = [pport for pport in hot_swap_pports if pport not in oir_pport_to_lports]
    if unknown:
        pytest.fail(f"hot_swap_ports_under_test physical port(s) {unknown} are not in ports_under_test")

    same_class = swap_kind == "same_xcvr_api_class"
    swap_targets = [(pport, None) for pport in hot_swap_pports] if same_class else list(hot_swap)
    shutdown_wait = oir_system_attributes["port_shutdown_wait_sec"]
    startup_wait = oir_system_attributes["port_startup_wait_sec"]

    all_failures = []
    for pport, target_class in swap_targets:
        lports = oir_pport_to_lports[pport]
        original_class, class_err = oir_helpers.get_xcvr_api_class_names(duthost, [pport])[pport]
        original_serials, serial_err = oir_helpers.get_vendor_serials(duthost, lports)
        if class_err or serial_err:
            all_failures += _prefix(pport, [err for err in (class_err, serial_err) if err])
            continue
        expected_class = original_class if same_class else target_class

        # Step 1: remove the original module.
        flap_baseline = oir_helpers.get_flap_counts(duthost, lports)
        watermark = oir_helpers.capture_kernel_error_watermark(duthost, physical_oir_attributes)
        failures = oir_helpers.perform_oir(request, duthost, physical_oir_attributes, [pport], present=False)
        if failures:
            all_failures += _prefix(pport, failures)
            continue
        failures = _verify_removal(
            duthost, port_attributes_dict, lports, flap_baseline, watermark, shutdown_wait)

        # Step 2: seat the swap-in optic.
        swap_failures = oir_helpers.perform_oir(
            request, duthost, physical_oir_attributes, [pport], present=True,
            action=f"INSERT a DIFFERENT optic whose XcvrApi class is '{expected_class}'")
        if swap_failures:
            # An unsupported optic never becomes Present, in which case the port
            # must keep looking exactly like an empty cage.
            failures += _verify_removal(
                duthost, port_attributes_dict, lports, flap_baseline, watermark, shutdown_wait)
        else:
            failures += _verify_hot_swapped_module(
                duthost, lports, pport, expected_class, original_serials,
                lport_to_first_subport_mapping, startup_wait)

            # Step 3: remove the swap-in optic.
            flap_baseline = oir_helpers.get_flap_counts(duthost, lports)
            watermark = oir_helpers.capture_kernel_error_watermark(duthost, physical_oir_attributes)
            step3_failures = oir_helpers.perform_oir(
                request, duthost, physical_oir_attributes, [pport], present=False)
            failures += step3_failures or _verify_removal(
                duthost, port_attributes_dict, lports, flap_baseline, watermark, shutdown_wait)

        # Step 4: restore the original module.
        health_baseline = capture_baseline(duthost)
        watermark = oir_helpers.capture_kernel_error_watermark(duthost, physical_oir_attributes)
        restore_failures = oir_helpers.perform_oir(
            request, duthost, physical_oir_attributes, [pport], present=True,
            action="INSERT the ORIGINAL transceiver back")
        failures += restore_failures or _verify_insertion(
            duthost, port_attributes_dict, lport_to_first_subport_mapping,
            physical_oir_attributes, lports, health_baseline, watermark, startup_wait)

        all_failures += _prefix(pport, failures)

    if all_failures:
        pytest.fail(f"Physical OIR hot swap ({swap_kind}) failures:\n  - " + "\n  - ".join(all_failures))
