"""Remote reseat.

Implements the Remote reseat test cases TC1-TC2 from
``docs/testplan/transceiver/online_insertion_removal_testplan.md``.

A remote reseat runs the plan's seven-step procedure (DOM monitoring off, port
shutdown, module reset, low then high power mode, port startup, DOM monitoring
on) on every module under test together, checking each step's expected result
as it runs; see :func:`oir_helpers.perform_remote_reseat`.  A remote reseat
simulates a removal and an insertion, so after the last reseat the ports under
test, and their link peers on this DUT, are checked against the expected
results of a physical insertion (:func:`oir_helpers.verify_insertion`):

  1. EEPROM content from the show and sfputil CLIs (exit code 0) matches the inventory.
  2. DOM values are valid and republished after the last reseat re-enabled DOM
     monitoring; the VDM, PM and flag tables are still published.
  3. The ports are oper up within ``port_startup_wait_sec`` and the system is healthy.
  4. No link flap for ``link_flap_monitor_timeout_sec``; each reseat takes every
     port and link peer down and up exactly once.
  5. Optics and media SI settings are left to the Standard Port Recovery
     procedure's SI sub-check, which is not implemented yet.
  6. The LLDP neighbor is the port's connection-graph peer.
  7. ``TRANSCEIVER_STATUS_SW`` is READY and no transceiver table was lost.
  8. No transceiver kernel error, when ``monitor_kernel_errors`` is set.

As in Physical OIR, a link peer's DOM / PM / flag tables, and a peer on another
device, are not verified.  No other inventory port may flap.  Per-port failures
are aggregated into a single ``pytest.fail`` so one run surfaces every issue
across every port under test.
"""
import logging

import pytest

from tests.transceiver.attribute_parser.attribute_keys import REMOTE_RESEAT_ATTRIBUTES_KEY
from tests.transceiver.common.health_checks import capture_baseline
from tests.transceiver.oir import oir_helpers

logger = logging.getLogger(__name__)

pytestmark = pytest.mark.usefixtures("gold_fw_verified", "_restore_reseat_state")

# A reseat takes each port, and its link peer, down at the shutdown and up at the startup.
FLAPS_PER_RESEAT = 2


def _run_remote_reseats(duthost, port_attributes_dict, lport_to_first_subport_mapping,
                        reseat_pport_to_lports, port_peers, iterations):
    """Remotely reseat every module under test ``iterations`` times, then verify
    the TC1 expected results after the last reseat.

    The baselines are taken before the first reseat, so the published tables,
    the process health, the flap counts and the kernel log cover every reseat.
    The DOM sensor baseline is the one the last reseat reads while DOM
    monitoring is still disabled, so only the monitoring it re-enabled can
    republish DOM data.  The iterations stop at the first reseat that fails.
    """
    _, lports = oir_helpers.all_ports(reseat_pport_to_lports)
    shutdown_wait, startup_wait = oir_helpers.bulk_waits(port_attributes_dict, lports)

    baseline_tables, errors = oir_helpers.capture_state_tables(duthost, lports)
    if errors:
        return [f"setup: STATE_DB baseline: {error}" for error in errors]
    other_flap_baseline = oir_helpers.get_other_ports_flap_sentinels(
        duthost, port_attributes_dict, lports, port_peers)
    health_baseline = capture_baseline(duthost)
    watermark = oir_helpers.capture_kernel_error_watermark(
        duthost, port_attributes_dict, lports, attribute_key=REMOTE_RESEAT_ATTRIBUTES_KEY)
    flap_baseline = oir_helpers.get_flap_counts(duthost, oir_helpers.with_link_peers(duthost, lports, port_peers))

    failures, dom_baseline = [], {}
    for iteration in range(1, iterations + 1):
        logger.info("Remote reseat %d/%d", iteration, iterations)
        failures, dom_baseline = oir_helpers.perform_remote_reseat(
            duthost, port_attributes_dict, lport_to_first_subport_mapping, lports, shutdown_wait, startup_wait)
        if failures:
            failures = [f"reseat {iteration}/{iterations}: {failure}" for failure in failures]
            break

    if not failures:
        failures = oir_helpers.verify_insertion(
            duthost, port_attributes_dict, lport_to_first_subport_mapping,
            lports, health_baseline, watermark, startup_wait,
            port_peers=port_peers,
            baseline_tables=baseline_tables,
            baseline_sensor_data=dom_baseline,
            insert_flap_baseline=flap_baseline,
            expected_flap_increment=FLAPS_PER_RESEAT * iterations,
            attribute_key=REMOTE_RESEAT_ATTRIBUTES_KEY,
            scenario="after remote reseat")
    failures += oir_helpers.verify_other_ports_no_flap(duthost, other_flap_baseline)
    return failures


def test_remote_reseat(
    duthost, port_attributes_dict, lport_to_first_subport_mapping, reseat_pport_to_lports, port_peers,
):
    """TC1: remotely reseat every module under test and verify its ports and link peers recover."""
    failures = _run_remote_reseats(
        duthost, port_attributes_dict, lport_to_first_subport_mapping,
        reseat_pport_to_lports, port_peers, iterations=1)

    if failures:
        pytest.fail("Remote reseat (TC1) failures:\n  - " + "\n  - ".join(failures))


def test_remote_reseat_stress(
    duthost, port_attributes_dict, lport_to_first_subport_mapping, reseat_pport_to_lports, port_peers,
):
    """TC2: remotely reseat every module under test ``remote_reseat_stress_iteration``
    times and verify the TC1 expected results after the last reseat."""
    _, lports = oir_helpers.all_ports(reseat_pport_to_lports)
    iterations = port_attributes_dict[lports[0]][REMOTE_RESEAT_ATTRIBUTES_KEY]["remote_reseat_stress_iteration"]
    if not isinstance(iterations, int) or iterations < 1:
        pytest.fail(
            "remote_reseat_stress_iteration must be a positive integer to exercise a stress "
            f"cycle, got {iterations!r}")

    failures = _run_remote_reseats(
        duthost, port_attributes_dict, lport_to_first_subport_mapping,
        reseat_pport_to_lports, port_peers, iterations=iterations)

    if failures:
        pytest.fail("Remote reseat stress (TC2) failures:\n  - " + "\n  - ".join(failures))
