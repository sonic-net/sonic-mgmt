"""EEPROM Scenario Coverage — S1: DataPath field clear/restore on shut/no-shut.

Implements scenario **S1** of the EEPROM plan
(``docs/testplan/transceiver/eeprom_test_plan.md``) via the shared model: the
``scenario_ops`` bulk operation helpers + the ``datapath`` verifiers. The test
just orchestrates operation → verifier per the scenario template — all CMIS
active-optical ports are shut together, verified cleared, brought back up
together, then verified recovered; the verifiers iterate/aggregate internally.
"""
import logging

import pytest

from tests.transceiver.attribute_parser.attribute_keys import SYSTEM_ATTRIBUTES_KEY
from tests.transceiver.common import scenario_ops
from tests.transceiver.eeprom import datapath

logger = logging.getLogger(__name__)


def test_datapath_clear_restore_on_shut_noshut(duthost, port_attributes_dict):
    """S1: DataPath fields clear to ``N/A`` on shut and restore on startup (bulk).

    Follows the scenario-coverage skeleton: pre-check → bulk shut → verify
    cleared → bulk startup → verify recovered → teardown. Per-port failures
    aggregate into one ``pytest.fail``.
    """
    ports = datapath.cmis_active_optical_ports(port_attributes_dict)
    if not ports:
        pytest.skip("No CMIS active-optical ports to exercise for S1")

    # Bulk settle waits: max of the System-shard per-port attrs across target
    # ports (read directly so a missing key fails loudly), scaled to the number
    # of ports since a bulk (all-at-once) shut/startup settles slower than a
    # single port — see scenario_ops.scale_bulk_wait.
    target_attrs = [port_attributes_dict[port] for port in ports]
    shutdown_wait = scenario_ops.scale_bulk_wait(
        max(a.get(SYSTEM_ATTRIBUTES_KEY, {})["port_shutdown_wait_sec"] for a in target_attrs),
        len(ports))
    # Per-port oper-up budget; used unscaled for the datapath republish poll
    # (a per-port latency after link-up, not a bulk-throughput one) and scaled
    # for the bulk oper-up waits below.
    port_startup_wait = max(
        a.get(SYSTEM_ATTRIBUTES_KEY, {})["port_startup_wait_sec"] for a in target_attrs)
    startup_wait = scenario_ops.scale_bulk_wait(port_startup_wait, len(ports))

    all_failures = []
    # 1. Pre-check: DataPath already at steady state (so a post-op failure is
    #    attributable to the shut/no-shut). Ports are already up and steady — no
    #    transition to wait for — so this is a snapshot (``wait_sec=0``), unlike
    #    the post-startup recovery which polls up to ``port_startup_wait``.
    all_failures += datapath.verify_datapath_recovered(
        duthost, port_attributes_dict, 0, ports=ports)

    logger.info("S1: exercising DataPath clear/restore on %d port(s) "
                "(shutdown_wait=%ss startup_wait=%ss)",
                len(ports), shutdown_wait, startup_wait)
    try:
        # 2. Bulk shut, then verify DataPath cleared while down. On shutdown the
        #    port is disabled (link drops) first and xcvrd clears the fields
        #    after, so oper-down does NOT imply cleared yet — poll shutdown_wait.
        all_failures += scenario_ops.perform_ports_shutdown(
            duthost, ports, shutdown_wait)
        all_failures += datapath.verify_datapath_cleared(
            duthost, port_attributes_dict, shutdown_wait, ports=ports)

        # 3. Bulk startup (waits for oper-up), then verify DataPath recovered.
        #    oper-up does NOT guarantee xcvrd has already re-published the
        #    datapath fields (TRANSCEIVER_INFO): a port can lag link-up by a
        #    moment. That republish lag is a per-port latency (not scaled by the
        #    fleet size), so poll up to the unscaled per-port port_startup_wait.
        all_failures += scenario_ops.perform_ports_startup(
            duthost, ports, startup_wait)
        all_failures += datapath.verify_datapath_recovered(
            duthost, port_attributes_dict, port_startup_wait, ports=ports)
    finally:
        # Teardown: ensure every exercised port is back up on any failure path.
        scenario_ops.perform_ports_startup(duthost, ports, startup_wait)

    if all_failures:
        pytest.fail(
            "DataPath clear/restore on shut/no-shut (S1) failures:\n"
            + "\n".join(all_failures)
        )
