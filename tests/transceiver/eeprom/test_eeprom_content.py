"""EEPROM content verification tests.

The parsing/comparison machinery and the ``verify_<...>_recovered`` verifiers
live in :mod:`tests.transceiver.eeprom.eeprom_content` so they can be reused
without importing a test module.
"""
import pytest

from tests.transceiver.eeprom.eeprom_content import (
    SFPUTIL_CLI_KEY_TO_INV_KEY,
    SHOW_CLI_KEY_TO_INV_KEY,
    parse_via_sfputil,
    run_bulk_eeprom_check,
    run_per_port_eeprom_check,
)


def test_eeprom_content_verification_via_sfputil(
    duthost, port_attributes_dict, lport_to_first_subport_mapping
):
    """Verify EEPROM content via ``sfputil show eeprom -p <port>`` per port.

    Implements Generic test case from
    ``docs/testplan/transceiver/eeprom_test_plan.md``.  For every port with
    inventory attributes the test:

      * Runs ``sfputil show eeprom -p <port>`` once, timed.
      * Fails the port when elapsed time exceeds
        ``EEPROM_ATTRIBUTES.eeprom_dump_timeout_sec`` (default 5s per the
        plan).  This is the test case expected result "EEPROM dump completes
        within eeprom_dump_timeout_sec".
      * Compares the parsed EEPROM fields against expected values from
        ``port_attributes_dict``.  Firmware versions are NOT checked here:
        ``sfputil show eeprom`` does not report them, so they are verified by
        the show-CLI variant instead.

    Runs on the first sub-port of each breakout only: this command reads EEPROM
    bytes off the physical module, so non-primary sub-ports return byte-identical
    content.

    Aggregates per-port failure blocks into one ``pytest.fail``.
    """
    all_failures = run_per_port_eeprom_check(
        duthost, port_attributes_dict,
        parse_wrapper=parse_via_sfputil,
        source_label="sfputil show eeprom -p <port>",
        key_mapping=SFPUTIL_CLI_KEY_TO_INV_KEY,
        lport_to_first_subport=lport_to_first_subport_mapping,
    )
    if all_failures:
        pytest.fail("EEPROM verification failures:\n" + "\n".join(all_failures))


def test_eeprom_content_verification_via_show_cli(duthost, port_attributes_dict):
    """Verify EEPROM content via ``show interfaces transceiver info`` (bulk).

    Mirror of :func:`test_eeprom_content_verification_via_sfputil` for the SONiC
    ``show`` CLI variant.  This variant additionally verifies firmware versions
    (``Active Firmware`` / ``Inactive Firmware``), which only this CLI reports,
    and the Generic TC#4 step-4 dynamic DataPath fields (``host_lane_count`` /
    ``media_lane_count`` and per-host-lane ``active_apsel_hostlane<n>``) by module
    class.

    Runs on ALL sub-ports (not just the first): ``show interfaces transceiver
    info`` reads STATE_DB ``TRANSCEIVER_INFO``, which xcvrd populates per logical
    sub-port, so every sub-port's entry must be validated — a non-primary
    sub-port whose entry is missing or diverged is an xcvrd failure mode only
    this DB-backed path can catch.

    Uses the bulk path (:func:`run_bulk_eeprom_check`): one ``show interfaces
    transceiver info`` per ASIC namespace + per-port dict lookups, instead of one
    CLI invocation per sub-port (which would be hundreds of Click spawns on a
    high-radix DUT).  Because it is a STATE_DB read with no I2C, the per-port
    ``eeprom_dump_timeout_sec`` budget is not enforced here (it targets the I2C
    dump latency on the sfputil path).
    """
    all_failures = run_bulk_eeprom_check(
        duthost, port_attributes_dict,
        source_label="show interfaces transceiver info",
        key_mapping=SHOW_CLI_KEY_TO_INV_KEY,
    )
    if all_failures:
        pytest.fail("EEPROM verification failures:\n" + "\n".join(all_failures))
