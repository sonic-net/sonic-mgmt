import logging

import pytest

from tests.transceiver.common import cli_helpers, db_helpers
from tests.transceiver.common.cli_parser_helper import (
    parse_presence,
    RC_FAILURE,
)
# parse_eeprom is the pre-existing baseline parser and stays in utils/.
from tests.transceiver.utils.cli_parser_helper import parse_eeprom

logger = logging.getLogger(__name__)


PRESENCE_STATUS_NOT_PRESENT = "Not present"

# Expected absence messages per command family (case-sensitive — note the difference)
ABSENT_MSG_SFPUTIL = "SFP EEPROM not detected"   # sfputil family:                     lowercase 'not'
ABSENT_MSG_CLI_INFO = "SFP EEPROM Not detected"   # show interfaces transceiver info:   capital 'Not'


def _reduce_eeprom(lines):
    """Reduce an ``... eeprom`` / ``... info`` dump to ``{port: status_line}``.

    ``parse_eeprom`` records each ``EthernetN: <text>`` header under the port's
    ``status`` key (e.g. ``"SFP EEPROM not detected"`` for an empty cage), which
    is the per-port status the verification loop compares against.
    """
    return {port: fields.get("status") for port, fields in parse_eeprom(lines).items()}


# The four CLIs that report transceiver presence / EEPROM, each run ONCE without
# a port argument so the whole switch is read in 4 commands rather than 4×N.
# Every entry reduces its global output to a uniform ``{port: status}`` map plus
# the status an *empty* port must report, so the per-port verification collapses
# to a single loop instead of four near-identical blocks.
#
#   (label, global command, lines->{port: status} reducer, expected-empty-status)
# Presence output is already {port: status}, so it uses ``parse_presence``
# directly; the eeprom/info dumps need ``_reduce_eeprom`` to pull each port's
# status line out of the parsed {port: {field: value}} map.
_ABSENCE_CHECKS = (
    (
        "sfputil show presence",
        cli_helpers.sfputil_show_presence_cmd(),
        parse_presence,
        PRESENCE_STATUS_NOT_PRESENT,
    ),
    (
        "show interfaces transceiver presence",
        cli_helpers.show_interfaces_transceiver_presence_cmd(),
        parse_presence,
        PRESENCE_STATUS_NOT_PRESENT,
    ),
    (
        "sfputil show eeprom",
        cli_helpers.sfputil_show_eeprom_cmd(),
        _reduce_eeprom,
        ABSENT_MSG_SFPUTIL,
    ),
    (
        "show interfaces transceiver info",
        cli_helpers.show_interfaces_transceiver_info_cmd(),
        _reduce_eeprom,
        ABSENT_MSG_CLI_INFO,
    ),
)


def test_absence_message_verification(duthost, port_attributes_dict):
    """Verify absence error messages for ports with no transceiver installed.

    Step 1 — Derives all empty ports as CONFIG_DB.PORT.keys() − port_attributes_dict.keys()
             (the "absent-port error-message verification" case in eeprom_test_plan.md):
             every physical port configured on the DUT that does not carry a
             transceiver in the inventory.
    Step 2 — Runs each of the four presence / EEPROM CLIs ONCE without a port
             argument, parses the global output into a ``{port: status}`` map,
             then verifies every empty port reports the expected absence status.

    Running the CLIs globally (rather than once per port) reads the whole switch
    in 4 commands instead of 4×N, which is the dominant cost on a fully-broken-out
    chassis with hundreds of empty logical ports.

    Expected absence status is case-sensitive and differs per command family:
        sfputil show eeprom   : "SFP EEPROM not detected"   (lowercase 'not')
        show transceiver info : "SFP EEPROM Not detected"   (capital 'Not')
        presence commands     : 'Not present' in the Presence column

    CLIs verified per absent port (all run without a port argument):
        1. sfputil show presence
        2. show interfaces transceiver presence
        3. sfputil show eeprom
        4. show interfaces transceiver info
    """
    # Step 1 - Derive empty ports from CONFIG_DB (the "Error handling - Missing
    # transceiver" case in eeprom_test_plan.md): empty ports = all physical
    # ports in the CONFIG_DB PORT table minus the ports that carry a transceiver
    # in port_attributes_dict. Deriving from CONFIG_DB (rather than
    # 'show ... presence') avoids conflating "transceiver absent" with "port not
    # in inventory" and isn't subject to silently dropping a port if presence
    # parsing breaks.
    config_ports = db_helpers.get_config_db_port_names(duthost)
    if not config_ports:
        pytest.skip("CONFIG_DB PORT table is empty; cannot derive empty ports")

    absent_ports = sorted(config_ports - set(port_attributes_dict.keys()))

    if not absent_ports:
        pytest.skip(
            "No empty ports found on DUT (all configured ports are in the transceiver "
            "inventory); skipping absence message verification"
        )

    logger.info("Empty ports derived from CONFIG_DB (%d): %s", len(absent_ports), absent_ports)

    # ------------------------------------------------------------------ #
    # Step 2a - Run each CLI once (global, no port arg) and reduce its    #
    #           output to a {port: status} map. A CLI that fails outright #
    #           (non-zero rc / empty output) is reported once here rather #
    #           than once per empty port.                                 #
    # ------------------------------------------------------------------ #
    all_failures = []
    status_maps = []   # list of (label, {port: status}, expected_status)
    for label, cmd, reduce_output, expected in _ABSENCE_CHECKS:
        result = duthost.command(cmd, module_ignore_errors=True)
        lines = result.get("stdout_lines", [])
        if result.get("rc", RC_FAILURE) != 0 or not lines:
            stderr = (result.get("stderr") or "").strip()[:200]
            all_failures.append(
                f"[{label}] command failed (rc={result.get('rc')}, stderr={stderr or '<empty>'})"
            )
            continue
        status_maps.append((label, reduce_output(lines), expected))

    # ------------------------------------------------------------------ #
    # Step 2b - One loop over empty ports applies all four checks. Each   #
    #           check is a uniform {port: status} lookup compared to the  #
    #           expected absence status, so the four CLIs share one body. #
    # ------------------------------------------------------------------ #
    for port in absent_ports:
        field_failures = []
        for label, status_by_port, expected in status_maps:
            actual = status_by_port.get(port)
            if actual != expected:
                field_failures.append(
                    f"[{label}]: expected '{expected}', got {actual!r}"
                )
        if field_failures:
            all_failures.append(f"{port}:\n  " + "\n  ".join(field_failures))

    if all_failures:
        pytest.fail("Absent port message verification failures:\n" + "\n".join(all_failures))
